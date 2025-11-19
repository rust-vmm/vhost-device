// vhost device Gpu
//
// Copyright 2024 RedHat
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

/// Helper macro to manage the thread-local lazy initialization of GPU adapters.
///
/// This macro ensures that a GPU backend adapter (e.g., Gfxstream or Virgl) is
/// instantiated only once per thread when the first event arrives (`lazy
/// initialization`).
macro_rules! handle_adapter {
    ($adapter_type:ty, $tls_name:ident, $new_adapter:expr, $self:expr, $device_event:expr, $vrings:expr) => {{
        thread_local! {
            static $tls_name: RefCell<Option<$adapter_type>> = const { RefCell::new(None) };
        }

        let mut event_poll_fd = None;

        $tls_name.with_borrow_mut(|maybe_renderer| {
            let renderer = match maybe_renderer {
                Some(renderer) => renderer,
                None => {
                    // Pass $vrings to the call
                    let (control_vring, gpu_backend) = $self.extract_backend_and_vring($vrings)?;

                    let renderer = $new_adapter(control_vring, gpu_backend)?;

                    event_poll_fd = renderer.get_event_poll_fd();
                    maybe_renderer.insert(renderer)
                }
            };

            // Pass $device_event, renderer, and $vrings to the call
            $self.handle_event($device_event, renderer, $vrings)
        })?;

        Ok(event_poll_fd)
    }};
}

use std::{
    cell::RefCell,
    io::{self, Result as IoResult},
    os::fd::AsRawFd,
    sync::{self, Arc, Mutex},
};

use log::{debug, info, trace, warn};
use rutabaga_gfx::RutabagaFence;
use thiserror::Error as ThisError;
use vhost::vhost_user::{
    gpu_message::{VhostUserGpuCursorPos, VhostUserGpuEdidRequest},
    message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures},
    GpuBackend,
};
use vhost_user_backend::{VhostUserBackend, VringEpollHandler, VringRwLock, VringT};
use virtio_bindings::{
    bindings::{
        virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_RING_RESET, VIRTIO_F_VERSION_1},
        virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC},
    },
    virtio_gpu::{
        VIRTIO_GPU_F_CONTEXT_INIT, VIRTIO_GPU_F_EDID, VIRTIO_GPU_F_RESOURCE_BLOB,
        VIRTIO_GPU_F_VIRGL,
    },
};
use virtio_queue::{QueueOwnedT, Reader, Writer};
use vm_memory::{ByteValued, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap, Le32};
use vmm_sys_util::{
    epoll::EventSet,
    event::{new_event_consumer_and_notifier, EventConsumer, EventFlag, EventNotifier},
    eventfd::EventFd,
};

#[cfg(feature = "backend-gfxstream")]
use crate::backend::gfxstream::GfxstreamAdapter;
#[cfg(feature = "backend-virgl")]
use crate::backend::virgl::VirglRendererAdapter;
use crate::{
    backend::null::NullAdapter,
    gpu_types::{ResourceCreate3d, Transfer3DDesc, VirtioGpuRing},
    protocol::{
        virtio_gpu_ctrl_hdr, virtio_gpu_ctx_create, virtio_gpu_get_edid,
        virtio_gpu_resource_create_2d, virtio_gpu_resource_create_3d, virtio_gpu_transfer_host_3d,
        virtio_gpu_transfer_to_host_2d, virtio_gpu_update_cursor, GpuCommand,
        GpuCommandDecodeError, GpuResponse::ErrUnspec, GpuResponseEncodeError, VirtioGpuConfig,
        VirtioGpuResult, CONTROL_QUEUE, CURSOR_QUEUE, NUM_QUEUES, POLL_EVENT, QUEUE_SIZE,
        VIRTIO_GPU_BIND_RENDER_TARGET, VIRTIO_GPU_FLAG_FENCE, VIRTIO_GPU_FLAG_INFO_RING_IDX,
        VIRTIO_GPU_MAX_SCANOUTS, VIRTIO_GPU_TEXTURE_2D,
    },
    renderer::Renderer,
    GpuConfig, GpuMode,
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Failed to handle event, didn't match EPOLLIN")]
    HandleEventNotEpollIn,
    #[error("Failed to handle unknown event")]
    HandleEventUnknown,
    #[error("Descriptor read failed")]
    DescriptorReadFailed,
    #[error("Descriptor write failed")]
    DescriptorWriteFailed,
    #[error("Invalid command type {0}")]
    InvalidCommandType(u32),
    #[error("Failed to send used queue notification: {0}")]
    NotificationFailed(io::Error),
    #[error("Failed to create new EventFd")]
    EventFdFailed,
    #[error("Failed to create an iterator over a descriptor chain: {0}")]
    CreateIteratorDescChain(virtio_queue::Error),
    #[error("Failed to create descriptor chain Reader: {0}")]
    CreateReader(virtio_queue::Error),
    #[error("Failed to create descriptor chain Writer: {0}")]
    CreateWriter(virtio_queue::Error),
    #[error("Failed to decode gpu command: {0}")]
    GpuCommandDecode(GpuCommandDecodeError),
    #[error("Failed to encode gpu response: {0}")]
    GpuResponseEncode(GpuResponseEncodeError),
    #[error("Failed add used chain to queue: {0}")]
    QueueAddUsed(virtio_queue::Error),
    #[error("Epoll handler not available: {0}")]
    EpollHandler(String),
    #[error("Failed register epoll listener: {0}")]
    RegisterEpollListener(io::Error),
    #[error("Failed to create backend")]
    BackendCreationFailed,
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        Self::other(e)
    }
}

struct VhostUserGpuBackendInner {
    virtio_cfg: VirtioGpuConfig,
    event_idx_enabled: bool,
    gpu_backend: Option<GpuBackend>,
    exit_consumer: EventConsumer,
    exit_notifier: EventNotifier,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    gpu_config: GpuConfig,
}

pub struct VhostUserGpuBackend {
    inner: Mutex<VhostUserGpuBackendInner>,
    // this uses sync::Weak to avoid a reference cycle
    epoll_handler: Mutex<sync::Weak<VringEpollHandler<Arc<Self>>>>,
    poll_event_fd: Mutex<Option<EventFd>>,
}

impl VhostUserGpuBackend {
    pub fn new(gpu_config: GpuConfig) -> Result<Arc<Self>> {
        info!(
            "GpuBackend using mode {} (capsets: '{}'), flags: {:?}",
            gpu_config.gpu_mode(),
            gpu_config.capsets(),
            gpu_config.flags()
        );
        let (exit_consumer, exit_notifier) = new_event_consumer_and_notifier(EventFlag::NONBLOCK)
            .map_err(|_| Error::EventFdFailed)?;

        let inner = VhostUserGpuBackendInner {
            virtio_cfg: VirtioGpuConfig {
                events_read: 0.into(),
                events_clear: 0.into(),
                num_scanouts: Le32::from(VIRTIO_GPU_MAX_SCANOUTS),
                num_capsets: Le32::from(gpu_config.capsets().num_capsets()),
            },
            event_idx_enabled: false,
            gpu_backend: None,
            exit_consumer,
            exit_notifier,
            mem: None,
            gpu_config,
        };

        Ok(Arc::new(Self {
            inner: Mutex::new(inner),
            epoll_handler: Mutex::new(sync::Weak::new()),
            poll_event_fd: Mutex::new(None),
        }))
    }

    pub fn set_epoll_handler(&self, epoll_handlers: &[Arc<VringEpollHandler<Arc<Self>>>]) {
        // We only expect 1 thread to which we want to register all handlers
        assert_eq!(
            epoll_handlers.len(),
            1,
            "Expected exactly one epoll handler"
        );

        // Acquire the lock. Panics if poisoned because the state is invalid in that
        // case, and recovery would not make sense in this context.
        let mut handler = self.epoll_handler.lock().unwrap();
        *handler = Arc::downgrade(&epoll_handlers[0]);
    }
}

impl VhostUserGpuBackendInner {
    fn process_gpu_command(
        renderer: &mut dyn Renderer,
        mem: &GuestMemoryMmap,
        hdr: virtio_gpu_ctrl_hdr,
        cmd: GpuCommand,
    ) -> VirtioGpuResult {
        renderer.force_ctx_0();
        debug!("process_gpu_command: {cmd:?}");
        match cmd {
            GpuCommand::GetDisplayInfo => renderer.display_info(),
            GpuCommand::GetEdid(req) => Self::handle_get_edid(renderer, req),
            GpuCommand::ResourceCreate2d(req) => Self::handle_resource_create_2d(renderer, req),
            GpuCommand::ResourceUnref(req) => renderer.unref_resource(req.resource_id.into()),
            GpuCommand::SetScanout(req) => {
                renderer.set_scanout(req.scanout_id.into(), req.resource_id.into(), req.r)
            }
            GpuCommand::ResourceFlush(req) => {
                renderer.flush_resource(req.resource_id.into(), req.r)
            }
            GpuCommand::TransferToHost2d(req) => Self::handle_transfer_to_host_2d(renderer, req),
            GpuCommand::ResourceAttachBacking(req, iovecs) => {
                renderer.attach_backing(req.resource_id.into(), mem, iovecs)
            }
            GpuCommand::ResourceDetachBacking(req) => {
                renderer.detach_backing(req.resource_id.into())
            }
            GpuCommand::UpdateCursor(req) => Self::handle_update_cursor(renderer, req),
            GpuCommand::MoveCursor(req) => Self::handle_move_cursor(renderer, req),
            GpuCommand::ResourceAssignUuid(_) => {
                panic!("virtio_gpu: GpuCommand::ResourceAssignUuid unimplemented")
            }
            GpuCommand::GetCapsetInfo(req) => renderer.get_capset_info(req.capset_index.into()),
            GpuCommand::GetCapset(req) => {
                renderer.get_capset(req.capset_id.into(), req.capset_version.into())
            }
            GpuCommand::CtxCreate(req) => Self::handle_ctx_create(renderer, hdr, req),
            GpuCommand::CtxDestroy(_) => renderer.destroy_context(hdr.ctx_id.into()),
            GpuCommand::CtxAttachResource(req) => {
                renderer.context_attach_resource(hdr.ctx_id.into(), req.resource_id.into())
            }
            GpuCommand::CtxDetachResource(req) => {
                renderer.context_detach_resource(hdr.ctx_id.into(), req.resource_id.into())
            }
            GpuCommand::ResourceCreate3d(req) => Self::handle_resource_create_3d(renderer, req),
            GpuCommand::TransferToHost3d(req) => {
                Self::handle_transfer_to_host_3d(renderer, hdr.ctx_id.into(), req)
            }
            GpuCommand::TransferFromHost3d(req) => {
                Self::handle_transfer_from_host_3d(renderer, hdr.ctx_id.into(), req)
            }
            GpuCommand::CmdSubmit3d {
                fence_ids,
                mut cmd_data,
            } => renderer.submit_command(hdr.ctx_id.into(), &mut cmd_data, &fence_ids),
            GpuCommand::ResourceCreateBlob(_) => {
                panic!("virtio_gpu: GpuCommand::ResourceCreateBlob unimplemented")
            }

            GpuCommand::SetScanoutBlob(_) => {
                panic!("virtio_gpu: GpuCommand::SetScanoutBlob unimplemented")
            }
            GpuCommand::ResourceMapBlob(_) => {
                panic!("virtio_gpu: GpuCommand::ResourceMapBlob unimplemented")
            }
            GpuCommand::ResourceUnmapBlob(_) => {
                panic!("virtio_gpu: GpuCommand::ResourceUnmapBlob unimplemented")
            }
        }
    }

    fn handle_get_edid(renderer: &dyn Renderer, req: virtio_gpu_get_edid) -> VirtioGpuResult {
        let edid_req = VhostUserGpuEdidRequest {
            scanout_id: req.scanout.into(),
        };
        renderer.get_edid(edid_req)
    }

    fn handle_resource_create_2d(
        renderer: &mut dyn Renderer,
        req: virtio_gpu_resource_create_2d,
    ) -> VirtioGpuResult {
        let resource_create_3d = ResourceCreate3d {
            target: VIRTIO_GPU_TEXTURE_2D,
            format: req.format.into(),
            bind: VIRTIO_GPU_BIND_RENDER_TARGET,
            width: req.width.into(),
            height: req.height.into(),
            depth: 1,
            array_size: 1,
            last_level: 0,
            nr_samples: 0,
            flags: 0,
        };
        renderer.resource_create_3d(req.resource_id.into(), resource_create_3d)
    }

    fn handle_transfer_to_host_2d(
        renderer: &mut dyn Renderer,
        req: virtio_gpu_transfer_to_host_2d,
    ) -> VirtioGpuResult {
        let transfer = Transfer3DDesc::new_2d(
            req.r.x.into(),
            req.r.y.into(),
            req.r.width.into(),
            req.r.height.into(),
            req.offset.into(),
        );
        renderer.transfer_write_2d(0, req.resource_id.into(), transfer)
    }

    fn handle_update_cursor(
        renderer: &mut dyn Renderer,
        req: virtio_gpu_update_cursor,
    ) -> VirtioGpuResult {
        let cursor_pos = VhostUserGpuCursorPos {
            scanout_id: req.pos.scanout_id.into(),
            x: req.pos.x.into(),
            y: req.pos.y.into(),
        };
        renderer.update_cursor(
            req.resource_id.into(),
            cursor_pos,
            req.hot_x.into(),
            req.hot_y.into(),
        )
    }

    fn handle_move_cursor(
        renderer: &mut dyn Renderer,
        req: virtio_gpu_update_cursor,
    ) -> VirtioGpuResult {
        let cursor = VhostUserGpuCursorPos {
            scanout_id: req.pos.scanout_id.into(),
            x: req.pos.x.into(),
            y: req.pos.y.into(),
        };
        renderer.move_cursor(req.resource_id.into(), cursor)
    }

    fn handle_ctx_create(
        renderer: &mut dyn Renderer,
        hdr: virtio_gpu_ctrl_hdr,
        req: virtio_gpu_ctx_create,
    ) -> VirtioGpuResult {
        let context_name: Option<String> = Some(req.get_debug_name());
        renderer.create_context(
            hdr.ctx_id.into(),
            req.context_init.into(),
            context_name.as_deref(),
        )
    }

    fn handle_resource_create_3d(
        renderer: &mut dyn Renderer,
        req: virtio_gpu_resource_create_3d,
    ) -> VirtioGpuResult {
        let resource_create_3d = ResourceCreate3d {
            target: req.target.into(),
            format: req.format.into(),
            bind: req.bind.into(),
            width: req.width.into(),
            height: req.height.into(),
            depth: req.depth.into(),
            array_size: req.array_size.into(),
            last_level: req.last_level.into(),
            nr_samples: req.nr_samples.into(),
            flags: req.flags.into(),
        };
        renderer.resource_create_3d(req.resource_id.into(), resource_create_3d)
    }

    fn handle_transfer_to_host_3d(
        renderer: &mut dyn Renderer,
        ctx_id: u32,
        req: virtio_gpu_transfer_host_3d,
    ) -> VirtioGpuResult {
        let transfer = Transfer3DDesc {
            x: req.box_.x.into(),
            y: req.box_.y.into(),
            z: req.box_.z.into(),
            w: req.box_.w.into(),
            h: req.box_.h.into(),
            d: req.box_.d.into(),
            level: req.level.into(),
            stride: req.stride.into(),
            layer_stride: req.layer_stride.into(),
            offset: req.offset.into(),
        };
        renderer.transfer_write(ctx_id, req.resource_id.into(), transfer)
    }

    fn handle_transfer_from_host_3d(
        renderer: &mut dyn Renderer,
        ctx_id: u32,
        req: virtio_gpu_transfer_host_3d,
    ) -> VirtioGpuResult {
        let transfer = Transfer3DDesc {
            x: req.box_.x.into(),
            y: req.box_.y.into(),
            z: req.box_.z.into(),
            w: req.box_.w.into(),
            h: req.box_.h.into(),
            d: req.box_.d.into(),
            level: req.level.into(),
            stride: req.stride.into(),
            layer_stride: req.layer_stride.into(),
            offset: req.offset.into(),
        };
        renderer.transfer_read(ctx_id, req.resource_id.into(), transfer, None)
    }

    fn process_queue_chain(
        &self,
        renderer: &mut dyn Renderer,
        vring: &VringRwLock,
        head_index: u16,
        reader: &mut Reader,
        writer: &mut Writer,
        signal_used_queue: &mut bool,
    ) -> Result<()> {
        let mut response = ErrUnspec;
        let mem = self.mem.as_ref().unwrap().memory().into_inner();

        let ctrl_hdr = match GpuCommand::decode(reader) {
            Ok((ctrl_hdr, gpu_cmd)) => {
                let cmd_name = gpu_cmd.command_name();
                let response_result = Self::process_gpu_command(renderer, &mem, ctrl_hdr, gpu_cmd);
                // Unwrap the response from inside Result and log information
                response = match response_result {
                    Ok(response) => response,
                    Err(response) => {
                        debug!("GpuCommand {cmd_name} failed: {response:?}");
                        response
                    }
                };
                Some(ctrl_hdr)
            }
            Err(e) => {
                warn!("Failed to decode GpuCommand: {e}");
                None
            }
        };

        if writer.available_bytes() == 0 {
            debug!("Command does not have descriptors for a response");
            vring.add_used(head_index, 0).map_err(Error::QueueAddUsed)?;
            *signal_used_queue = true;
            return Ok(());
        }

        let mut fence_id = 0;
        let mut ctx_id = 0;
        let mut flags = 0;
        let mut ring_idx = 0;

        if let Some(ctrl_hdr) = ctrl_hdr {
            if <Le32 as Into<u32>>::into(ctrl_hdr.flags) & VIRTIO_GPU_FLAG_FENCE != 0 {
                flags = ctrl_hdr.flags.into();
                fence_id = ctrl_hdr.fence_id.into();
                ctx_id = ctrl_hdr.ctx_id.into();
                ring_idx = ctrl_hdr.ring_idx;

                let fence = RutabagaFence {
                    flags,
                    fence_id,
                    ctx_id,
                    ring_idx,
                };
                if let Err(fence_response) = renderer.create_fence(fence) {
                    warn!(
                        "Failed to create fence: fence_id: {fence_id} fence_response: \
                         {fence_response}"
                    );
                    response = fence_response;
                }
            }
        }

        // Prepare the response now, even if it is going to wait until
        // fence is complete.
        let response_len = response
            .encode(flags, fence_id, ctx_id, ring_idx, writer)
            .map_err(Error::GpuResponseEncode)?;

        let add_to_queue = if flags & VIRTIO_GPU_FLAG_FENCE != 0 {
            let ring = match flags & VIRTIO_GPU_FLAG_INFO_RING_IDX {
                0 => VirtioGpuRing::Global,
                _ => VirtioGpuRing::ContextSpecific { ctx_id, ring_idx },
            };
            debug!("Trying to process_fence for the command");
            renderer.process_fence(ring, fence_id, head_index, response_len)
        } else {
            true
        };

        if add_to_queue {
            vring
                .add_used(head_index, response_len)
                .map_err(Error::QueueAddUsed)?;
            trace!("add_used {response_len} bytes");
            *signal_used_queue = true;
        }
        Ok(())
    }

    /// Process the requests in the vring and dispatch replies
    fn process_queue(&self, renderer: &mut dyn Renderer, vring: &VringRwLock) -> Result<()> {
        let mem = self.mem.as_ref().unwrap().memory().into_inner();
        let desc_chains: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(mem.clone())
            .map_err(Error::CreateIteratorDescChain)?
            .collect();

        let mut signal_used_queue = false;
        for desc_chain in desc_chains {
            let head_index = desc_chain.head_index();
            let mut reader = desc_chain
                .clone()
                .reader(&mem)
                .map_err(Error::CreateReader)?;
            let mut writer = desc_chain.writer(&mem).map_err(Error::CreateWriter)?;

            self.process_queue_chain(
                renderer,
                vring,
                head_index,
                &mut reader,
                &mut writer,
                &mut signal_used_queue,
            )?;
        }

        if signal_used_queue {
            debug!("Notifying used queue");
            vring
                .signal_used_queue()
                .map_err(Error::NotificationFailed)?;
        }
        debug!("Processing control queue finished");

        Ok(())
    }

    fn handle_event(
        &self,
        device_event: u16,
        renderer: &mut dyn Renderer,
        vrings: &[VringRwLock],
    ) -> IoResult<()> {
        match device_event {
            CONTROL_QUEUE | CURSOR_QUEUE => {
                let vring = &vrings
                    .get(device_event as usize)
                    .ok_or(Error::HandleEventUnknown)?;
                if self.event_idx_enabled {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_queue() until it stops finding new
                    // requests on the queue.
                    loop {
                        vring.disable_notification().unwrap();
                        self.process_queue(renderer, vring)?;
                        if !vring.enable_notification().unwrap() {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    self.process_queue(renderer, vring)?;
                }
            }
            POLL_EVENT => {
                trace!("Handling POLL_EVENT");
                renderer.event_poll();
            }
            _ => {
                warn!("unhandled device_event: {device_event}");
                return Err(Error::HandleEventUnknown.into());
            }
        }

        Ok(())
    }

    fn extract_backend_and_vring<'a>(
        &mut self,
        vrings: &'a [VringRwLock],
    ) -> IoResult<(&'a VringRwLock, Option<GpuBackend>)> {
        let control_vring = &vrings[CONTROL_QUEUE as usize];
        let backend = self.gpu_backend.take();

        if !self.gpu_config.flags().headless && backend.is_none() {
            return Err(io::Error::other(
                "set_gpu_socket() not called, GpuBackend missing",
            ));
        }

        Ok((control_vring, backend))
    }

    fn lazy_init_and_handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        _thread_id: usize,
    ) -> IoResult<Option<EventFd>> {
        debug!("Handle event called");
        if evset != EventSet::IN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        match self.gpu_config.gpu_mode() {
            #[cfg(feature = "backend-gfxstream")]
            GpuMode::Gfxstream => handle_adapter!(
                GfxstreamAdapter,
                TLS_GFXSTREAM,
                |control_vring, gpu_backend| -> io::Result<GfxstreamAdapter> {
                    Ok(GfxstreamAdapter::new(
                        control_vring,
                        &self.gpu_config,
                        gpu_backend,
                    ))
                },
                self,
                device_event,
                vrings
            ),

            #[cfg(feature = "backend-virgl")]
            GpuMode::VirglRenderer => handle_adapter!(
                VirglRendererAdapter,
                TLS_VIRGL,
                |control_vring, gpu_backend| {
                    VirglRendererAdapter::new(control_vring, &self.gpu_config, gpu_backend)
                },
                self,
                device_event,
                vrings
            ),

            GpuMode::Null => handle_adapter!(
                NullAdapter,
                TLS_NULL,
                |control_vring, gpu_backend| -> io::Result<NullAdapter> {
                    Ok(NullAdapter::new(
                        control_vring,
                        &self.gpu_config,
                        gpu_backend,
                    ))
                },
                self,
                device_event,
                vrings
            ),
        }
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        let offset = offset as usize;
        let size = size as usize;

        let buf = self.virtio_cfg.as_slice();

        if offset + size > buf.len() {
            return Vec::new();
        }

        buf[offset..offset + size].to_vec()
    }
}

/// `VhostUserBackend` trait methods
impl VhostUserBackend for VhostUserGpuBackend {
    type Vring = VringRwLock;
    type Bitmap = ();

    fn num_queues(&self) -> usize {
        debug!("Num queues called");
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        debug!("Max queues called");
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        let mut features = (1 << VIRTIO_F_VERSION_1)
            | (1 << VIRTIO_F_RING_RESET)
            | (1 << VIRTIO_F_NOTIFY_ON_EMPTY)
            | (1 << VIRTIO_RING_F_INDIRECT_DESC)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
            | (1 << VIRTIO_GPU_F_VIRGL)
            | (1 << VIRTIO_GPU_F_RESOURCE_BLOB)
            | (1 << VIRTIO_GPU_F_CONTEXT_INIT)
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        let inner = self.inner.lock().unwrap();
        if !inner.gpu_config.flags().headless {
            features |= 1 << VIRTIO_GPU_F_EDID;
        }

        features
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        debug!("Protocol features called");
        VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::MQ
    }

    fn set_event_idx(&self, enabled: bool) {
        self.inner.lock().unwrap().event_idx_enabled = enabled;
        debug!("Event idx set to: {enabled}");
    }

    fn update_memory(&self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        debug!("Update memory called");
        self.inner.lock().unwrap().mem = Some(mem);
        Ok(())
    }

    fn set_gpu_socket(&self, backend: GpuBackend) -> IoResult<()> {
        self.inner.lock().unwrap().gpu_backend = Some(backend);
        Ok(())
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        self.inner.lock().unwrap().get_config(offset, size)
    }

    fn exit_event(&self, _thread_index: usize) -> Option<(EventConsumer, EventNotifier)> {
        let inner = self.inner.lock().unwrap();
        let consumer = inner.exit_consumer.try_clone().ok()?;
        let notifier = inner.exit_notifier.try_clone().ok()?;
        Some((consumer, notifier))
    }

    fn handle_event(
        &self,
        device_event: u16,
        evset: EventSet,
        vrings: &[Self::Vring],
        thread_id: usize,
    ) -> IoResult<()> {
        let poll_event_fd = self.inner.lock().unwrap().lazy_init_and_handle_event(
            device_event,
            evset,
            vrings,
            thread_id,
        )?;

        if let Some(poll_event_fd) = poll_event_fd {
            let Some(epoll_handler) = (match self.epoll_handler.lock() {
                Ok(h) => h,
                Err(poisoned) => poisoned.into_inner(),
            })
            .upgrade() else {
                return Err(
                    Error::EpollHandler("Failed to upgrade epoll handler".to_string()).into(),
                );
            };
            epoll_handler
                .register_listener(
                    poll_event_fd.as_raw_fd(),
                    EventSet::IN,
                    u64::from(POLL_EVENT),
                )
                .map_err(Error::RegisterEpollListener)?;
            debug!("Registered POLL_EVENT on fd: {}", poll_event_fd.as_raw_fd());
            // store the fd, so it is not closed after exiting this scope
            self.poll_event_fd.lock().unwrap().replace(poll_event_fd);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{ErrorKind, Read},
        mem,
        os::unix::net::UnixStream,
        sync::Arc,
        thread,
        time::Duration,
    };

    use assert_matches::assert_matches;
    use mockall::{mock, predicate};
    use rusty_fork::rusty_fork_test;
    use vhost::vhost_user::gpu_message::{VhostUserGpuDMABUFScanout, VhostUserGpuUpdate};
    use vhost_user_backend::{VhostUserDaemon, VringRwLock, VringT};
    use vm_memory::{
        ByteValued, Bytes, GuestAddress, GuestMemoryAtomic, GuestMemoryMmap, VolatileSlice,
    };

    use super::*;
    use crate::{
        gpu_types::{ResourceCreate3d, Transfer3DDesc, VirtioGpuRing},
        protocol::{
            virtio_gpu_ctrl_hdr, virtio_gpu_ctx_create, virtio_gpu_ctx_destroy,
            virtio_gpu_ctx_resource, virtio_gpu_get_capset, virtio_gpu_get_capset_info,
            virtio_gpu_mem_entry, virtio_gpu_rect, virtio_gpu_resource_attach_backing,
            virtio_gpu_resource_detach_backing, virtio_gpu_resource_flush,
            virtio_gpu_resource_unref, virtio_gpu_set_scanout,
            GpuResponse::{OkCapset, OkCapsetInfo, OkDisplayInfo, OkEdid, OkNoData},
            VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE, VIRTIO_GPU_CMD_CTX_CREATE,
            VIRTIO_GPU_CMD_CTX_DESTROY, VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE,
            VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING, VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
            VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING, VIRTIO_GPU_CMD_RESOURCE_FLUSH,
            VIRTIO_GPU_CMD_SET_SCANOUT, VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D,
            VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D, VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D,
            VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM, VIRTIO_GPU_RESP_ERR_UNSPEC,
            VIRTIO_GPU_RESP_OK_NODATA,
        },
        renderer::Renderer,
        testutils::{create_vring, TestingDescChainArgs},
        GpuCapset, GpuConfigBuilder, GpuFlags, GpuMode,
    };

    // Create a mock for the Renderer trait
    mock! {
        pub MockRenderer {}

        impl Renderer for MockRenderer {
            fn display_info(&self) -> VirtioGpuResult;
            fn get_edid(&self, edid_req: VhostUserGpuEdidRequest) -> VirtioGpuResult;
            fn set_scanout(&mut self, scanout_id: u32, resource_id: u32, rect: virtio_gpu_rect) -> VirtioGpuResult;
            fn flush_resource(&mut self, resource_id: u32, rect: virtio_gpu_rect) -> VirtioGpuResult;
            fn resource_create_blob(
                &mut self,
                ctx_id: u32,
                resource_id: u32,
                blob_id: u64,
                size: u64,
                blob_mem: u32,
                blob_flags: u32,
            ) -> VirtioGpuResult;
            fn resource_map_blob(&mut self, resource_id: u32, offset: u64) -> VirtioGpuResult;
            fn resource_unmap_blob(&mut self, resource_id: u32) -> VirtioGpuResult;
            fn resource_create_3d(&mut self, resource_id: u32, req: ResourceCreate3d) -> VirtioGpuResult;
            fn unref_resource(&mut self, resource_id: u32) -> VirtioGpuResult;
            fn transfer_write(&mut self, ctx_id: u32, resource_id: u32, req: Transfer3DDesc) -> VirtioGpuResult;
            fn transfer_write_2d(&mut self, ctx_id: u32, resource_id: u32, req: Transfer3DDesc) -> VirtioGpuResult;
            fn transfer_read<'a>(
                &mut self,
                ctx_id: u32,
                resource_id: u32,
                req: Transfer3DDesc,
                buf: Option<VolatileSlice<'a>>,
            ) -> VirtioGpuResult;
            fn attach_backing(
                &mut self,
                resource_id: u32,
                mem: &GuestMemoryMmap,
                vecs: Vec<(GuestAddress, usize)>,
            ) -> VirtioGpuResult;
            fn detach_backing(&mut self, resource_id: u32) -> VirtioGpuResult;
            fn update_cursor(
                &mut self,
                resource_id: u32,
                cursor_pos: VhostUserGpuCursorPos,
                hot_x: u32,
                hot_y: u32,
            ) -> VirtioGpuResult;
            fn move_cursor(
                &mut self,
                resource_id: u32,
                cursor: VhostUserGpuCursorPos,
            ) -> VirtioGpuResult;
            fn get_capset_info(&self, index: u32) -> VirtioGpuResult;
            fn get_capset(&self, capset_id: u32, version: u32) -> VirtioGpuResult;
            fn create_context<'a>(
                &mut self,
                ctx_id: u32,
                context_init: u32,
                context_name: Option<&'a str>,
            ) -> VirtioGpuResult;
            fn destroy_context(&mut self, ctx_id: u32) -> VirtioGpuResult;
            fn context_attach_resource(&mut self, ctx_id: u32, resource_id: u32) -> VirtioGpuResult;
            fn context_detach_resource(&mut self, ctx_id: u32, resource_id: u32) -> VirtioGpuResult;
            fn submit_command(
                &mut self,
                ctx_id: u32,
                commands: &mut [u8],
                fence_ids: &[u64],
            ) -> VirtioGpuResult;
            fn force_ctx_0(&self);
            fn resource_assign_uuid(&self, resource_id: u32) -> VirtioGpuResult;
            fn create_fence(&mut self, rutabaga_fence: RutabagaFence) -> VirtioGpuResult;
            fn process_fence(&mut self, ring: VirtioGpuRing, fence_id: u64, desc_index: u16, len: u32) -> bool;
            fn get_event_poll_fd(&self) -> Option<EventFd>;
            fn event_poll(&self);
        }
    }

    const MEM_SIZE: usize = 2 * 1024 * 1024; // 2MiB

    const CURSOR_QUEUE_ADDR: GuestAddress = GuestAddress(0x0);
    const CURSOR_QUEUE_DATA_ADDR: GuestAddress = GuestAddress(0x1_000);
    const CURSOR_QUEUE_SIZE: u16 = 16;
    const CONTROL_QUEUE_ADDR: GuestAddress = GuestAddress(0x2_000);
    const CONTROL_QUEUE_DATA_ADDR: GuestAddress = GuestAddress(0x10_000);
    const CONTROL_QUEUE_SIZE: u16 = 1024;

    fn init() -> (Arc<VhostUserGpuBackend>, GuestMemoryAtomic<GuestMemoryMmap>) {
        let config = GpuConfigBuilder::default()
            .set_gpu_mode(GpuMode::VirglRenderer)
            .set_capset(GpuCapset::VIRGL | GpuCapset::VIRGL2)
            .set_flags(GpuFlags::default())
            .build()
            .unwrap();
        let backend = VhostUserGpuBackend::new(config).unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), MEM_SIZE)]).unwrap(),
        );

        backend.update_memory(mem.clone()).unwrap();
        (backend, mem)
    }

    fn gpu_backend_pair() -> (UnixStream, GpuBackend) {
        let (frontend, backend) = UnixStream::pair().unwrap();
        let backend = GpuBackend::from_stream(backend);

        (frontend, backend)
    }

    #[test]
    fn test_process_gpu_command() {
        let (_, mem) = init();
        let hdr = virtio_gpu_ctrl_hdr::default();

        let test_cmd = |cmd: GpuCommand, setup: fn(&mut MockMockRenderer)| {
            let mut mock_renderer = MockMockRenderer::new();
            mock_renderer.expect_force_ctx_0().return_const(());
            setup(&mut mock_renderer);
            VhostUserGpuBackendInner::process_gpu_command(
                &mut mock_renderer,
                &mem.memory(),
                hdr,
                cmd,
            )
        };

        let cmd = GpuCommand::GetDisplayInfo;
        let result = test_cmd(cmd, |g| {
            g.expect_display_info()
                .return_once(|| Ok(OkDisplayInfo(vec![(1280, 720, true)])));
        });
        assert_matches!(result, Ok(OkDisplayInfo(_)));

        let cmd = GpuCommand::GetEdid(virtio_gpu_get_edid::default());
        let result = test_cmd(cmd, |g| {
            g.expect_get_edid().return_once(|_| {
                Ok(OkEdid {
                    blob: Box::new([0xff; 512]),
                })
            });
        });
        assert_matches!(result, Ok(OkEdid { .. }));

        let cmd = GpuCommand::ResourceCreate2d(virtio_gpu_resource_create_2d::default());
        let result = test_cmd(cmd, |g| {
            g.expect_resource_create_3d()
                .return_once(|_, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::ResourceUnref(virtio_gpu_resource_unref::default());
        let result = test_cmd(cmd, |g| {
            g.expect_unref_resource().return_once(|_| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::SetScanout(virtio_gpu_set_scanout::default());
        let result = test_cmd(cmd, |g| {
            g.expect_set_scanout().return_once(|_, _, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::ResourceFlush(virtio_gpu_resource_flush::default());
        let result = test_cmd(cmd, |g| {
            g.expect_flush_resource().return_once(|_, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::TransferToHost2d(virtio_gpu_transfer_to_host_2d::default());
        let result = test_cmd(cmd, |g| {
            g.expect_transfer_write_2d()
                .return_once(|_, _, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::ResourceAttachBacking(
            virtio_gpu_resource_attach_backing::default(),
            Vec::default(),
        );
        let result = test_cmd(cmd, |g| {
            g.expect_attach_backing()
                .return_once(|_, _, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::ResourceDetachBacking(virtio_gpu_resource_detach_backing::default());
        let result = test_cmd(cmd, |g| {
            g.expect_detach_backing().return_once(|_| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::UpdateCursor(virtio_gpu_update_cursor::default());
        let result = test_cmd(cmd, |g| {
            g.expect_update_cursor()
                .return_once(|_, _, _, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::MoveCursor(virtio_gpu_update_cursor::default());
        let result = test_cmd(cmd, |g| {
            g.expect_move_cursor().return_once(|_, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::GetCapsetInfo(virtio_gpu_get_capset_info::default());
        let result = test_cmd(cmd, |g| {
            g.expect_get_capset_info().return_once(|_| {
                Ok(OkCapsetInfo {
                    capset_id: 1,
                    version: 2,
                    size: 32,
                })
            });
        });
        assert_matches!(
            result,
            Ok(OkCapsetInfo {
                capset_id: 1,
                version: 2,
                size: 32
            })
        );

        let cmd = GpuCommand::GetCapset(virtio_gpu_get_capset::default());
        let result = test_cmd(cmd, |g| {
            // Fixed E0559: Correctly constructing the OkCapset tuple variant with a Vec<u8>
            g.expect_get_capset()
                .return_once(|_, _| Ok(OkCapset(vec![0; 1])));
        });
        assert_matches!(result, Ok(OkCapset { .. }));

        let cmd = GpuCommand::CtxCreate(virtio_gpu_ctx_create::default());
        let result = test_cmd(cmd, |g| {
            g.expect_create_context()
                .return_once(|_, _, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::CtxDestroy(virtio_gpu_ctx_destroy::default());
        let result = test_cmd(cmd, |g| {
            g.expect_destroy_context().return_once(|_| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::CtxAttachResource(virtio_gpu_ctx_resource::default());
        let result = test_cmd(cmd, |g| {
            g.expect_context_attach_resource()
                .return_once(|_, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::CtxDetachResource(virtio_gpu_ctx_resource::default());
        let result = test_cmd(cmd, |g| {
            g.expect_context_detach_resource()
                .return_once(|_, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::ResourceCreate3d(virtio_gpu_resource_create_3d::default());
        let result = test_cmd(cmd, |g| {
            g.expect_resource_create_3d()
                .return_once(|_, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::TransferToHost3d(virtio_gpu_transfer_host_3d::default());
        let result = test_cmd(cmd, |g| {
            g.expect_transfer_write()
                .return_once(|_, _, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::TransferFromHost3d(virtio_gpu_transfer_host_3d::default());
        let result = test_cmd(cmd, |g| {
            g.expect_transfer_read()
                .return_once(|_, _, _, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::CmdSubmit3d {
            cmd_data: vec![0xff; 512],
            fence_ids: vec![],
        };
        let result = test_cmd(cmd, |g| {
            g.expect_submit_command()
                .return_once(|_, _, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));
    }

    fn create_control_vring(
        mem: &GuestMemoryAtomic<GuestMemoryMmap>,
        chains: &[TestingDescChainArgs],
    ) -> (VringRwLock, Vec<Vec<GuestAddress>>, EventFd) {
        create_vring(
            mem,
            chains,
            CONTROL_QUEUE_ADDR,
            CONTROL_QUEUE_DATA_ADDR,
            CONTROL_QUEUE_SIZE,
        )
    }

    fn create_cursor_vring(
        mem: &GuestMemoryAtomic<GuestMemoryMmap>,
        chains: &[TestingDescChainArgs],
    ) -> (VringRwLock, Vec<Vec<GuestAddress>>, EventFd) {
        create_vring(
            mem,
            chains,
            CURSOR_QUEUE_ADDR,
            CURSOR_QUEUE_DATA_ADDR,
            CURSOR_QUEUE_SIZE,
        )
    }

    #[test]
    fn test_handle_event_executes_gpu_commands() {
        let (backend, mem) = init();
        backend.update_memory(mem.clone()).unwrap();

        let hdr = virtio_gpu_ctrl_hdr {
            type_: VIRTIO_GPU_CMD_RESOURCE_CREATE_2D.into(),
            ..Default::default()
        };

        let cmd = virtio_gpu_resource_create_2d {
            resource_id: 1.into(),
            format: VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM.into(),
            width: 1920.into(),
            height: 1080.into(),
        };

        let chain1 = TestingDescChainArgs {
            readable_desc_bufs: &[hdr.as_slice(), cmd.as_slice()],
            writable_desc_lengths: &[mem::size_of::<virtio_gpu_ctrl_hdr>() as u32],
        };

        let chain2 = TestingDescChainArgs {
            readable_desc_bufs: &[hdr.as_slice(), cmd.as_slice()],
            writable_desc_lengths: &[mem::size_of::<virtio_gpu_ctrl_hdr>() as u32],
        };

        let (control_vring, outputs, control_signal_used_queue_evt) =
            create_control_vring(&mem, &[chain1, chain2]);
        let (cursor_vring, _, cursor_signal_used_queue_evt) = create_cursor_vring(&mem, &[]);

        let mem = mem.memory().into_inner();

        let mut mock_renderer = MockMockRenderer::new();
        let seq = &mut mockall::Sequence::new();

        mock_renderer
            .expect_force_ctx_0()
            .return_const(())
            .once()
            .in_sequence(seq);

        mock_renderer
            .expect_resource_create_3d()
            .with(predicate::eq(1), predicate::always())
            .returning(|_, _| Ok(OkNoData))
            .once()
            .in_sequence(seq);

        mock_renderer
            .expect_force_ctx_0()
            .return_const(())
            .once()
            .in_sequence(seq);

        mock_renderer
            .expect_resource_create_3d()
            .with(predicate::eq(1), predicate::always())
            .returning(|_, _| Err(ErrUnspec))
            .once()
            .in_sequence(seq);

        assert_eq!(
            cursor_signal_used_queue_evt.read().unwrap_err().kind(),
            ErrorKind::WouldBlock
        );

        backend
            .inner
            .lock()
            .unwrap()
            .handle_event(0, &mut mock_renderer, &[control_vring, cursor_vring])
            .unwrap();

        let expected_hdr1 = virtio_gpu_ctrl_hdr {
            type_: VIRTIO_GPU_RESP_OK_NODATA.into(),
            ..Default::default()
        };

        let expected_hdr2 = virtio_gpu_ctrl_hdr {
            type_: VIRTIO_GPU_RESP_ERR_UNSPEC.into(),
            ..Default::default()
        };
        control_signal_used_queue_evt
            .read()
            .expect("Expected device to signal used queue!");
        assert_eq!(
            cursor_signal_used_queue_evt.read().unwrap_err().kind(),
            ErrorKind::WouldBlock,
            "Unexpected signal_used_queue on cursor queue!"
        );

        let result_hdr1: virtio_gpu_ctrl_hdr = mem.memory().read_obj(outputs[0][0]).unwrap();
        assert_eq!(result_hdr1, expected_hdr1);

        let result_hdr2: virtio_gpu_ctrl_hdr = mem.memory().read_obj(outputs[1][0]).unwrap();
        assert_eq!(result_hdr2, expected_hdr2);
    }

    #[test]
    fn test_command_with_fence_ready_immediately() {
        const FENCE_ID: u64 = 123;

        let (backend, mem) = init();
        backend.update_memory(mem.clone()).unwrap();

        let hdr = virtio_gpu_ctrl_hdr {
            type_: VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D.into(),
            flags: VIRTIO_GPU_FLAG_FENCE.into(),
            fence_id: FENCE_ID.into(),
            ctx_id: 0.into(),
            ring_idx: 0,
            padding: Default::default(),
        };

        let cmd = virtio_gpu_transfer_host_3d::default();

        let chain = TestingDescChainArgs {
            readable_desc_bufs: &[hdr.as_slice(), cmd.as_slice()],
            writable_desc_lengths: &[mem::size_of::<virtio_gpu_ctrl_hdr>() as u32],
        };

        let (control_vring, outputs, control_signal_used_queue_evt) =
            create_control_vring(&mem, &[chain]);
        let (cursor_vring, _, _) = create_cursor_vring(&mem, &[]);

        let mut mock_renderer = MockMockRenderer::new();
        let seq = &mut mockall::Sequence::new();

        mock_renderer
            .expect_force_ctx_0()
            .return_const(())
            .once()
            .in_sequence(seq);

        mock_renderer
            .expect_transfer_write()
            .returning(|_, _, _| Ok(OkNoData))
            .once()
            .in_sequence(seq);

        mock_renderer
            .expect_create_fence()
            .withf(|fence| fence.fence_id == FENCE_ID)
            .returning(|_| Ok(OkNoData))
            .once()
            .in_sequence(seq);

        mock_renderer
            .expect_process_fence()
            .with(
                predicate::eq(VirtioGpuRing::Global),
                predicate::eq(FENCE_ID),
                predicate::eq(0),
                predicate::eq(mem::size_of_val(&hdr) as u32),
            )
            .return_const(true)
            .once()
            .in_sequence(seq);

        backend
            .inner
            .lock()
            .unwrap()
            .handle_event(0, &mut mock_renderer, &[control_vring, cursor_vring])
            .unwrap();

        let expected_hdr = virtio_gpu_ctrl_hdr {
            type_: VIRTIO_GPU_RESP_OK_NODATA.into(),
            flags: VIRTIO_GPU_FLAG_FENCE.into(),
            fence_id: FENCE_ID.into(),
            ctx_id: 0.into(),
            ring_idx: 0,
            padding: Default::default(),
        };

        control_signal_used_queue_evt
            .read()
            .expect("Expected device to call signal_used_queue!");

        let result_hdr1: virtio_gpu_ctrl_hdr = mem.memory().read_obj(outputs[0][0]).unwrap();
        assert_eq!(result_hdr1, expected_hdr);
    }

    #[test]
    fn test_command_with_fence_not_ready() {
        const FENCE_ID: u64 = 123;
        const CTX_ID: u32 = 1;
        const RING_IDX: u8 = 2;

        let (backend, mem) = init();
        backend.update_memory(mem.clone()).unwrap();

        let hdr = virtio_gpu_ctrl_hdr {
            type_: VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D.into(),
            flags: (VIRTIO_GPU_FLAG_FENCE | VIRTIO_GPU_FLAG_INFO_RING_IDX).into(),
            fence_id: FENCE_ID.into(),
            ctx_id: CTX_ID.into(),
            ring_idx: RING_IDX,
            padding: Default::default(),
        };

        let cmd = virtio_gpu_transfer_host_3d::default();

        let chain = TestingDescChainArgs {
            readable_desc_bufs: &[hdr.as_slice(), cmd.as_slice()],
            writable_desc_lengths: &[mem::size_of::<virtio_gpu_ctrl_hdr>() as u32],
        };

        let (control_vring, _, control_signal_used_queue_evt) =
            create_control_vring(&mem, &[chain]);
        let (cursor_vring, _, _) = create_cursor_vring(&mem, &[]);

        let mut mock_renderer = MockMockRenderer::new();
        let seq = &mut mockall::Sequence::new();

        mock_renderer
            .expect_force_ctx_0()
            .return_const(())
            .once()
            .in_sequence(seq);

        mock_renderer
            .expect_transfer_read()
            .returning(|_, _, _, _| Ok(OkNoData))
            .once()
            .in_sequence(seq);

        mock_renderer
            .expect_create_fence()
            .withf(|fence| fence.fence_id == FENCE_ID)
            .returning(|_| Ok(OkNoData))
            .once()
            .in_sequence(seq);

        mock_renderer
            .expect_process_fence()
            .with(
                predicate::eq(VirtioGpuRing::ContextSpecific {
                    ctx_id: CTX_ID,
                    ring_idx: RING_IDX,
                }),
                predicate::eq(FENCE_ID),
                predicate::eq(0),
                predicate::eq(mem::size_of_val(&hdr) as u32),
            )
            .return_const(false)
            .once()
            .in_sequence(seq);

        backend
            .inner
            .lock()
            .unwrap()
            .handle_event(0, &mut mock_renderer, &[control_vring, cursor_vring])
            .unwrap();

        assert_eq!(
            control_signal_used_queue_evt.read().unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
    }

    #[test]
    fn test_verify_backend_headless() {
        let (backend, _) = init();

        // Headless is disabled, so EDID flag should be set.
        backend.inner.lock().unwrap().gpu_config.flags.headless = false;
        assert_eq!(
            backend.features() & (1 << VIRTIO_GPU_F_EDID),
            1 << VIRTIO_GPU_F_EDID
        );

        // Headless is enabled, so EDID flag should not be set.
        backend.inner.lock().unwrap().gpu_config.flags.headless = true;
        assert_eq!(backend.features() & (1 << VIRTIO_GPU_F_EDID), 0);
    }

    rusty_fork_test! {
        #[test]
        fn test_verify_backend() {
            let gpu_config = GpuConfigBuilder::default()
                .set_gpu_mode(GpuMode::VirglRenderer)
                .set_flags(GpuFlags::default())
                .build()
                .unwrap();
            let backend = VhostUserGpuBackend::new(gpu_config).unwrap();

            assert_eq!(backend.num_queues(), NUM_QUEUES);
            assert_eq!(backend.max_queue_size(), QUEUE_SIZE);
            assert_eq!(backend.features(), 0x0101_7100_001B);
            assert_eq!(
                backend.protocol_features(),
                VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::MQ
            );
            assert_eq!(backend.queues_per_thread(), vec![0xffff_ffff]);
            assert_eq!(backend.get_config(0, 0), Vec::<u8>::new());

            assert!(backend.inner.lock().unwrap().gpu_backend.is_none());
            backend.set_gpu_socket(gpu_backend_pair().1).unwrap();
            assert!(backend.inner.lock().unwrap().gpu_backend.is_some());

            backend.set_event_idx(true);
            assert!(backend.inner.lock().unwrap().event_idx_enabled);

            assert!(backend.exit_event(0).is_some());

            let mem = GuestMemoryAtomic::new(
                GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
            );
            backend.update_memory(mem.clone()).unwrap();

            let vring = VringRwLock::new(mem, 0x1000).unwrap();
            vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
            vring.set_queue_ready(true);

            assert_eq!(
                backend
                    .handle_event(0, EventSet::OUT, &[vring.clone()], 0)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Other
            );

            assert_eq!(
                backend
                    .handle_event(1, EventSet::IN, &[vring.clone()], 0)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Other
            );

            // Hit the loop part
            backend.set_event_idx(true);
            backend
                .handle_event(0, EventSet::IN, &[vring.clone()], 0)
                .unwrap();

            // Hit the non-loop part
            backend.set_event_idx(false);
            backend.handle_event(0, EventSet::IN, &[vring], 0).unwrap();
        }
    }

    mod test_image {
        use super::*;
        const GREEN_PIXEL: u32 = 0x00FF_00FF;
        const RED_PIXEL: u32 = 0x00FF_00FF;
        const BYTES_PER_PIXEL: usize = 4;

        pub fn write(mem: &GuestMemoryMmap, image_addr: GuestAddress, width: u32, height: u32) {
            let mut image_addr: u64 = image_addr.0;
            for i in 0..width * height {
                let pixel = if i % 2 == 0 { RED_PIXEL } else { GREEN_PIXEL };
                let pixel = pixel.to_be_bytes();

                mem.memory()
                    .write_slice(&pixel, GuestAddress(image_addr))
                    .unwrap();
                image_addr += BYTES_PER_PIXEL as u64;
            }
        }
    }

    fn split_into_mem_entries(
        addr: GuestAddress,
        len: u32,
        chunk_size: u32,
    ) -> Vec<virtio_gpu_mem_entry> {
        let mut entries = Vec::new();
        let mut addr = addr.0;
        let mut remaining = len;

        while remaining >= chunk_size {
            entries.push(virtio_gpu_mem_entry {
                addr: addr.into(),
                length: chunk_size.into(),
                padding: Le32::default(),
            });
            addr += u64::from(chunk_size);
            remaining -= chunk_size;
        }

        if remaining != 0 {
            entries.push(virtio_gpu_mem_entry {
                addr: addr.into(),
                length: remaining.into(),
                padding: Le32::default(),
            });
        }

        entries
    }

    fn new_hdr(type_: u32) -> virtio_gpu_ctrl_hdr {
        virtio_gpu_ctrl_hdr {
            type_: type_.into(),
            ..Default::default()
        }
    }

    rusty_fork_test! {
        /// This test uses multiple gpu commands, it crates a resource, writes a test image into it and
        /// then present the display output.
        #[test]
        fn test_display_output() {
            const IMAGE_ADDR: GuestAddress = GuestAddress(0x30_000);
            const IMAGE_WIDTH: u32 = 640;
            const IMAGE_HEIGHT: u32 = 480;
            const RESP_SIZE: u32 = mem::size_of::<virtio_gpu_ctrl_hdr>() as u32;

            // Note: The new `set_scanout` logic for VirglRenderer sends a VhostUserGpuDMABUFScanout
            // message and a file descriptor.
            const EXPECTED_DMABUF_SCANOUT_REQUEST: VhostUserGpuDMABUFScanout = VhostUserGpuDMABUFScanout {
                scanout_id: 1,
                x: 0,
                y: 0,
                width: IMAGE_WIDTH,
                height: IMAGE_HEIGHT,
                fd_width: IMAGE_WIDTH,
                fd_height: IMAGE_HEIGHT,
                fd_stride: IMAGE_WIDTH * 4,
                fd_flags: 0,
                fd_drm_fourcc: 875_708_993, // This is a placeholder; actual value depends on the backend.
            };

            let (backend, mem) = init();
            let (mut gpu_frontend, gpu_backend) = gpu_backend_pair();
            gpu_frontend
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            gpu_frontend
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();

            backend.set_gpu_socket(gpu_backend).unwrap();

            // Unfortunately, there is no way to create a VringEpollHandler directly (the ::new is not public)
            // So we create a daemon to create the epoll handler for us here
            let daemon = VhostUserDaemon::new(
                "vhost-device-gpu-backend".to_string(),
                backend.clone(),
                mem.clone(),
            )
            .expect("Could not create daemon");
            let epoll_handlers = daemon.get_epoll_handlers();
            backend.set_epoll_handler(&epoll_handlers);
            mem::drop(daemon);

            let image_rect = virtio_gpu_rect {
                x: 0.into(),
                y: 0.into(),
                width: IMAGE_WIDTH.into(),
                height: IMAGE_HEIGHT.into(),
            };

            // Construct a command to create a resource
            let hdr = new_hdr(VIRTIO_GPU_CMD_RESOURCE_CREATE_2D);
            let cmd = virtio_gpu_resource_create_2d {
                resource_id: 1.into(),
                format: VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM.into(), // RGBA8888
                width: IMAGE_WIDTH.into(),
                height: IMAGE_HEIGHT.into(),
            };
            let create_resource_cmd = TestingDescChainArgs {
                readable_desc_bufs: &[hdr.as_slice(), cmd.as_slice()],
                writable_desc_lengths: &[RESP_SIZE],
            };

            // Construct a command to attach backing memory location(s) to the resource
            let hdr = new_hdr(VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING);
            let mem_entries = split_into_mem_entries(IMAGE_ADDR, IMAGE_WIDTH * IMAGE_HEIGHT * 4, 4096);
            let cmd = virtio_gpu_resource_attach_backing {
                resource_id: 1.into(),
                nr_entries: (mem_entries.len() as u32).into(),
            };
            let mut readable_desc_bufs = vec![hdr.as_slice(), cmd.as_slice()];
            readable_desc_bufs.extend(mem_entries.iter().map(ByteValued::as_slice));
            let attach_backing_cmd = TestingDescChainArgs {
                readable_desc_bufs: &readable_desc_bufs,
                writable_desc_lengths: &[RESP_SIZE],
            };

            // Construct a command to detach backing memory location(s) from the resource
            let hdr = new_hdr(VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING);
            let cmd = virtio_gpu_resource_detach_backing {
                resource_id: 1.into(),
                padding: Le32::default(),
            };
            let detach_backing_cmd = TestingDescChainArgs {
                readable_desc_bufs: &[hdr.as_slice(), cmd.as_slice()],
                writable_desc_lengths: &[RESP_SIZE],
            };

            // Construct a command to transfer the resource data from the attached memory to gpu
            let hdr = new_hdr(VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D);
            let cmd = virtio_gpu_transfer_to_host_2d {
                r: image_rect,
                offset: 0.into(),
                resource_id: 1.into(),
                padding: Le32::default(),
            };
            let transfer_to_host_cmd = TestingDescChainArgs {
                readable_desc_bufs: &[hdr.as_slice(), cmd.as_slice()],
                writable_desc_lengths: &[RESP_SIZE],
            };

            // Construct a command to transfer the resource data from the host gpu to the attached memory
            let hdr = new_hdr(VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D);
            let cmd = virtio_gpu_transfer_host_3d::default();
            let transfer_from_host_cmd = TestingDescChainArgs {
                readable_desc_bufs: &[hdr.as_slice(), cmd.as_slice()],
                writable_desc_lengths: &[RESP_SIZE],
            };

            // Construct a command to create a context for the given ctx_id in the hdr
            let hdr = new_hdr(VIRTIO_GPU_CMD_CTX_CREATE);
            let cmd = virtio_gpu_ctx_create::default();
            let ctx_create_cmd = TestingDescChainArgs {
                readable_desc_bufs: &[hdr.as_slice(), cmd.as_slice()],
                writable_desc_lengths: &[RESP_SIZE],
            };

            // Construct a command to destroy a context for the given ctx_id in the hdr
            let hdr = new_hdr(VIRTIO_GPU_CMD_CTX_DESTROY);
            let cmd = virtio_gpu_ctx_destroy::default();
            let ctx_destroy_cmd = TestingDescChainArgs {
                readable_desc_bufs: &[hdr.as_slice(), cmd.as_slice()],
                writable_desc_lengths: &[RESP_SIZE],
            };

            // Construct a command to attach a context for the given ctx_id in the hdr
            let hdr = new_hdr(VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE);
            let cmd = virtio_gpu_ctx_resource::default();
            let ctx_attach_cmd = TestingDescChainArgs {
                readable_desc_bufs: &[hdr.as_slice(), cmd.as_slice()],
                writable_desc_lengths: &[RESP_SIZE],
            };

            // Construct a command to detach a context for the given ctx_id in the hdr
            let hdr = new_hdr(VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE);
            let cmd = virtio_gpu_ctx_resource::default();
            let ctx_detach_cmd = TestingDescChainArgs {
                readable_desc_bufs: &[hdr.as_slice(), cmd.as_slice()],
                writable_desc_lengths: &[RESP_SIZE],
            };

            // Construct a command to set the scanout (display) output
            let hdr = new_hdr(VIRTIO_GPU_CMD_SET_SCANOUT);
            let cmd = virtio_gpu_set_scanout {
                r: image_rect,
                resource_id: 1.into(),
                scanout_id: 1.into(),
            };
            let set_scanout_cmd = TestingDescChainArgs {
                readable_desc_bufs: &[hdr.as_slice(), cmd.as_slice()],
                writable_desc_lengths: &[RESP_SIZE],
            };

            // Construct a command to flush the resource
            let hdr = new_hdr(VIRTIO_GPU_CMD_RESOURCE_FLUSH);
            let cmd = virtio_gpu_resource_flush {
                r: image_rect,
                resource_id: 1.into(),
                padding: Le32::default(),
            };
            let flush_resource_cmd = TestingDescChainArgs {
                readable_desc_bufs: &[hdr.as_slice(), cmd.as_slice()],
                writable_desc_lengths: &[RESP_SIZE],
            };

            // Create a control queue with all the commands defined above
            let commands = [
                create_resource_cmd,
                attach_backing_cmd,
                transfer_to_host_cmd,
                transfer_from_host_cmd,
                set_scanout_cmd,
                flush_resource_cmd,
                detach_backing_cmd,
                ctx_create_cmd,
                ctx_attach_cmd,
                ctx_detach_cmd,
                ctx_destroy_cmd,
            ];
            let (control_vring, _, _) = create_control_vring(&mem, &commands);

            // Create an empty cursor queue with no commands
            let (cursor_vring, _, _) = create_cursor_vring(&mem, &[]);

            // Write the test image in guest memory
            test_image::write(&mem.memory(), IMAGE_ADDR, IMAGE_WIDTH, IMAGE_HEIGHT);

            // This simulates the frontend vmm. Here we check the issued frontend requests and if the
            // output matches the test image.
            let frontend_thread = thread::spawn(move || {
                // Read the `set_scanout` message and associated file descriptor.
                let mut scanout_request_hdr = [0; 12];
                gpu_frontend.read_exact(&mut scanout_request_hdr).unwrap();
                let mut scanout_request = VhostUserGpuDMABUFScanout::default();
                gpu_frontend.read_exact(scanout_request.as_mut_slice()).unwrap();

                // Assert that the received message matches the expected DMABUF scanout request.
                assert_eq!(scanout_request, EXPECTED_DMABUF_SCANOUT_REQUEST);

                // Read the `update_scanout` message.
                let mut update_request_hdr = [0; 12];
                let mut update_request = VhostUserGpuUpdate::default();

                gpu_frontend.read_exact(&mut update_request_hdr).unwrap();
                gpu_frontend.read_exact(update_request.as_mut_slice()).unwrap();
            });

            backend
                .handle_event(0, EventSet::IN, &[control_vring, cursor_vring], 0)
                .unwrap();

            frontend_thread.join().unwrap();
        }
    }
}
