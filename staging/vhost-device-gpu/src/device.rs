// vhost device Gpu
//
// Copyright 2024 RedHat
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use log::{debug, error, trace, warn};
use std::{
    cell::RefCell,
    io::{self, Result as IoResult},
    os::fd::AsRawFd,
    sync::{self, Arc, Mutex},
};

use rutabaga_gfx::{
    ResourceCreate3D, RutabagaFence, Transfer3D, RUTABAGA_PIPE_BIND_RENDER_TARGET,
    RUTABAGA_PIPE_TEXTURE_2D,
};
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
    eventfd::{EventFd, EFD_NONBLOCK},
};

use crate::{
    protocol::{
        virtio_gpu_box, virtio_gpu_ctrl_hdr, virtio_gpu_ctx_create, virtio_gpu_ctx_resource,
        virtio_gpu_cursor_pos, virtio_gpu_get_capset, virtio_gpu_get_capset_info,
        virtio_gpu_get_edid, virtio_gpu_rect, virtio_gpu_resource_assign_uuid,
        virtio_gpu_resource_attach_backing, virtio_gpu_resource_create_2d,
        virtio_gpu_resource_create_3d, virtio_gpu_resource_detach_backing,
        virtio_gpu_resource_flush, virtio_gpu_resource_unref, virtio_gpu_set_scanout,
        virtio_gpu_transfer_host_3d, virtio_gpu_transfer_to_host_2d, virtio_gpu_update_cursor,
        GpuCommand, GpuCommandDecodeError,
        GpuResponse::{self, ErrUnspec},
        GpuResponseEncodeError, VirtioGpuConfig, VirtioGpuResult, CONTROL_QUEUE, CURSOR_QUEUE,
        NUM_QUEUES, POLL_EVENT, QUEUE_SIZE, VIRTIO_GPU_FLAG_FENCE, VIRTIO_GPU_FLAG_INFO_RING_IDX,
        VIRTIO_GPU_MAX_SCANOUTS,
    },
    virtio_gpu::{RutabagaVirtioGpu, VirtioGpu, VirtioGpuRing},
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
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

struct VhostUserGpuBackendInner {
    virtio_cfg: VirtioGpuConfig,
    event_idx: bool,
    gpu_backend: Option<GpuBackend>,
    pub exit_event: EventFd,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    renderer: GpuMode,
}

pub struct VhostUserGpuBackend {
    inner: Mutex<VhostUserGpuBackendInner>,
    // this uses sync::Weak to avoid a reference cycle
    epoll_handler: Mutex<sync::Weak<VringEpollHandler<Arc<Self>>>>,
    poll_event_fd: Mutex<Option<EventFd>>,
}

impl VhostUserGpuBackend {
    pub fn new(gpu_config: GpuConfig) -> Result<Arc<Self>> {
        log::trace!("VhostUserGpuBackend::new(config = {:?})", &gpu_config);
        let inner = VhostUserGpuBackendInner {
            virtio_cfg: VirtioGpuConfig {
                events_read: 0.into(),
                events_clear: 0.into(),
                num_scanouts: Le32::from(VIRTIO_GPU_MAX_SCANOUTS as u32),
                num_capsets: RutabagaVirtioGpu::MAX_NUMBER_OF_CAPSETS.into(),
            },
            event_idx: false,
            gpu_backend: None,
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| Error::EventFdFailed)?,
            mem: None,
            renderer: gpu_config.get_renderer(),
        };

        Ok(Arc::new(Self {
            inner: Mutex::new(inner),
            epoll_handler: Mutex::new(sync::Weak::new()),
            poll_event_fd: Mutex::new(None),
        }))
    }

    pub fn set_epoll_handler(&self, epoll_handlers: &[Arc<VringEpollHandler<Arc<Self>>>]) {
        // We only expect 1 thread to which we want to register all handlers
        assert_eq!(epoll_handlers.len(), 1);
        let mut handler = match self.epoll_handler.lock() {
            Ok(h) => h,
            Err(poisoned) => poisoned.into_inner(),
        };
        *handler = Arc::downgrade(&epoll_handlers[0]);
    }
}

impl VhostUserGpuBackendInner {
    fn process_gpu_command(
        &mut self,
        virtio_gpu: &mut RutabagaVirtioGpu,
        mem: &GuestMemoryMmap,
        hdr: virtio_gpu_ctrl_hdr,
        cmd: GpuCommand,
    ) -> VirtioGpuResult {
        virtio_gpu.force_ctx_0();
        debug!("process_gpu_command: {cmd:?}");
        match cmd {
            GpuCommand::GetDisplayInfo => {
                if let Some(gpu_backend) = self.gpu_backend.as_mut() {
                    match gpu_backend.get_display_info() {
                        Ok(display_info) => {
                            let virtio_display = virtio_gpu.display_info(display_info);
                            debug!("Displays: {:?}", virtio_display);
                            Ok(GpuResponse::OkDisplayInfo(virtio_display))
                        }
                        Err(err) => {
                            error!("Failed to get display info: {:?}", err);
                            Err(ErrUnspec)
                        }
                    }
                } else {
                    error!("{cmd:?} Failed to get GPU backend");
                    Err(ErrUnspec)
                }
            }
            GpuCommand::GetEdid(virtio_gpu_get_edid { scanout, .. }) => {
                let edid_req: VhostUserGpuEdidRequest = VhostUserGpuEdidRequest {
                    scanout_id: scanout,
                };
                if let Some(gpu_backend) = self.gpu_backend.as_mut() {
                    virtio_gpu.get_edid(gpu_backend, edid_req)
                } else {
                    error!("{cmd:?} Failed to get GPU backend");
                    Err(ErrUnspec)
                }
            }
            GpuCommand::ResourceCreate2d(virtio_gpu_resource_create_2d {
                resource_id,
                format,
                width,
                height,
            }) => {
                let resource_create_3d = ResourceCreate3D {
                    target: RUTABAGA_PIPE_TEXTURE_2D,
                    format,
                    bind: RUTABAGA_PIPE_BIND_RENDER_TARGET,
                    width,
                    height,
                    depth: 1,
                    array_size: 1,
                    last_level: 0,
                    nr_samples: 0,
                    flags: 0,
                };

                virtio_gpu.resource_create_3d(resource_id, resource_create_3d)
            }
            GpuCommand::ResourceUnref(virtio_gpu_resource_unref { resource_id, .. }) => {
                virtio_gpu.unref_resource(resource_id)
            }
            GpuCommand::SetScanout(virtio_gpu_set_scanout {
                r,
                scanout_id,
                resource_id,
            }) => {
                if let Some(gpu_backend) = self.gpu_backend.as_mut() {
                    virtio_gpu.set_scanout(gpu_backend, scanout_id, resource_id, r.into())
                } else {
                    error!("{cmd:?} Failed to get GPU backend");
                    Err(ErrUnspec)
                }
            }
            GpuCommand::ResourceFlush(virtio_gpu_resource_flush { resource_id, r, .. }) => {
                if let Some(gpu_backend) = self.gpu_backend.as_mut() {
                    virtio_gpu.flush_resource(resource_id, gpu_backend, r.into())
                } else {
                    error!("{cmd:?} Failed to get GPU backend");
                    Err(ErrUnspec)
                }
            }
            GpuCommand::TransferToHost2d(virtio_gpu_transfer_to_host_2d {
                resource_id,
                r:
                    virtio_gpu_rect {
                        x,
                        y,
                        width,
                        height,
                    },
                offset,
                ..
            }) => {
                let transfer = Transfer3D::new_2d(x, y, width, height, offset);
                virtio_gpu.transfer_write(0, resource_id, transfer)
            }
            GpuCommand::ResourceAttachBacking(
                virtio_gpu_resource_attach_backing { resource_id, .. },
                iovecs,
            ) => virtio_gpu.attach_backing(resource_id, mem, iovecs),
            GpuCommand::ResourceDetachBacking(virtio_gpu_resource_detach_backing {
                resource_id,
                ..
            }) => virtio_gpu.detach_backing(resource_id),
            GpuCommand::UpdateCursor(virtio_gpu_update_cursor {
                pos:
                    virtio_gpu_cursor_pos {
                        scanout_id, x, y, ..
                    },
                resource_id,
                hot_x,
                hot_y,
                ..
            }) => {
                if let Some(gpu_backend) = self.gpu_backend.as_mut() {
                    let cursor_pos = VhostUserGpuCursorPos { scanout_id, x, y };
                    virtio_gpu.update_cursor(resource_id, gpu_backend, cursor_pos, hot_x, hot_y)
                } else {
                    error!("{cmd:?} Failed to get GPU backend");
                    Err(ErrUnspec)
                }
            }
            GpuCommand::MoveCursor(virtio_gpu_update_cursor {
                pos:
                    virtio_gpu_cursor_pos {
                        scanout_id, x, y, ..
                    },
                resource_id,
                ..
            }) => {
                if let Some(gpu_backend) = self.gpu_backend.as_mut() {
                    let cursor = VhostUserGpuCursorPos { scanout_id, x, y };
                    virtio_gpu.move_cursor(resource_id, gpu_backend, cursor)
                } else {
                    error!("{cmd:?} Failed to get GPU backend");
                    Err(ErrUnspec)
                }
            }
            GpuCommand::ResourceAssignUuid(virtio_gpu_resource_assign_uuid {
                resource_id, ..
            }) => virtio_gpu.resource_assign_uuid(resource_id),
            GpuCommand::GetCapsetInfo(virtio_gpu_get_capset_info { capset_index, .. }) => {
                virtio_gpu.get_capset_info(capset_index)
            }
            GpuCommand::GetCapset(virtio_gpu_get_capset {
                capset_id,
                capset_version,
            }) => virtio_gpu.get_capset(capset_id, capset_version),

            GpuCommand::CtxCreate(virtio_gpu_ctx_create {
                context_init,
                debug_name,
                ..
            }) => {
                let context_name: Option<String> = String::from_utf8(debug_name.to_vec()).ok();
                virtio_gpu.create_context(hdr.ctx_id, context_init, context_name.as_deref())
            }
            GpuCommand::CtxDestroy(_info) => virtio_gpu.destroy_context(hdr.ctx_id),
            GpuCommand::CtxAttachResource(virtio_gpu_ctx_resource { resource_id, .. }) => {
                virtio_gpu.context_attach_resource(hdr.ctx_id, resource_id)
            }
            GpuCommand::CtxDetachResource(virtio_gpu_ctx_resource { resource_id, .. }) => {
                virtio_gpu.context_detach_resource(hdr.ctx_id, resource_id)
            }
            GpuCommand::ResourceCreate3d(virtio_gpu_resource_create_3d {
                resource_id,
                target,
                format,
                bind,
                width,
                height,
                depth,
                array_size,
                last_level,
                nr_samples,
                flags,
                ..
            }) => {
                let resource_create_3d = ResourceCreate3D {
                    target,
                    format,
                    bind,
                    width,
                    height,
                    depth,
                    array_size,
                    last_level,
                    nr_samples,
                    flags,
                };

                virtio_gpu.resource_create_3d(resource_id, resource_create_3d)
            }
            GpuCommand::TransferToHost3d(virtio_gpu_transfer_host_3d {
                box_: virtio_gpu_box { x, y, z, w, h, d },
                offset,
                resource_id,
                level,
                stride,
                layer_stride,
            }) => {
                let ctx_id = hdr.ctx_id;

                let transfer = Transfer3D {
                    x,
                    y,
                    z,
                    w,
                    h,
                    d,
                    level,
                    stride,
                    layer_stride,
                    offset,
                };

                virtio_gpu.transfer_write(ctx_id, resource_id, transfer)
            }
            GpuCommand::TransferFromHost3d(virtio_gpu_transfer_host_3d {
                box_: virtio_gpu_box { x, y, z, w, h, d },
                offset,
                resource_id,
                level,
                stride,
                layer_stride,
            }) => {
                let ctx_id = hdr.ctx_id;

                let transfer = Transfer3D {
                    x,
                    y,
                    z,
                    w,
                    h,
                    d,
                    level,
                    stride,
                    layer_stride,
                    offset,
                };

                virtio_gpu.transfer_read(ctx_id, resource_id, transfer, None)
            }
            GpuCommand::CmdSubmit3d {
                fence_ids,
                mut cmd_data,
            } => virtio_gpu.submit_command(hdr.ctx_id, &mut cmd_data, &fence_ids),
            GpuCommand::ResourceCreateBlob(_info) => {
                panic!("virtio_gpu: GpuCommand::ResourceCreateBlob unimplemented");
            }
            GpuCommand::SetScanoutBlob(_info) => {
                panic!("virtio_gpu: GpuCommand::SetScanoutBlob unimplemented");
            }
            GpuCommand::ResourceMapBlob(_info) => {
                panic!("virtio_gpu: GpuCommand::ResourceMapBlob unimplemented");
            }
            GpuCommand::ResourceUnmapBlob(_info) => {
                panic!("virtio_gpu: GpuCommand::ResourceUnmapBlob unimplemented");
            }
        }
    }

    fn process_queue_chain(
        &mut self,
        virtio_gpu: &mut RutabagaVirtioGpu,
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
                // TODO: consider having a method that return &'static str for logging purpose
                let cmd_name = format!("{:?}", gpu_cmd);
                let response_result = self.process_gpu_command(virtio_gpu, &mem, ctrl_hdr, gpu_cmd);
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
            if ctrl_hdr.flags & VIRTIO_GPU_FLAG_FENCE != 0 {
                flags = ctrl_hdr.flags;
                fence_id = ctrl_hdr.fence_id;
                ctx_id = ctrl_hdr.ctx_id;
                ring_idx = ctrl_hdr.ring_idx;

                let fence = RutabagaFence {
                    flags,
                    fence_id,
                    ctx_id,
                    ring_idx,
                };
                if let Err(fence_response) = virtio_gpu.create_fence(fence) {
                    warn!("Failed to create fence: fence_id: {fence_id} fence_response: {fence_response}");
                    response = fence_response;
                }
            }
        }

        // Prepare the response now, even if it is going to wait until
        // fence is complete.
        let response_len = response
            .encode(flags, fence_id, ctx_id, ring_idx, writer)
            .map_err(Error::GpuResponseEncode)?;

        let mut add_to_queue = true;
        if flags & VIRTIO_GPU_FLAG_FENCE != 0 {
            let ring = match flags & VIRTIO_GPU_FLAG_INFO_RING_IDX {
                0 => VirtioGpuRing::Global,
                _ => VirtioGpuRing::ContextSpecific { ctx_id, ring_idx },
            };
            debug!("Trying to process_fence for the command");
            add_to_queue = virtio_gpu.process_fence(ring, fence_id, head_index, response_len);
        }

        if add_to_queue {
            vring
                .add_used(head_index, response_len)
                .map_err(Error::QueueAddUsed)?;
            trace!("add_used {}bytes", response_len);
            *signal_used_queue = true;
        }
        Ok(())
    }

    /// Process the requests in the vring and dispatch replies
    fn process_queue(
        &mut self,
        virtio_gpu: &mut RutabagaVirtioGpu,
        vring: &VringRwLock,
    ) -> Result<()> {
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
                virtio_gpu,
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
        &mut self,
        device_event: u16,
        virtio_gpu: &mut RutabagaVirtioGpu,
        vrings: &[VringRwLock],
    ) -> IoResult<()> {
        match device_event {
            CONTROL_QUEUE | CURSOR_QUEUE => {
                let vring = &vrings
                    .get(device_event as usize)
                    .ok_or_else(|| Error::HandleEventUnknown)?;
                if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_queue() until it stops finding new
                    // requests on the queue.
                    loop {
                        vring.disable_notification().unwrap();
                        self.process_queue(virtio_gpu, vring)?;
                        if !vring.enable_notification().unwrap() {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    self.process_queue(virtio_gpu, vring)?;
                }
            }
            POLL_EVENT => {
                trace!("Handling POLL_EVENT");
                virtio_gpu.event_poll()
            }
            _ => {
                warn!("unhandled device_event: {}", device_event);
                return Err(Error::HandleEventUnknown.into());
            }
        }

        Ok(())
    }

    fn lazy_init_and_handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        _thread_id: usize,
    ) -> IoResult<Option<EventFd>> {
        // We use thread_local here because it is the easiest way to handle VirtioGpu being !Send
        thread_local! {
            static VIRTIO_GPU_REF: RefCell<Option<RutabagaVirtioGpu>> = const { RefCell::new(None) };
        }

        debug!("Handle event called");
        if evset != EventSet::IN {
            return Err(Error::HandleEventNotEpollIn.into());
        };

        let mut event_poll_fd = None;
        VIRTIO_GPU_REF.with_borrow_mut(|maybe_virtio_gpu| {
            // Lazy initializes the virtio_gpu
            let virtio_gpu = maybe_virtio_gpu.get_or_insert_with(|| {
                // We currently pass the CONTROL_QUEUE vring to RutabagaVirtioGpu, because we only
                // expect to process fences for that queue.
                let control_vring = &vrings[CONTROL_QUEUE as usize];

                // VirtioGpu::new can be called once per process (otherwise it panics),
                // so if somehow another thread accidentally wants to create another gpu here,
                // it will panic anyway
                let virtio_gpu = RutabagaVirtioGpu::new(control_vring, self.renderer);
                event_poll_fd = virtio_gpu.get_event_poll_fd();
                virtio_gpu
            });

            self.handle_event(device_event, virtio_gpu, vrings)
        })?;

        Ok(event_poll_fd)
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

/// VhostUserBackend trait methods
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
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_F_RING_RESET
            | 1 << VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | 1 << VIRTIO_GPU_F_VIRGL
            | 1 << VIRTIO_GPU_F_EDID
            | 1 << VIRTIO_GPU_F_RESOURCE_BLOB
            | 1 << VIRTIO_GPU_F_CONTEXT_INIT
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        debug!("Protocol features called");
        VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::MQ
    }

    fn set_event_idx(&self, enabled: bool) {
        self.inner.lock().unwrap().event_idx = enabled;
        debug!("Event idx set to: {}", enabled);
    }

    fn update_memory(&self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        debug!("Update memory called");
        self.inner.lock().unwrap().mem = Some(mem);
        Ok(())
    }

    fn set_gpu_socket(&self, backend: GpuBackend) {
        self.inner.lock().unwrap().gpu_backend = Some(backend);
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        self.inner.lock().unwrap().get_config(offset, size)
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        self.inner.lock().unwrap().exit_event.try_clone().ok()
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
            let epoll_handler = match self.epoll_handler.lock() {
                Ok(h) => h,
                Err(poisoned) => poisoned.into_inner(),
            };
            let epoll_handler = match epoll_handler.upgrade() {
                Some(handler) => handler,
                None => {
                    return Err(
                        Error::EpollHandler("Failed to upgrade epoll handler".to_string()).into(),
                    );
                }
            };
            epoll_handler
                .register_listener(poll_event_fd.as_raw_fd(), EventSet::IN, POLL_EVENT as u64)
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
    use super::*;
    use crate::protocol::*;
    use rutabaga_gfx::{RutabagaBuilder, RutabagaComponentType, RutabagaHandler};
    use std::{
        collections::BTreeMap,
        mem::size_of,
        sync::{Arc, Mutex},
    };
    use vhost_user_backend::{VringRwLock, VringT};
    use virtio_bindings::bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::{mock::MockSplitQueue, Descriptor, DescriptorChain, Queue};
    use vm_memory::{
        Address, ByteValued, Bytes, GuestAddress, GuestMemoryAtomic, GuestMemoryLoadGuard,
        GuestMemoryMmap,
    };

    type GpuDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

    const SOCKET_PATH: &str = "vgpu.socket";

    #[derive(Copy, Clone, Default)]
    #[repr(C)]
    struct VirtioGpuOutHdr {
        a: u16,
        b: u16,
        c: u32,
    }

    // SAFETY: The layout of the structure is fixed and can be initialized by
    // reading its content from byte array.
    unsafe impl ByteValued for VirtioGpuOutHdr {}

    #[derive(Copy, Clone, Default)]
    #[repr(C)]
    struct VirtioGpuInHdr {
        d: u8,
    }

    // SAFETY: The layout of the structure is fixed and can be initialized by
    // reading its content from byte array.
    unsafe impl ByteValued for VirtioGpuInHdr {}

    fn init() -> (
        Arc<VhostUserGpuBackend>,
        GuestMemoryAtomic<GuestMemoryMmap>,
        VringRwLock,
    ) {
        let backend = VhostUserGpuBackend::new(GpuConfig::new(
            SOCKET_PATH.into(),
            GpuMode::ModeVirglRenderer,
        ))
        .unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem.clone(), 16).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);

        (backend, mem, vring)
    }

    // Prepares a single chain of descriptors
    fn prepare_descriptors(
        mut next_addr: u64,
        mem: &GuestMemoryLoadGuard<GuestMemoryMmap<()>>,
        buf: &mut Vec<u8>,
        cmd_type: u32,
    ) -> Vec<Descriptor> {
        let mut descriptors = Vec::new();
        let mut index = 0;

        // Gpu header descriptor
        let ctrl_hdr = virtio_gpu_ctrl_hdr {
            type_: cmd_type,
            ..virtio_gpu_ctrl_hdr::default()
        };

        let desc_out = Descriptor::new(
            next_addr,
            size_of::<virtio_gpu_ctrl_hdr>() as u32,
            VRING_DESC_F_NEXT as u16,
            index + 1,
        );
        next_addr += desc_out.len() as u64;
        index += 1;

        mem.write_obj::<virtio_gpu_ctrl_hdr>(ctrl_hdr, desc_out.addr())
            .unwrap();
        descriptors.push(desc_out);

        // Buf descriptor: optional
        if !buf.is_empty() {
            let desc_buf = Descriptor::new(
                next_addr,
                buf.len() as u32,
                (VRING_DESC_F_WRITE | VRING_DESC_F_NEXT) as u16,
                index + 1,
            );
            next_addr += desc_buf.len() as u64;

            mem.write(buf, desc_buf.addr()).unwrap();
            descriptors.push(desc_buf);
        }

        // In response descriptor
        let desc_in = Descriptor::new(
            next_addr,
            size_of::<VirtioGpuInHdr>() as u32,
            VRING_DESC_F_WRITE as u16,
            0,
        );
        descriptors.push(desc_in);
        descriptors
    }

    // Prepares a single chain of descriptors
    fn prepare_desc_chain(
        buf: &mut Vec<u8>,
        cmd_type: u32,
    ) -> (Arc<VhostUserGpuBackend>, VringRwLock) {
        let (backend, mem, vring) = init();
        let mem_handle = mem.memory();
        let vq = MockSplitQueue::new(&*mem_handle, 16);
        let next_addr = vq.desc_table().total_size() + 0x100;

        let descriptors = prepare_descriptors(next_addr, &mem_handle, buf, cmd_type);

        vq.build_desc_chain(&descriptors).unwrap();

        // Put the descriptor index 0 in the first available ring position.
        mem_handle
            .write_obj(0u16, vq.avail_addr().unchecked_add(4))
            .unwrap();

        // Set `avail_idx` to 1.
        mem_handle
            .write_obj(1u16, vq.avail_addr().unchecked_add(2))
            .unwrap();

        vring.set_queue_size(16);
        vring
            .set_queue_info(vq.desc_table_addr().0, vq.avail_addr().0, vq.used_addr().0)
            .unwrap();
        vring.set_queue_ready(true);

        backend.update_memory(mem).unwrap();

        (backend, vring)
    }

    // Prepares a chain of descriptors
    fn prepare_desc_chains(
        mem: &GuestMemoryAtomic<GuestMemoryMmap>,
        buf: &mut Vec<u8>,
        cmd_type: u32,
    ) -> GpuDescriptorChain {
        let mem_handle = mem.memory();
        let vq = MockSplitQueue::new(&*mem_handle, 16);
        let next_addr = vq.desc_table().total_size() + 0x100;

        let descriptors = prepare_descriptors(next_addr, &mem_handle, buf, cmd_type);

        for (idx, desc) in descriptors.iter().enumerate() {
            vq.desc_table().store(idx as u16, *desc).unwrap();
        }

        // Put the descriptor index 0 in the first available ring position.
        mem_handle
            .write_obj(0u16, vq.avail_addr().unchecked_add(4))
            .unwrap();

        // Set `avail_idx` to 1.
        mem_handle
            .write_obj(1u16, vq.avail_addr().unchecked_add(2))
            .unwrap();

        // Create descriptor chain from pre-filled memory
        vq.create_queue::<Queue>()
            .unwrap()
            .iter(mem_handle)
            .unwrap()
            .next()
            .unwrap()
    }

    fn new_2d() -> RutabagaVirtioGpu {
        let rutabaga = RutabagaBuilder::new(RutabagaComponentType::Rutabaga2D, 0)
            .build(RutabagaHandler::new(|_| {}), None)
            .unwrap();
        RutabagaVirtioGpu {
            rutabaga,
            resources: BTreeMap::default(),
            fence_state: Arc::new(Mutex::new(Default::default())),
            scanouts: Default::default(),
        }
    }

    #[test]
    fn test_process_queue_chain() {
        let (backend, mem, _) = init();
        backend.update_memory(mem.clone()).unwrap();
        let mut backend_inner = backend.inner.lock().unwrap();

        let vring = VringRwLock::new(mem.clone(), 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);

        let mut buf: Vec<u8> = vec![0; 30];
        let command_types = [
            VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
            VIRTIO_GPU_CMD_RESOURCE_UNREF,
            VIRTIO_GPU_CMD_SET_SCANOUT,
            VIRTIO_GPU_CMD_SET_SCANOUT_BLOB,
            VIRTIO_GPU_CMD_RESOURCE_FLUSH,
            VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D,
            VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING,
            VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING,
            VIRTIO_GPU_CMD_GET_CAPSET,
            VIRTIO_GPU_CMD_GET_CAPSET_INFO,
            VIRTIO_GPU_CMD_GET_EDID,
            VIRTIO_GPU_CMD_CTX_CREATE,
            VIRTIO_GPU_CMD_CTX_DESTROY,
            VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE,
            VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE,
            VIRTIO_GPU_CMD_RESOURCE_CREATE_3D,
            VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D,
            VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D,
            VIRTIO_GPU_CMD_SUBMIT_3D,
            VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB,
            VIRTIO_GPU_CMD_RESOURCE_MAP_BLOB,
            VIRTIO_GPU_CMD_RESOURCE_UNMAP_BLOB,
            VIRTIO_GPU_CMD_UPDATE_CURSOR,
            VIRTIO_GPU_CMD_MOVE_CURSOR,
            VIRTIO_GPU_CMD_RESOURCE_ASSIGN_UUID,
        ];
        for cmd_type in command_types {
            let desc_chain = prepare_desc_chains(&mem, &mut buf, cmd_type);
            let mem = mem.memory().into_inner();

            let mut reader = desc_chain
                .clone()
                .reader(&mem)
                .map_err(Error::CreateReader)
                .unwrap();
            let mut writer = desc_chain
                .clone()
                .writer(&mem)
                .map_err(Error::CreateWriter)
                .unwrap();

            let mut virtio_gpu = new_2d();
            let mut signal_used_queue = true;

            backend_inner
                .process_queue_chain(
                    &mut virtio_gpu,
                    &vring,
                    desc_chain.head_index(),
                    &mut reader,
                    &mut writer,
                    &mut signal_used_queue,
                )
                .unwrap();
        }
    }

    #[test]
    fn test_process_queue() {
        // Test process_queue functionality
        let mut buf: Vec<u8> = vec![0; 30];
        let (backend, vring) = prepare_desc_chain(&mut buf, 0);
        let mut backend_inner = backend.inner.lock().unwrap();

        let mut virtio_gpu = new_2d();
        backend_inner
            .process_queue(&mut virtio_gpu, &vring)
            .unwrap();
    }

    #[test]
    #[ignore = "This test needs to modified to mock GpuBackend"]
    fn test_process_gpu_command() {
        let (backend, mem, _) = init();
        let mut backend_inner = backend.inner.lock().unwrap();

        backend_inner.mem = Some(mem.clone());
        let mem = mem.memory().into_inner();
        let mut virtio_gpu = new_2d();
        let hdr = virtio_gpu_ctrl_hdr::default();
        let gpu_cmd = [
            GpuCommand::ResourceCreate2d(virtio_gpu_resource_create_2d::default()),
            GpuCommand::ResourceUnref(virtio_gpu_resource_unref::default()),
            GpuCommand::ResourceFlush(virtio_gpu_resource_flush::default()),
            GpuCommand::GetCapset(virtio_gpu_get_capset::default()),
            GpuCommand::ResourceCreate3d(virtio_gpu_resource_create_3d::default()),
        ];
        for cmd in gpu_cmd {
            backend_inner
                .process_gpu_command(&mut virtio_gpu, &mem, hdr, cmd)
                .unwrap();
        }
    }

    #[test]
    fn test_process_gpu_command_failure() {
        let (backend, mem, _) = init();
        let mut backend_inner = backend.inner.lock().unwrap();
        backend_inner.mem = Some(mem.clone());

        let mem = mem.memory().into_inner();
        let mut virtio_gpu = new_2d();
        let hdr = virtio_gpu_ctrl_hdr::default();
        let gpu_cmd = [
            GpuCommand::TransferToHost2d(virtio_gpu_transfer_to_host_2d::default()),
            GpuCommand::TransferToHost3d(virtio_gpu_transfer_host_3d::default()),
            GpuCommand::ResourceDetachBacking(virtio_gpu_resource_detach_backing::default()),
            GpuCommand::GetCapsetInfo(virtio_gpu_get_capset_info::default()),
            GpuCommand::CtxCreate(virtio_gpu_ctx_create::default()),
            GpuCommand::CtxAttachResource(virtio_gpu_ctx_resource::default()),
            GpuCommand::CtxDetachResource(virtio_gpu_ctx_resource::default()),
            GpuCommand::CtxDestroy(virtio_gpu_ctx_destroy::default()),
            GpuCommand::ResourceAssignUuid(virtio_gpu_resource_assign_uuid::default()),
            GpuCommand::ResourceAttachBacking(
                virtio_gpu_resource_attach_backing::default(),
                [(GuestAddress(0), 0x1000)].to_vec(),
            ),
            GpuCommand::CmdSubmit3d {
                cmd_data: Vec::new(),
                fence_ids: Vec::new(),
            },
        ];
        for cmd in gpu_cmd {
            backend_inner
                .process_gpu_command(&mut virtio_gpu, &mem, hdr, cmd)
                .unwrap_err();
        }
    }

    #[test]
    fn test_verify_backend() {
        let gpu_config = GpuConfig::new(SOCKET_PATH.into(), GpuMode::ModeVirglRenderer);
        let backend = VhostUserGpuBackend::new(gpu_config).unwrap();

        assert_eq!(backend.num_queues(), NUM_QUEUES);
        assert_eq!(backend.max_queue_size(), QUEUE_SIZE);
        assert_eq!(backend.features(), 0x1017100001B);
        assert_eq!(
            backend.protocol_features(),
            VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::MQ
        );
        assert_eq!(backend.queues_per_thread(), vec![0xffff_ffff]);
        assert_eq!(backend.get_config(0, 0), vec![]);

        backend.set_event_idx(true);
        assert!(backend.inner.lock().unwrap().event_idx);

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

    #[test]
    fn test_gpu_command_encode() {
        let (backend, mem, _) = init();
        backend.update_memory(mem.clone()).unwrap();

        let mut buf: Vec<u8> = vec![0; 2048];
        let desc_chain = prepare_desc_chains(&mem, &mut buf, 0);

        let mem = mem.memory();

        let mut writer = desc_chain
            .clone()
            .writer(&mem)
            .map_err(Error::CreateWriter)
            .unwrap();

        let resp = GpuResponse::OkNoData;
        let resp_ok_nodata = GpuResponse::encode(&resp, 0, 0, 0, 0, &mut writer).unwrap();
        assert_eq!(resp_ok_nodata, 24);

        let resp = GpuResponse::OkDisplayInfo(vec![(0, 0, false)]);
        let resp_display_info = GpuResponse::encode(&resp, 0, 0, 0, 0, &mut writer).unwrap();
        assert_eq!(resp_display_info, 408);

        let edid_data: Box<[u8]> = Box::new([0u8; 1024]);
        let resp = GpuResponse::OkEdid { blob: edid_data };
        let resp_edid = GpuResponse::encode(&resp, 0, 0, 0, 0, &mut writer).unwrap();
        assert_eq!(resp_edid, 1056);

        let resp = GpuResponse::OkCapset(vec![]);
        let resp_capset = GpuResponse::encode(&resp, 0, 0, 0, 0, &mut writer).unwrap();
        assert_eq!(resp_capset, 24);

        let resp = GpuResponse::OkCapsetInfo {
            capset_id: 0,
            version: 0,
            size: 0,
        };
        let resp_capset = GpuResponse::encode(&resp, 0, 0, 0, 0, &mut writer).unwrap();
        assert_eq!(resp_capset, 40);

        let resp = GpuResponse::OkResourcePlaneInfo {
            format_modifier: 0,
            plane_info: vec![],
        };
        let resp_resource_planeinfo = GpuResponse::encode(&resp, 0, 0, 0, 0, &mut writer).unwrap();
        assert_eq!(resp_resource_planeinfo, 72);

        let resp = GpuResponse::OkResourceUuid { uuid: [0u8; 16] };
        let resp_resource_uuid = GpuResponse::encode(&resp, 0, 0, 0, 0, &mut writer).unwrap();
        assert_eq!(resp_resource_uuid, 40);

        let resp = GpuResponse::OkMapInfo { map_info: 0 };
        let resp_map_info = GpuResponse::encode(&resp, 0, 0, 0, 0, &mut writer).unwrap();
        assert_eq!(resp_map_info, 32);
    }
}
