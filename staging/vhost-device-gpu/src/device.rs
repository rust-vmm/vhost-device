// vhost device Gpu
//
// Copyright 2024 RedHat
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use crate::{
    protocol::{
        virtio_gpu_box, virtio_gpu_ctrl_hdr, virtio_gpu_ctx_create, virtio_gpu_ctx_resource,
        virtio_gpu_cursor_pos, virtio_gpu_get_capset, virtio_gpu_get_capset_info,
        virtio_gpu_get_edid, virtio_gpu_rect, virtio_gpu_resource_attach_backing,
        virtio_gpu_resource_create_2d, virtio_gpu_resource_create_3d,
        virtio_gpu_resource_detach_backing, virtio_gpu_resource_flush, virtio_gpu_resource_unref,
        virtio_gpu_set_scanout, virtio_gpu_transfer_host_3d, virtio_gpu_transfer_to_host_2d,
        virtio_gpu_update_cursor, GpuCommand, GpuCommandDecodeError, GpuResponse::ErrUnspec,
        GpuResponseEncodeError, VirtioGpuConfig, VirtioGpuResult, CONTROL_QUEUE, CURSOR_QUEUE,
        NUM_QUEUES, POLL_EVENT, QUEUE_SIZE, VIRTIO_GPU_FLAG_FENCE, VIRTIO_GPU_FLAG_INFO_RING_IDX,
        VIRTIO_GPU_MAX_SCANOUTS,
    },
    virtio_gpu::{RutabagaVirtioGpu, VirtioGpu, VirtioGpuRing},
    GpuConfig, GpuMode,
};
use log::{debug, error, trace, warn};
use rutabaga_gfx::{
    ResourceCreate3D, RutabagaFence, Transfer3D, RUTABAGA_PIPE_BIND_RENDER_TARGET,
    RUTABAGA_PIPE_TEXTURE_2D,
};
use std::{
    cell::RefCell,
    io::ErrorKind,
    io::{self, Result as IoResult},
    os::fd::AsRawFd,
    sync::{self, Arc, Mutex},
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
        virtio_gpu: &mut impl VirtioGpu,
        mem: &GuestMemoryMmap,
        hdr: virtio_gpu_ctrl_hdr,
        cmd: GpuCommand,
    ) -> VirtioGpuResult {
        virtio_gpu.force_ctx_0();
        debug!("process_gpu_command: {cmd:?}");
        match cmd {
            GpuCommand::GetDisplayInfo => virtio_gpu.display_info(),
            GpuCommand::GetEdid(virtio_gpu_get_edid { scanout, .. }) => {
                let edid_req: VhostUserGpuEdidRequest = VhostUserGpuEdidRequest {
                    scanout_id: scanout,
                };
                virtio_gpu.get_edid(edid_req)
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
            }) => virtio_gpu.set_scanout(scanout_id, resource_id, r.into()),
            GpuCommand::ResourceFlush(virtio_gpu_resource_flush { resource_id, r, .. }) => {
                virtio_gpu.flush_resource(resource_id, r.into())
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
                let cursor_pos = VhostUserGpuCursorPos { scanout_id, x, y };
                virtio_gpu.update_cursor(resource_id, cursor_pos, hot_x, hot_y)
            }
            GpuCommand::MoveCursor(virtio_gpu_update_cursor {
                pos:
                    virtio_gpu_cursor_pos {
                        scanout_id, x, y, ..
                    },
                resource_id,
                ..
            }) => {
                let cursor = VhostUserGpuCursorPos { scanout_id, x, y };
                virtio_gpu.move_cursor(resource_id, cursor)
            }
            GpuCommand::ResourceAssignUuid(_info) => {
                panic!("virtio_gpu: GpuCommand::ResourceAssignUuid unimplemented");
            }
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
        virtio_gpu: &mut impl VirtioGpu,
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
        virtio_gpu: &mut impl VirtioGpu,
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
        virtio_gpu: &mut impl VirtioGpu,
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
            let virtio_gpu = match maybe_virtio_gpu {
                Some(virtio_gpu) => virtio_gpu,
                None => {
                    let gpu_backend = self.gpu_backend.take().ok_or_else(|| {
                        io::Error::new(
                            ErrorKind::Other,
                            "set_gpu_socket() not called, GpuBackend missing",
                        )
                    })?;

                    // We currently pass the CONTROL_QUEUE vring to RutabagaVirtioGpu, because we only
                    // expect to process fences for that queue.
                    let control_vring = &vrings[CONTROL_QUEUE as usize];

                    // VirtioGpu::new can be called once per process (otherwise it panics),
                    // so if somehow another thread accidentally wants to create another gpu here,
                    // it will panic anyway
                    let virtio_gpu =
                        RutabagaVirtioGpu::new(control_vring, self.renderer, gpu_backend);
                    event_poll_fd = virtio_gpu.get_event_poll_fd();

                    maybe_virtio_gpu.insert(virtio_gpu)
                }
            };

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

    use crate::protocol::{
        virtio_gpu_mem_entry,
        GpuResponse::{OkCapsetInfo, OkDisplayInfo, OkEdid, OkNoData},
        VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING, VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
        VIRTIO_GPU_CMD_RESOURCE_FLUSH, VIRTIO_GPU_CMD_SET_SCANOUT,
        VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D, VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D,
        VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D, VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM,
        VIRTIO_GPU_RESP_ERR_UNSPEC, VIRTIO_GPU_RESP_OK_NODATA,
    };
    use crate::virtio_gpu::MockVirtioGpu;
    use assert_matches::assert_matches;
    use mockall::predicate;
    use rusty_fork::rusty_fork_test;
    use std::{
        fs::File,
        io::{ErrorKind, Read},
        iter::zip,
        mem,
        os::{fd::FromRawFd, unix::net::UnixStream},
        sync::Arc,
        thread,
        time::Duration,
    };
    use vhost::vhost_user::gpu_message::{VhostUserGpuScanout, VhostUserGpuUpdate};
    use vhost_user_backend::{VhostUserDaemon, VringRwLock, VringT};
    use virtio_bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::{mock::MockSplitQueue, Descriptor, Queue, QueueT};
    use vm_memory::{
        ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryAtomic, GuestMemoryMmap,
    };

    const SOCKET_PATH: &str = "vgpu.socket";
    const MEM_SIZE: usize = 2 * 1024 * 1024; // 2MiB

    const CURSOR_QUEUE_ADDR: GuestAddress = GuestAddress(0x0);
    const CURSOR_QUEUE_DATA_ADDR: GuestAddress = GuestAddress(0x1_000);
    const CURSOR_QUEUE_SIZE: u16 = 16;
    const CONTROL_QUEUE_ADDR: GuestAddress = GuestAddress(0x2_000);
    const CONTROL_QUEUE_DATA_ADDR: GuestAddress = GuestAddress(0x10_000);
    const CONTROL_QUEUE_SIZE: u16 = 1024;

    fn init() -> (Arc<VhostUserGpuBackend>, GuestMemoryAtomic<GuestMemoryMmap>) {
        let backend = VhostUserGpuBackend::new(GpuConfig::new(
            SOCKET_PATH.into(),
            GpuMode::ModeVirglRenderer,
        ))
        .unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), MEM_SIZE)]).unwrap(),
        );

        backend.update_memory(mem.clone()).unwrap();
        (backend, mem)
    }

    /// Arguments to create a descriptor chain for testing
    struct TestingDescChainArgs<'a> {
        readable_desc_bufs: &'a [&'a [u8]],
        writable_desc_lengths: &'a [u32],
    }

    fn gpu_backend_pair() -> (UnixStream, GpuBackend) {
        let (frontend, backend) = UnixStream::pair().unwrap();
        let backend = GpuBackend::from_stream(backend);

        (frontend, backend)
    }

    fn event_fd_into_file(event_fd: EventFd) -> File {
        // SAFETY: We ensure that the `event_fd` is properly handled such that its file descriptor
        // is not closed after `File` takes ownership of it.
        unsafe {
            let event_fd_raw = event_fd.as_raw_fd();
            mem::forget(event_fd);
            File::from_raw_fd(event_fd_raw)
        }
    }

    #[test]
    fn test_process_gpu_command() {
        let (backend, mem) = init();
        let mut backend_inner = backend.inner.lock().unwrap();
        let hdr = virtio_gpu_ctrl_hdr::default();

        let mut test_cmd = |cmd: GpuCommand, setup: fn(&mut MockVirtioGpu)| {
            let mut mock_gpu = MockVirtioGpu::new();
            mock_gpu.expect_force_ctx_0().return_once(|| ());
            setup(&mut mock_gpu);
            backend_inner.process_gpu_command(&mut mock_gpu, &mem.memory(), hdr, cmd)
        };

        let cmd = GpuCommand::GetDisplayInfo;
        let result = test_cmd(cmd, |g| {
            g.expect_display_info()
                .return_once(|| Ok(OkDisplayInfo(vec![(1280, 720, true)])));
        });
        assert_matches!(result, Ok(OkDisplayInfo(_)));

        let cmd = GpuCommand::GetEdid(Default::default());
        let result = test_cmd(cmd, |g| {
            g.expect_get_edid().return_once(|_| {
                Ok(OkEdid {
                    blob: Box::new([0xff; 512]),
                })
            });
        });
        assert_matches!(result, Ok(OkEdid { .. }));

        let cmd = GpuCommand::ResourceCreate2d(Default::default());
        let result = test_cmd(cmd, |g| {
            g.expect_resource_create_3d()
                .return_once(|_, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::ResourceUnref(Default::default());
        let result = test_cmd(cmd, |g| {
            g.expect_unref_resource().return_once(|_| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::SetScanout(Default::default());
        let result = test_cmd(cmd, |g| {
            g.expect_set_scanout().return_once(|_, _, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::ResourceFlush(Default::default());
        let result = test_cmd(cmd, |g| {
            g.expect_flush_resource().return_once(|_, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::TransferToHost2d(Default::default());
        let result = test_cmd(cmd, |g| {
            g.expect_transfer_write()
                .return_once(|_, _, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::ResourceAttachBacking(Default::default(), Default::default());
        let result = test_cmd(cmd, |g| {
            g.expect_attach_backing()
                .return_once(|_, _, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::ResourceDetachBacking(Default::default());
        let result = test_cmd(cmd, |g| {
            g.expect_detach_backing().return_once(|_| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::GetCapsetInfo(Default::default());
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

        let cmd = GpuCommand::CtxCreate(Default::default());
        let result = test_cmd(cmd, |g| {
            g.expect_create_context()
                .return_once(|_, _, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::CtxDestroy(Default::default());
        let result = test_cmd(cmd, |g| {
            g.expect_destroy_context().return_once(|_| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::CtxAttachResource(Default::default());
        let result = test_cmd(cmd, |g| {
            g.expect_context_attach_resource()
                .return_once(|_, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::CtxDetachResource(Default::default());
        let result = test_cmd(cmd, |g| {
            g.expect_context_detach_resource()
                .return_once(|_, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::ResourceCreate3d(Default::default());
        let result = test_cmd(cmd, |g| {
            g.expect_resource_create_3d()
                .return_once(|_, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::TransferToHost3d(Default::default());
        let result = test_cmd(cmd, |g| {
            g.expect_transfer_write()
                .return_once(|_, _, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::TransferFromHost3d(Default::default());
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

        let cmd = GpuCommand::UpdateCursor(Default::default());
        let result = test_cmd(cmd, |g| {
            g.expect_update_cursor()
                .return_once(|_, _, _, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::MoveCursor(Default::default());
        let result = test_cmd(cmd, |g| {
            g.expect_move_cursor().return_once(|_, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));

        let cmd = GpuCommand::MoveCursor(Default::default());
        let result = test_cmd(cmd, |g| {
            g.expect_move_cursor().return_once(|_, _| Ok(OkNoData));
        });
        assert_matches!(result, Ok(OkNoData));
    }

    fn make_descriptors_into_a_chain(start_idx: u16, descriptors: &mut [Descriptor]) {
        let last_idx = start_idx + descriptors.len() as u16 - 1;
        for (idx, desc) in zip(start_idx.., descriptors.iter_mut()) {
            if idx == last_idx {
                desc.set_flags(desc.flags() & !VRING_DESC_F_NEXT as u16);
            } else {
                desc.set_flags(desc.flags() | VRING_DESC_F_NEXT as u16);
                desc.set_next(idx + 1);
            };
        }
    }

    // Creates a vring from the specified descriptor chains
    // For each created device-writable descriptor chain a Vec<(GuestAddress, usize)> is returned
    // representing the descriptors of that chain.
    fn create_vring<'a>(
        mem: &GuestMemoryAtomic<GuestMemoryMmap>,
        chains: &[TestingDescChainArgs],
        queue_addr_start: GuestAddress,
        data_addr_start: GuestAddress,
        queue_size: u16,
    ) -> (VringRwLock, Vec<Vec<GuestAddress>>, EventFd) {
        let mem_handle = mem.memory();
        mem.memory()
            .check_address(queue_addr_start)
            .expect("Invalid start adress");

        let mut output_bufs = Vec::new();
        let vq = MockSplitQueue::create(&*mem_handle, queue_addr_start, queue_size);
        // Address of the buffer associated with the descriptor
        let mut next_addr = data_addr_start.0;
        let mut chain_index_start = 0;
        let mut descriptors = Vec::new();

        for chain in chains {
            for buf in chain.readable_desc_bufs {
                mem.memory()
                    .check_address(GuestAddress(next_addr))
                    .expect("Readable descriptor's buffer address is not valid!");
                let desc = Descriptor::new(
                    next_addr,
                    buf.len()
                        .try_into()
                        .expect("Buffer too large to fit into descriptor"),
                    0,
                    0,
                );
                mem_handle.write(buf, desc.addr()).unwrap();
                descriptors.push(desc);
                next_addr += buf.len() as u64;
            }
            let mut writable_descriptor_adresses = Vec::new();
            for desc_len in chain.writable_desc_lengths.iter().copied() {
                mem.memory()
                    .check_address(GuestAddress(next_addr))
                    .expect("Writable descriptor's buffer address is not valid!");
                let desc = Descriptor::new(next_addr, desc_len, VRING_DESC_F_WRITE as u16, 0);
                writable_descriptor_adresses.push(desc.addr());
                descriptors.push(desc);
                next_addr += desc_len as u64;
            }
            output_bufs.push(writable_descriptor_adresses);
            make_descriptors_into_a_chain(
                chain_index_start as u16,
                &mut descriptors[chain_index_start..],
            );
            chain_index_start = descriptors.len();
        }

        assert!(descriptors.len() < queue_size as usize);
        if !descriptors.is_empty() {
            vq.build_multiple_desc_chains(&descriptors)
                .expect("Failed to build descriptor chain");
        }

        let queue: Queue = vq.create_queue().unwrap();
        let vring = VringRwLock::new(mem.clone(), queue_size).unwrap();
        let signal_used_queue_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let signal_used_queue_evt_clone = signal_used_queue_evt.try_clone().unwrap();
        vring
            .set_queue_info(queue.desc_table(), queue.avail_ring(), queue.used_ring())
            .unwrap();
        vring.set_call(Some(event_fd_into_file(signal_used_queue_evt_clone)));

        vring.set_enabled(true);
        vring.set_queue_ready(true);

        (vring, output_bufs, signal_used_queue_evt)
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
        let mut backend_inner = backend.inner.lock().unwrap();

        let hdr = virtio_gpu_ctrl_hdr {
            type_: VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
            ..Default::default()
        };

        let cmd = virtio_gpu_resource_create_2d {
            resource_id: 1,
            format: VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM,
            width: 1920,
            height: 1080,
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

        let mut mock_gpu = MockVirtioGpu::new();
        let seq = &mut mockall::Sequence::new();

        mock_gpu
            .expect_force_ctx_0()
            .return_const(())
            .once()
            .in_sequence(seq);

        mock_gpu
            .expect_resource_create_3d()
            .with(predicate::eq(1), predicate::always())
            .returning(|_, _| Ok(OkNoData))
            .once()
            .in_sequence(seq);

        mock_gpu
            .expect_force_ctx_0()
            .return_const(())
            .once()
            .in_sequence(seq);

        mock_gpu
            .expect_resource_create_3d()
            .with(predicate::eq(1), predicate::always())
            .returning(|_, _| Err(ErrUnspec))
            .once()
            .in_sequence(seq);

        assert_eq!(
            cursor_signal_used_queue_evt.read().unwrap_err().kind(),
            ErrorKind::WouldBlock
        );

        backend_inner
            .handle_event(0, &mut mock_gpu, &[control_vring.clone(), cursor_vring])
            .unwrap();

        let expected_hdr1 = virtio_gpu_ctrl_hdr {
            type_: VIRTIO_GPU_RESP_OK_NODATA,
            ..Default::default()
        };

        let expected_hdr2 = virtio_gpu_ctrl_hdr {
            type_: VIRTIO_GPU_RESP_ERR_UNSPEC,
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
        let (backend, mem) = init();
        backend.update_memory(mem.clone()).unwrap();
        let mut backend_inner = backend.inner.lock().unwrap();

        const FENCE_ID: u64 = 123;

        let hdr = virtio_gpu_ctrl_hdr {
            type_: VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D,
            flags: VIRTIO_GPU_FLAG_FENCE,
            fence_id: FENCE_ID,
            ctx_id: 0,
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

        let mut mock_gpu = MockVirtioGpu::new();
        let seq = &mut mockall::Sequence::new();

        mock_gpu
            .expect_force_ctx_0()
            .return_const(())
            .once()
            .in_sequence(seq);

        mock_gpu
            .expect_transfer_write()
            .returning(|_, _, _| Ok(OkNoData))
            .once()
            .in_sequence(seq);

        mock_gpu
            .expect_create_fence()
            .withf(|fence| fence.fence_id == FENCE_ID)
            .returning(|_| Ok(OkNoData))
            .once()
            .in_sequence(seq);

        mock_gpu
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

        backend_inner
            .handle_event(0, &mut mock_gpu, &[control_vring.clone(), cursor_vring])
            .unwrap();

        let expected_hdr = virtio_gpu_ctrl_hdr {
            type_: VIRTIO_GPU_RESP_OK_NODATA,
            flags: VIRTIO_GPU_FLAG_FENCE,
            fence_id: FENCE_ID,
            ctx_id: 0,
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
        let (backend, mem) = init();
        backend.update_memory(mem.clone()).unwrap();
        let mut backend_inner = backend.inner.lock().unwrap();

        const FENCE_ID: u64 = 123;
        const CTX_ID: u32 = 1;
        const RING_IDX: u8 = 2;

        let hdr = virtio_gpu_ctrl_hdr {
            type_: VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D,
            flags: VIRTIO_GPU_FLAG_FENCE | VIRTIO_GPU_FLAG_INFO_RING_IDX,
            fence_id: FENCE_ID,
            ctx_id: CTX_ID,
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

        let mut mock_gpu = MockVirtioGpu::new();
        let seq = &mut mockall::Sequence::new();

        mock_gpu
            .expect_force_ctx_0()
            .return_const(())
            .once()
            .in_sequence(seq);

        mock_gpu
            .expect_transfer_read()
            .returning(|_, _, _, _| Ok(OkNoData))
            .once()
            .in_sequence(seq);

        mock_gpu
            .expect_create_fence()
            .withf(|fence| fence.fence_id == FENCE_ID)
            .returning(|_| Ok(OkNoData))
            .once()
            .in_sequence(seq);

        mock_gpu
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

        backend_inner
            .handle_event(0, &mut mock_gpu, &[control_vring.clone(), cursor_vring])
            .unwrap();

        assert_eq!(
            control_signal_used_queue_evt.read().unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
    }

    rusty_fork_test! {
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
        backend.set_gpu_socket(gpu_backend_pair().1);

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
    }

    mod test_image {
        use super::*;
        const GREEN_PIXEL: u32 = 0x00FF00FF;
        const RED_PIXEL: u32 = 0xFF0000FF;
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

        pub fn assert(data: &[u8], width: u32, height: u32) {
            assert_eq!(data.len(), (width * height) as usize * BYTES_PER_PIXEL);
            for (i, pixel) in data.chunks(BYTES_PER_PIXEL).enumerate() {
                let expected_pixel = if i % 2 == 0 { RED_PIXEL } else { GREEN_PIXEL };
                assert_eq!(
                    pixel,
                    expected_pixel.to_be_bytes(),
                    "Wrong pixel at index {i}"
                );
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
                addr,
                length: chunk_size,
                padding: Default::default(),
            });
            addr += chunk_size as u64;
            remaining -= chunk_size;
        }

        if remaining != 0 {
            entries.push(virtio_gpu_mem_entry {
                addr,
                length: remaining,
                padding: Default::default(),
            })
        }

        entries
    }

    fn new_hdr(type_: u32) -> virtio_gpu_ctrl_hdr {
        virtio_gpu_ctrl_hdr {
            type_,
            ..Default::default()
        }
    }

    rusty_fork_test! {
    /// This test uses multiple gpu commands, it crates a resource, writes a test image into it and
    /// then present the display output.
    #[test]
    fn test_display_output() {
        let (backend, mem) = init();
        let (mut gpu_frontend, gpu_backend) = gpu_backend_pair();
        gpu_frontend
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        gpu_frontend
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();

        backend.set_gpu_socket(gpu_backend);

        // Unfortunately there is no way to crate a VringEpollHandler directly (the ::new is not public)
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

        const IMAGE_ADDR: GuestAddress = GuestAddress(0x30_000);
        const IMAGE_WIDTH: u32 = 640;
        const IMAGE_HEIGHT: u32 = 480;
        const RESP_SIZE: u32 = mem::size_of::<virtio_gpu_ctrl_hdr>() as u32;

        let image_rect = virtio_gpu_rect {
            x: 0,
            y: 0,
            width: IMAGE_WIDTH,
            height: IMAGE_HEIGHT,
        };

        // Construct a command to create a resource
        let hdr = new_hdr(VIRTIO_GPU_CMD_RESOURCE_CREATE_2D);
        let cmd = virtio_gpu_resource_create_2d {
            resource_id: 1,
            format: VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM, // RGBA8888
            width: IMAGE_WIDTH,
            height: IMAGE_HEIGHT,
        };
        let create_resource_cmd = TestingDescChainArgs {
            readable_desc_bufs: &[hdr.as_slice(), cmd.as_slice()],
            writable_desc_lengths: &[RESP_SIZE],
        };

        // Construct a command to attach backing memory location(s) to the resource
        let hdr = new_hdr(VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING);
        let mem_entries = split_into_mem_entries(IMAGE_ADDR, IMAGE_WIDTH * IMAGE_HEIGHT * 4, 4096);
        let cmd = virtio_gpu_resource_attach_backing {
            resource_id: 1,
            nr_entries: mem_entries.len() as u32,
        };
        let mut readable_desc_bufs = vec![hdr.as_slice(), cmd.as_slice()];
        readable_desc_bufs.extend(mem_entries.iter().map(|entry| entry.as_slice()));
        let attach_backing_cmd = TestingDescChainArgs {
            readable_desc_bufs: &readable_desc_bufs,
            writable_desc_lengths: &[RESP_SIZE],
        };

        // Construct a command to transfer the resource data from the attached memory to gpu
        let hdr = new_hdr(VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D);
        let cmd = virtio_gpu_transfer_to_host_2d {
            r: image_rect,
            offset: 0,
            resource_id: 1,
            padding: Default::default(),
        };
        let transfer_to_host_cmd = TestingDescChainArgs {
            readable_desc_bufs: &[hdr.as_slice(), cmd.as_slice()],
            writable_desc_lengths: &[RESP_SIZE],
        };

        // Construct a command to set the scanout (display) output
        let hdr = new_hdr(VIRTIO_GPU_CMD_SET_SCANOUT);
        let cmd = virtio_gpu_set_scanout {
            r: image_rect,
            resource_id: 1,
            scanout_id: 1,
        };
        let set_scanout_cmd = TestingDescChainArgs {
            readable_desc_bufs: &[hdr.as_slice(), cmd.as_slice()],
            writable_desc_lengths: &[RESP_SIZE],
        };

        // Construct a command to flush the resource
        let hdr = new_hdr(VIRTIO_GPU_CMD_RESOURCE_FLUSH);
        let cmd = virtio_gpu_resource_flush {
            r: image_rect,
            resource_id: 1,
            padding: Default::default(),
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
            set_scanout_cmd,
            flush_resource_cmd,
        ];
        let (control_vring, _, _) = create_control_vring(&mem, &commands);

        // Create an empty cursor queue with no commands
        let (cursor_vring, _, _) = create_cursor_vring(&mem, &[]);

        // Write the test image in guest memory
        test_image::write(&mem.memory(), IMAGE_ADDR, IMAGE_WIDTH, IMAGE_HEIGHT);

        const EXPECTED_SCANOUT_REQUEST: VhostUserGpuScanout = VhostUserGpuScanout {
            scanout_id: 1,
            width: IMAGE_WIDTH,
            height: IMAGE_HEIGHT,
        };

        const EXPECTED_UPDATE_REQUEST: VhostUserGpuUpdate = VhostUserGpuUpdate {
            scanout_id: 1,
            x: 0,
            y: 0,
            width: IMAGE_WIDTH,
            height: IMAGE_HEIGHT,
        };

        // This simulates the frontend vmm. Here we check the issued frontend requests and if the
        // output matches the test image.
        let frontend_thread = thread::spawn(move || {
            let mut scanout_request_hdr = [0; 12];
            let mut scanout_request = VhostUserGpuScanout::default();
            let mut update_request_hdr = [0; 12];
            let mut update_request = VhostUserGpuUpdate::default();
            let mut result_img = vec![0xdd; (IMAGE_WIDTH * IMAGE_HEIGHT * 4) as usize];

            gpu_frontend.read_exact(&mut scanout_request_hdr).unwrap();
            gpu_frontend
                .read_exact(scanout_request.as_mut_slice())
                .unwrap();
            gpu_frontend.read_exact(&mut update_request_hdr).unwrap();
            gpu_frontend
                .read_exact(update_request.as_mut_slice())
                .unwrap();
            gpu_frontend.read_exact(&mut result_img).unwrap();

            assert_eq!(scanout_request, EXPECTED_SCANOUT_REQUEST);
            assert_eq!(update_request, EXPECTED_UPDATE_REQUEST);
            test_image::assert(&result_img, IMAGE_WIDTH, IMAGE_HEIGHT);
        });

        backend
            .handle_event(0, EventSet::IN, &[control_vring, cursor_vring], 0)
            .unwrap();

        frontend_thread.join().unwrap();
    }
    }
}
