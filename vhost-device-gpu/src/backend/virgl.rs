// Virglrenderer backend device
// Copyright 2019 The ChromiumOS Authors
// Copyright 2025 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    collections::BTreeMap,
    io::IoSliceMut,
    os::fd::{AsFd, FromRawFd, IntoRawFd, RawFd},
    sync::{Arc, Mutex},
};

use libc::c_void;
use log::{debug, error, trace, warn};
use rutabaga_gfx::RutabagaFence;
use vhost::vhost_user::{
    gpu_message::{
        VhostUserGpuCursorPos, VhostUserGpuDMABUFScanout, VhostUserGpuDMABUFScanout2,
        VhostUserGpuEdidRequest, VhostUserGpuUpdate,
    },
    GpuBackend,
};
use vhost_user_backend::{VringRwLock, VringT};
use virglrenderer::{
    FenceHandler, Iovec, VirglContext, VirglRenderer, VirglRendererFlags, VirglResource,
    VIRGL_HANDLE_TYPE_MEM_DMABUF,
};
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap, VolatileSlice};
use vmm_sys_util::eventfd::EventFd;

use crate::{
    backend::{
        common,
        common::{common_set_scanout_disable, AssociatedScanouts, CursorConfig, VirtioGpuScanout},
    },
    gpu_types::{FenceState, ResourceCreate3d, Transfer3DDesc, VirtioGpuRing},
    protocol::{
        virtio_gpu_rect, GpuResponse,
        GpuResponse::{
            ErrInvalidContextId, ErrInvalidParameter, ErrInvalidResourceId, ErrInvalidScanoutId,
            ErrUnspec, OkCapset, OkCapsetInfo, OkNoData,
        },
        VirtioGpuResult, VIRTIO_GPU_MAX_SCANOUTS,
    },
    renderer::Renderer,
    GpuConfig,
};

const CAPSET_ID_VIRGL: u32 = 1;
const CAPSET_ID_VIRGL2: u32 = 2;
const CAPSET_ID_VENUS: u32 = 4;

#[derive(Clone)]
pub struct GpuResource {
    pub virgl_resource: VirglResource,
    // Stores information about which scanouts are associated with the given
    // resource. Resource could be used for multiple scanouts.
    pub scanouts: AssociatedScanouts,
    pub backing_iovecs: Arc<Mutex<Option<Vec<Iovec>>>>,
}

fn sglist_to_iovecs(
    vecs: &[(GuestAddress, usize)],
    mem: &GuestMemoryMmap,
) -> Result<Vec<Iovec>, ()> {
    if vecs
        .iter()
        .any(|&(addr, len)| mem.get_slice(addr, len).is_err())
    {
        return Err(());
    }

    let mut virgl_iovecs: Vec<Iovec> = Vec::new();
    for &(addr, len) in vecs {
        let slice = mem.get_slice(addr, len).unwrap();
        virgl_iovecs.push(Iovec {
            base: slice.ptr_guard_mut().as_ptr().cast::<c_void>(),
            len,
        });
    }
    Ok(virgl_iovecs)
}

impl From<virglrenderer::VirglError> for GpuResponse {
    fn from(_: virglrenderer::VirglError) -> Self {
        ErrUnspec
    }
}
pub struct VirglFenceHandler {
    queue_ctl: VringRwLock,
    fence_state: Arc<Mutex<FenceState>>,
}

impl VirglFenceHandler {
    pub const fn new(queue_ctl: VringRwLock, fence_state: Arc<Mutex<FenceState>>) -> Self {
        Self {
            queue_ctl,
            fence_state,
        }
    }
}

impl FenceHandler for VirglFenceHandler {
    fn call(&self, fence_id: u64, ctx_id: u32, ring_idx: u8) {
        let mut fence_state = self.fence_state.lock().unwrap();
        let mut i = 0;

        let ring = match ring_idx {
            0 => VirtioGpuRing::Global,
            _ => VirtioGpuRing::ContextSpecific { ctx_id, ring_idx },
        };

        while i < fence_state.descs.len() {
            if fence_state.descs[i].ring == ring && fence_state.descs[i].fence_id <= fence_id {
                let completed_desc = fence_state.descs.remove(i);

                self.queue_ctl
                    .add_used(completed_desc.desc_index, completed_desc.len)
                    .unwrap();

                self.queue_ctl
                    .signal_used_queue()
                    .map_err(|e| log::error!("Failed to signal queue: {e:?}"))
                    .unwrap();
            } else {
                i += 1;
            }
        }

        fence_state.completed_fences.insert(ring, fence_id);
    }
}

pub struct VirglRendererAdapter {
    renderer: VirglRenderer,
    gpu_backend: GpuBackend,
    fence_state: Arc<Mutex<FenceState>>,
    resources: BTreeMap<u32, GpuResource>,
    contexts: BTreeMap<u32, VirglContext>,
    scanouts: [Option<VirtioGpuScanout>; VIRTIO_GPU_MAX_SCANOUTS as usize],
}

impl VirglRendererAdapter {
    pub fn new(queue_ctl: &VringRwLock, config: &GpuConfig, gpu_backend: GpuBackend) -> Self {
        let virglrenderer_flags = VirglRendererFlags::new()
            .use_virgl(true)
            .use_venus(true)
            .use_egl(config.flags().use_egl)
            .use_gles(config.flags().use_gles)
            .use_glx(config.flags().use_glx)
            .use_surfaceless(config.flags().use_surfaceless)
            .use_external_blob(true)
            .use_async_fence_cb(true)
            .use_thread_sync(true);
        let fence_state = Arc::new(Mutex::new(FenceState::default()));
        let fence_handler = Box::new(VirglFenceHandler::new(
            queue_ctl.clone(),
            fence_state.clone(),
        ));

        let renderer = VirglRenderer::init(virglrenderer_flags, fence_handler, None)
            .expect("Failed to initialize virglrenderer");
        Self {
            renderer,
            gpu_backend,
            fence_state,
            resources: BTreeMap::new(),
            contexts: BTreeMap::new(),
            scanouts: Default::default(),
        }
    }
}

impl Renderer for VirglRendererAdapter {
    fn resource_create_3d(&mut self, resource_id: u32, args: ResourceCreate3d) -> VirtioGpuResult {
        let virgl_args: virglrenderer::ResourceCreate3D = args.into();

        let virgl_resource = self
            .renderer
            .create_3d(resource_id, virgl_args)
            .map_err(|_| ErrUnspec)?;
        let local_resource = GpuResource {
            virgl_resource,
            scanouts: AssociatedScanouts::default(),
            backing_iovecs: Arc::new(Mutex::new(None)),
        };
        self.resources.insert(resource_id, local_resource);
        Ok(OkNoData)
    }

    fn unref_resource(&mut self, resource_id: u32) -> VirtioGpuResult {
        let resource = self.resources.remove(&resource_id);
        match resource {
            None => return Err(ErrInvalidResourceId),
            // The spec doesn't say anything about this situation and this doesn't actually seem
            // to happen in practise but let's be careful and refuse to disable the resource.
            // This keeps the internal state of the gpu device and the fronted consistent.
            Some(resource) if resource.scanouts.has_any_enabled() => {
                warn!(
                    "The driver requested unref_resource, but resource {resource_id} has \
                     associated scanouts, refusing to delete the resource."
                );
                return Err(ErrUnspec);
            }
            _ => (),
        }
        self.renderer.unref_resource(resource_id);
        Ok(OkNoData)
    }

    fn transfer_write(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3DDesc,
    ) -> VirtioGpuResult {
        trace!("transfer_write ctx_id {ctx_id}, resource_id {resource_id}, {transfer:?}");

        self.renderer
            .transfer_write(resource_id, ctx_id, transfer.into(), None)?;
        Ok(OkNoData)
    }
    fn transfer_write_2d(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3DDesc,
    ) -> VirtioGpuResult {
        trace!("transfer_write ctx_id {ctx_id}, resource_id {resource_id}, {transfer:?}");
        self.renderer
            .transfer_write(resource_id, ctx_id, transfer.into(), None)?;
        Ok(OkNoData)
    }

    fn transfer_read(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3DDesc,
        buf: Option<VolatileSlice>,
    ) -> VirtioGpuResult {
        let buf = buf.map(|vs| {
            IoSliceMut::new(
                // SAFETY: trivially safe
                unsafe { std::slice::from_raw_parts_mut(vs.ptr_guard_mut().as_ptr(), vs.len()) },
            )
        });

        self.renderer
            .transfer_read(resource_id, ctx_id, transfer.into(), buf)?;
        Ok(OkNoData)
    }

    fn attach_backing(
        &mut self,
        resource_id: u32,
        mem: &GuestMemoryMmap,
        vecs: Vec<(GuestAddress, usize)>,
    ) -> VirtioGpuResult {
        let mut iovs: Vec<Iovec> = sglist_to_iovecs(&vecs, mem).map_err(|()| ErrUnspec)?;

        // Tell virgl to use our iovec array (pointer must stay valid afterwards)
        self.renderer.attach_backing(resource_id, &mut iovs)?;

        // Keep the Vec alive so the buffer’s pointer stays valid
        let res = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;
        res.backing_iovecs.lock().unwrap().replace(iovs);

        Ok(OkNoData)
    }

    fn detach_backing(&mut self, resource_id: u32) -> VirtioGpuResult {
        self.renderer.detach_backing(resource_id);
        if let Some(r) = self.resources.get_mut(&resource_id) {
            r.backing_iovecs.lock().unwrap().take(); // drop our boxed iovecs
        }
        Ok(OkNoData)
    }

    fn update_cursor(
        &mut self,
        resource_id: u32,
        cursor_pos: VhostUserGpuCursorPos,
        hot_x: u32,
        hot_y: u32,
    ) -> VirtioGpuResult {
        let config = CursorConfig {
            width: 64,
            height: 64,
        };

        let cursor_resource = self
            .resources
            .get(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        if cursor_resource.virgl_resource.width != config.width
            || cursor_resource.virgl_resource.height != config.height
        {
            error!("Cursor resource has invalid dimensions");
            return Err(ErrInvalidParameter);
        }

        let data = common::common_read_cursor_resource(self, resource_id, config)?;

        common::common_update_cursor(&self.gpu_backend, cursor_pos, hot_x, hot_y, &data, config)
    }

    fn move_cursor(&mut self, resource_id: u32, cursor: VhostUserGpuCursorPos) -> VirtioGpuResult {
        common::common_move_cursor(&self.gpu_backend, resource_id, cursor)
    }

    fn resource_assign_uuid(&self, _resource_id: u32) -> VirtioGpuResult {
        error!("Not implemented: resource_assign_uuid");
        Err(ErrUnspec)
    }

    fn get_capset_info(&self, index: u32) -> VirtioGpuResult {
        debug!("the capset index is {index}");
        let capset_id = match index {
            0 => CAPSET_ID_VIRGL,
            1 => CAPSET_ID_VIRGL2,
            3 => CAPSET_ID_VENUS,
            _ => return Err(ErrInvalidParameter),
        };
        let (version, size) = self.renderer.get_capset_info(index);
        Ok(OkCapsetInfo {
            capset_id,
            version,
            size,
        })
    }

    fn get_capset(&self, capset_id: u32, version: u32) -> VirtioGpuResult {
        let capset = self.renderer.get_capset(capset_id, version);
        Ok(OkCapset(capset))
    }

    fn create_context(
        &mut self,
        ctx_id: u32,
        context_init: u32,
        context_name: Option<&str>,
    ) -> VirtioGpuResult {
        if self.contexts.contains_key(&ctx_id) {
            return Err(ErrUnspec);
        }

        // Create the VirglContext using virglrenderer
        let ctx = virglrenderer::VirglContext::create_context(ctx_id, context_init, context_name)
            .map_err(|_| ErrInvalidContextId)?;

        // Insert the newly created context into our local BTreeMap.
        self.contexts.insert(ctx_id, ctx);
        Ok(OkNoData)
    }

    fn destroy_context(&mut self, ctx_id: u32) -> VirtioGpuResult {
        self.contexts.remove(&ctx_id).ok_or(ErrInvalidContextId)?;
        Ok(OkNoData)
    }

    fn context_attach_resource(&mut self, ctx_id: u32, resource_id: u32) -> VirtioGpuResult {
        let ctx = self.contexts.get_mut(&ctx_id).ok_or(ErrInvalidContextId)?;
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;
        ctx.attach(&mut resource.virgl_resource);
        Ok(OkNoData)
    }

    fn context_detach_resource(&mut self, ctx_id: u32, resource_id: u32) -> VirtioGpuResult {
        let ctx = self.contexts.get_mut(&ctx_id).ok_or(ErrInvalidContextId)?;
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;
        ctx.detach(&resource.virgl_resource);
        Ok(OkNoData)
    }

    fn submit_command(
        &mut self,
        ctx_id: u32,
        commands: &mut [u8],
        fence_ids: &[u64],
    ) -> VirtioGpuResult {
        let ctx = self.contexts.get_mut(&ctx_id).ok_or(ErrInvalidContextId)?;

        ctx.submit_cmd(commands, fence_ids)
            .map(|()| OkNoData)
            .map_err(|_| ErrUnspec)
    }

    fn create_fence(&mut self, fence: RutabagaFence) -> VirtioGpuResult {
        // Convert the fence ID to u32
        let fence_id_u32 = u32::try_from(fence.fence_id).map_err(|_| GpuResponse::ErrUnspec)?;

        self.renderer
            .create_fence(fence_id_u32, fence.ctx_id)
            .map_err(|_| ErrUnspec)?;
        Ok(OkNoData)
    }

    fn process_fence(
        &mut self,
        ring: VirtioGpuRing,
        fence_id: u64,
        desc_index: u16,
        len: u32,
    ) -> bool {
        common::common_process_fence(&self.fence_state, ring, fence_id, desc_index, len)
    }

    fn get_event_poll_fd(&self) -> Option<EventFd> {
        // SAFETY: The fd is guaranteed to be a valid owned descriptor.
        self.renderer
            .poll_descriptor()
            .map(|fd| unsafe { EventFd::from_raw_fd(fd.into_raw_fd()) })
    }

    fn event_poll(&self) {
        self.renderer.event_poll();
    }

    fn force_ctx_0(&self) {
        self.renderer.force_ctx_0();
    }

    fn display_info(&self) -> VirtioGpuResult {
        common::common_display_info(&self.gpu_backend)
    }
    fn get_edid(&self, edid_req: VhostUserGpuEdidRequest) -> VirtioGpuResult {
        common::common_get_edid(&self.gpu_backend, edid_req)
    }
    fn set_scanout(
        &mut self,
        scanout_id: u32,
        resource_id: u32,
        rect: virtio_gpu_rect,
    ) -> VirtioGpuResult {
        let scanout_idx = scanout_id as usize;
        // Basic Validation of scanout_id
        if scanout_idx >= VIRTIO_GPU_MAX_SCANOUTS as usize {
            return Err(ErrInvalidScanoutId);
        }

        // Handle existing scanout to disable it if necessary (like QEMU)
        let current_scanout_resource_id =
            self.scanouts[scanout_idx].as_ref().map(|s| s.resource_id);
        if let Some(old_resource_id) = current_scanout_resource_id {
            if old_resource_id != resource_id {
                // Only disable if resource_id changes
                if let Some(old_resource) = self.resources.get_mut(&old_resource_id) {
                    old_resource.scanouts.disable(scanout_id);
                }
            }
        }

        // Handle Resource ID 0 (Disable Scanout)
        if resource_id == 0 {
            common_set_scanout_disable(&mut self.scanouts, scanout_idx);

            // Send VHOST_USER_GPU_DMABUF_SCANOUT message with FD = -1
            self.gpu_backend
                .set_dmabuf_scanout(
                    &VhostUserGpuDMABUFScanout {
                        scanout_id,
                        x: 0,
                        y: 0,
                        width: 0,
                        height: 0,
                        fd_width: 0,
                        fd_height: 0,
                        fd_stride: 0,
                        fd_flags: 0,
                        fd_drm_fourcc: 0,
                    },
                    None::<&RawFd>, // Send None for the FD, which translates to -1 in the backend
                )
                .map_err(|e| {
                    error!("Failed to send DMABUF scanout disable message: {e:?}");
                    ErrUnspec
                })?;
            return Ok(OkNoData);
        }

        // Handling non-zero resource_id (Enable/Update Scanout)
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        // Extract the DMABUF information (handle and info_3d)
        let handle = resource.virgl_resource.handle.as_ref().ok_or_else(|| {
            error!("resource {resource_id} has no handle");
            ErrUnspec
        })?;

        if handle.handle_type != VIRGL_HANDLE_TYPE_MEM_DMABUF {
            error!(
                "resource {} handle is not a DMABUF (got type = {})",
                resource_id, handle.handle_type
            );
            return Err(ErrUnspec);
        }

        // Borrow the 3D info directly; no DmabufTextureInfo wrapper.
        let info_3d = resource.virgl_resource.info_3d.as_ref().ok_or_else(|| {
            error!("resource {resource_id} has handle but no info_3d");
            ErrUnspec
        })?;

        // Clone the fd we’ll pass to the backend.
        let fd = handle.os_handle.try_clone().map_err(|e| {
            error!("Failed to clone DMABUF FD for resource {resource_id}: {e:?}");
            ErrUnspec
        })?;

        debug!(
            "Using stored DMABUF texture info for resource {}: width={}, height={}, strides={}, fourcc={}, modifier={}",
            resource_id, info_3d.width, info_3d.height, info_3d.strides[0], info_3d.drm_fourcc, info_3d.modifier
        );

        // Construct VhostUserGpuDMABUFScanout Message
        let dmabuf_scanout_payload = VhostUserGpuDMABUFScanout {
            scanout_id,
            x: rect.x.into(),
            y: rect.y.into(),
            width: rect.width.into(),
            height: rect.height.into(),
            fd_width: info_3d.width,
            fd_height: info_3d.height,
            fd_stride: info_3d.strides[0],
            fd_flags: 0,
            fd_drm_fourcc: info_3d.drm_fourcc,
        };

        // Determine which message type to send based on modifier support
        let frontend_supports_dmabuf2 = info_3d.modifier != 0;

        if frontend_supports_dmabuf2 {
            let dmabuf_scanout2_msg = VhostUserGpuDMABUFScanout2 {
                dmabuf_scanout: dmabuf_scanout_payload,
                modifier: info_3d.modifier,
            };
            self.gpu_backend
                .set_dmabuf_scanout2(&dmabuf_scanout2_msg, Some(&fd.as_fd()))
                .map_err(|e| {
                    error!(
                        "Failed to send VHOST_USER_GPU_DMABUF_SCANOUT2 for resource {resource_id}: {e:?}"
                    );
                    ErrUnspec
                })?;
        } else {
            self.gpu_backend
                .set_dmabuf_scanout(&dmabuf_scanout_payload, Some(&fd.as_fd()))
                .map_err(|e| {
                    error!(
                        "Failed to send VHOST_USER_GPU_DMABUF_SCANOUT for resource {resource_id}: {e:?}"
                    );
                    ErrUnspec
                })?;
        }

        debug!(
            "Sent DMABUF scanout for resource {} using fd {:?}",
            resource_id,
            fd.as_fd()
        );

        // Update internal state to associate resource with scanout
        resource.scanouts.enable(scanout_id);
        self.scanouts[scanout_idx] = Some(VirtioGpuScanout { resource_id });

        Ok(OkNoData)
    }

    fn flush_resource(&mut self, resource_id: u32, _rect: virtio_gpu_rect) -> VirtioGpuResult {
        if resource_id == 0 {
            return Ok(OkNoData);
        }

        let resource = self
            .resources
            .get(&resource_id)
            .ok_or(ErrInvalidResourceId)?
            .clone();

        for scanout_id in resource.scanouts.iter_enabled() {
            // For VirglRenderer, use update_dmabuf_scanout (no image copy)
            self.gpu_backend
                .update_dmabuf_scanout(&VhostUserGpuUpdate {
                    scanout_id,
                    x: 0,
                    y: 0,
                    width: resource.virgl_resource.width,
                    height: resource.virgl_resource.height,
                })
                .map_err(|e| {
                    error!("Failed to update_dmabuf_scanout: {e:?}");
                    ErrUnspec
                })?;
        }
        Ok(OkNoData)
    }

    fn resource_create_blob(
        &mut self,
        _ctx_id: u32,
        _resource_id: u32,
        _blob_id: u64,
        _size: u64,
        _blob_mem: u32,
        _blob_flags: u32,
    ) -> VirtioGpuResult {
        error!("Not implemented: resource_create_blob");
        Err(ErrUnspec)
    }

    fn resource_map_blob(&mut self, _resource_id: u32, _offset: u64) -> VirtioGpuResult {
        error!("Not implemented: resource_map_blob");
        Err(ErrUnspec)
    }

    fn resource_unmap_blob(&mut self, _resource_id: u32) -> VirtioGpuResult {
        error!("Not implemented: resource_unmap_blob");
        Err(ErrUnspec)
    }
}

#[cfg(test)]
mod virgl_cov_tests {
    use std::{
        os::unix::net::UnixStream,
        sync::{Arc, Mutex},
    };

    use assert_matches::assert_matches;
    use rusty_fork::rusty_fork_test;
    use rutabaga_gfx::{RUTABAGA_PIPE_BIND_RENDER_TARGET, RUTABAGA_PIPE_TEXTURE_2D};
    use vm_memory::{Bytes, GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    use super::*;
    use crate::{
        gpu_types::{FenceDescriptor, FenceState, ResourceCreate3d, Transfer3DDesc, VirtioGpuRing},
        protocol::{virtio_gpu_rect, GpuResponse, VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM},
        renderer::Renderer,
        testutils::{
            create_vring, test_capset_operations, test_fence_operations, test_move_cursor,
            TestingDescChainArgs,
        },
        GpuCapset, GpuConfig, GpuFlags, GpuMode,
    };

    fn fence_desc(r: VirtioGpuRing, id: u64, idx: u16, len: u32) -> FenceDescriptor {
        FenceDescriptor {
            ring: r,
            fence_id: id,
            desc_index: idx,
            len,
        }
    }

    fn dummy_gpu_backend() -> GpuBackend {
        let (_, backend) = UnixStream::pair().unwrap();
        GpuBackend::from_stream(backend)
    }

    #[test]
    fn sglist_to_iovecs_err_on_invalid_slice() {
        // Single region: 0x1000..0x2000 (4 KiB)
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0x1000), 0x1000)]).unwrap();

        // Segment starts outside of mapped memory -> expect Err(()).
        let bad = vec![(GuestAddress(0x3000), 16usize)];
        assert!(sglist_to_iovecs(&bad, &mem).is_err());
    }

    rusty_fork::rusty_fork_test! {
        #[test]
        fn virgl_end_to_end_once() {
            // Fence handler coverage (no virgl init needed)
            let mem_a = GuestMemoryAtomic::new(
                GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20_000)]).unwrap()
            );
            let (vr_a, _outs_a, call_a) =
                create_vring(&mem_a, &[] as &[TestingDescChainArgs], GuestAddress(0x3000), GuestAddress(0x5000), 64);

            let fs_a = Arc::new(Mutex::new(FenceState {
                descs: vec![
                    fence_desc(VirtioGpuRing::Global, 5, 3, 64),
                    fence_desc(VirtioGpuRing::Global, 9, 4, 64),
                ],
                completed_fences: BTreeMap::default(),
            }));

            let handler_a = VirglFenceHandler {
                queue_ctl: vr_a,
                fence_state: fs_a.clone(),
            };

            let _ = call_a.read(); // drain stale
            handler_a.call(/*fence_id*/ 7, /*ctx_id*/ 0, /*ring_idx*/ 0);

            {
                let st = fs_a.lock().unwrap();
                assert_eq!(st.descs.len(), 1);
                assert_eq!(st.descs[0].fence_id, 9);
                assert_eq!(st.completed_fences.get(&VirtioGpuRing::Global), Some(&7u64));
                drop(st);
            }
            assert_eq!(call_a.read().unwrap(), 1);

            // Context ring path: no match → completed_fences updated, no notify
            let mem_b = GuestMemoryAtomic::new(
                GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20_000)]).unwrap()
            );
            let (vr_b, _outs_b, call_b) =
                create_vring(&mem_b, &[] as &[TestingDescChainArgs], GuestAddress(0x6000), GuestAddress(0x8000), 32);

            let ring_b = VirtioGpuRing::ContextSpecific { ctx_id: 42, ring_idx: 3 };
            let fs_b = Arc::new(Mutex::new(FenceState {
                descs: vec![fence_desc(VirtioGpuRing::Global, 7, 1, 1)],
                completed_fences: BTreeMap::default(),
            }));

            let handler_b = VirglFenceHandler {
                queue_ctl: vr_b,
                fence_state: fs_b.clone(),
            };
            handler_b.call(/*fence_id*/ 6, /*ctx_id*/ 42, /*ring_idx*/ 3);

            {
                let st = fs_b.lock().unwrap();
                assert_eq!(st.descs.len(), 1);
                assert_eq!(st.completed_fences.get(&ring_b), Some(&6u64));
                drop(st);
            }
            assert!(call_b.read().is_err(), "no signal when no match");

            // Initialize virgl ONCE in this forked process; exercise adapter paths
            let cfg = GpuConfig::new(
                GpuMode::VirglRenderer,
                Some(GpuCapset::VIRGL | GpuCapset::VIRGL2),
                GpuFlags::default(),
            ).expect("GpuConfig");

            let mem = GuestMemoryAtomic::new(
                GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20_000)]).unwrap()
            );
            let (vring, _outs, _call_evt) =
                create_vring(&mem, &[] as &[TestingDescChainArgs], GuestAddress(0x2000), GuestAddress(0x4000), 64);

            let backend = dummy_gpu_backend();
            let mut gpu = VirglRendererAdapter::new(&vring, &cfg, backend);

            gpu.event_poll();
            let edid_req = VhostUserGpuEdidRequest {
                scanout_id: 0,
            };
            gpu.get_edid(edid_req).unwrap_err();
            assert!(gpu.unref_resource(99_999).is_err(), "unref on missing must error");

            // Resource creation + attach backing
            let res_id = 1;
            let req = ResourceCreate3d {
                target: RUTABAGA_PIPE_TEXTURE_2D,
                format: VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM,
                bind: RUTABAGA_PIPE_BIND_RENDER_TARGET,
                width: 1, height: 1, depth: 1,
                array_size: 1, last_level: 0, nr_samples: 0, flags: 0,
            };
            gpu.resource_create_3d(res_id, req).unwrap();

            let gm_back = GuestMemoryMmap::from_ranges(&[(GuestAddress(0xA0000), 0x1000)]).unwrap();
            let pattern = [0xAA, 0xBB, 0xCC, 0xDD];
            gm_back.write(&pattern, GuestAddress(0xA0000)).unwrap();

            gpu.attach_backing(res_id, &gm_back, vec![(GuestAddress(0xA0000), 4usize)]).unwrap();

            // move_cursor: expected to Err with invalid resource id
            test_move_cursor(&mut gpu);

            // update_cursor: expected to Err with invalid resource id
            let cursor_pos = VhostUserGpuCursorPos {
                scanout_id: 0,
                x: 10,
                y: 10,
            };
            gpu.update_cursor(9_999, cursor_pos, 0, 0).unwrap_err();

            // update_cursor: create cursor resource and test reading path
            let cursor_res_id = 2;
            let cursor_req = ResourceCreate3d {
                target: RUTABAGA_PIPE_TEXTURE_2D,
                format: VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM,
                bind: RUTABAGA_PIPE_BIND_RENDER_TARGET,
                width: 64, height: 64, depth: 1,
                array_size: 1, last_level: 0, nr_samples: 0, flags: 0,
            };
            gpu.resource_create_3d(cursor_res_id, cursor_req).unwrap();

            // Attach backing for cursor resource
            let cursor_backing = GuestMemoryMmap::from_ranges(&[(GuestAddress(0xB0000), 0x10000)]).unwrap();
            gpu.attach_backing(cursor_res_id, &cursor_backing, vec![(GuestAddress(0xB0000), 16384usize)]).unwrap();

            // This should exercise common_read_cursor_resource and then fail at cursor_update (no frontend)
            let result = gpu.update_cursor(cursor_res_id, cursor_pos, 5, 5);
            assert_matches!(result, Err(GpuResponse::ErrUnspec), "Should fail at cursor_update to frontend");

            // submit_command: expected to Err with dummy buffer
            let mut cmd = [0u8; 8];
            let fence_id: Vec<u64> = vec![];
            gpu.submit_command(1, &mut cmd[..], &fence_id).unwrap_err();

            let t = Transfer3DDesc::new_2d(0, 0, 1, 1, 0);
            gpu.transfer_write(0, res_id, t).unwrap();
            gpu.transfer_read(0, res_id, t, None).unwrap();

            // create_fence + process_fence
            test_fence_operations(&mut gpu);

            gpu.detach_backing(res_id).unwrap();

            // create_context / destroy_context and use ctx in transfers
            let ctx_id = 1;
            assert_matches!(gpu.create_context(ctx_id, 0, None), Ok(_));
            gpu.context_attach_resource(1, 1).unwrap();
            gpu.context_detach_resource(1, 1).unwrap();

            let _ = gpu.destroy_context(ctx_id);
            // use invalid ctx_id, should fail after destroy
            let _ = gpu.transfer_write(ctx_id, res_id, t).unwrap_err();
            let _ = gpu.transfer_read(0, res_id, t, None).unwrap_err();

            // scanout + flush paths
            let dirty = virtio_gpu_rect { x: 0.into(), y: 0.into(), width: 32.into(), height: 32.into() };
            gpu.flush_resource(9_999, dirty).unwrap_err();

            let res2 = 404u32;
            let req2 = ResourceCreate3d {
                target: RUTABAGA_PIPE_TEXTURE_2D,
                format: VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM,
                bind: RUTABAGA_PIPE_BIND_RENDER_TARGET,
                width: 64, height: 64, depth: 1,
                array_size: 1, last_level: 0, nr_samples: 0, flags: 0,
            };
            gpu.resource_create_3d(res2, req2).unwrap();

            assert_matches!(gpu.flush_resource(res2, dirty), Ok(GpuResponse::OkNoData));

            gpu.set_scanout(1, 1, dirty).unwrap_err();
            gpu.set_scanout(1, 0, dirty).unwrap_err();

            // resource_id = 0 disables scanout
            assert_matches!(gpu.flush_resource(0, dirty), Ok(GpuResponse::OkNoData));

            // Test capset queries
            for index in [0, 1, 3] {
                test_capset_operations(&gpu, index);
            }

            // Test blob resource functions (all should return ErrUnspec - not implemented)
            assert_matches!(
                gpu.resource_create_blob(1, 100, 0, 4096, 0, 0),
                Err(GpuResponse::ErrUnspec)
            );
            assert_matches!(
                gpu.resource_map_blob(100, 0),
                Err(GpuResponse::ErrUnspec)
            );
            assert_matches!(
                gpu.resource_unmap_blob(100),
                Err(GpuResponse::ErrUnspec)
            );

            // Test resource_assign_uuid (not implemented)
            assert_matches!(
                gpu.resource_assign_uuid(1),
                Err(GpuResponse::ErrUnspec)
            );

            // Test display_info (should fail without frontend)
            assert_matches!(
                gpu.display_info(),
                Err(GpuResponse::ErrUnspec)
            );

            // Test force_ctx_0
            gpu.force_ctx_0();

            // Test get_event_poll_fd
            let _poll_fd = gpu.get_event_poll_fd();

            // Test transfer_write_2d
            let t2d = Transfer3DDesc::new_2d(0, 0, 1, 1, 0);
            gpu.transfer_write_2d(0, res_id, t2d).unwrap_err();

            // Test unref with resource that has scanouts (should fail)
            let res3 = 500u32;
            let req3 = ResourceCreate3d {
                target: RUTABAGA_PIPE_TEXTURE_2D,
                format: VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM,
                bind: RUTABAGA_PIPE_BIND_RENDER_TARGET,
                width: 32, height: 32, depth: 1,
                array_size: 1, last_level: 0, nr_samples: 0, flags: 0,
            };
            gpu.resource_create_3d(res3, req3).unwrap();

            // Manually enable scanout on the resource to test unref protection
            if let Some(resource) = gpu.resources.get_mut(&res3) {
                resource.scanouts.enable(0);
            }

            // Now unref should fail because resource has active scanouts
            assert_matches!(
                gpu.unref_resource(res3),
                Err(GpuResponse::ErrUnspec)
            );
        }
    }
}
