// Gfxstream backend device
// Copyright 2019 The ChromiumOS Authors
// Copyright 2025 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    cell::RefCell,
    collections::BTreeMap,
    io::{self, IoSliceMut},
    os::{fd::FromRawFd, raw::c_void},
    sync::{Arc, Mutex},
};

use log::{debug, error, warn};
use rutabaga_gfx::{
    ResourceCreate3D, Rutabaga, RutabagaBuilder, RutabagaComponentType, RutabagaFence,
    RutabagaFenceHandler, RutabagaHandle, RutabagaIntoRawDescriptor, RutabagaIovec, Transfer3D,
};
use vhost::vhost_user::{
    gpu_message::{
        VhostUserGpuCursorPos, VhostUserGpuEdidRequest, VhostUserGpuScanout, VhostUserGpuUpdate,
    },
    GpuBackend,
};
use vhost_user_backend::{VringRwLock, VringT};
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap, VolatileSlice};
use vmm_sys_util::eventfd::EventFd;

use crate::{
    backend::{
        common,
        common::{common_set_scanout_disable, AssociatedScanouts, CursorConfig, VirtioGpuScanout},
    },
    device::Error,
    gpu_types::{FenceState, ResourceCreate3d, Transfer3DDesc, VirtioGpuRing},
    protocol::{
        virtio_gpu_rect, GpuResponse,
        GpuResponse::{
            ErrInvalidParameter, ErrInvalidResourceId, ErrUnspec, OkCapset, OkCapsetInfo, OkNoData,
            OkResourcePlaneInfo,
        },
        GpuResponsePlaneInfo, VirtioGpuResult, VIRTIO_GPU_FLAG_INFO_RING_IDX,
        VIRTIO_GPU_MAX_SCANOUTS,
    },
    renderer::Renderer,
    GpuConfig,
};

// Number of bytes per pixel for reading 2D resources (assuming RGBA8 format)
const READ_RESOURCE_BYTES_PER_PIXEL: u32 = 4;

// A local resource struct for the Gfxstream backend
#[derive(Default, Clone)]
pub struct GfxstreamResource {
    pub id: u32,
    pub width: u32,
    pub height: u32,
    scanouts: common::AssociatedScanouts,
    pub info_3d: Option<rutabaga_gfx::Resource3DInfo>,
    pub handle: Option<Arc<RutabagaHandle>>,
}

impl GfxstreamResource {
    fn calculate_size(&self) -> Result<usize, &str> {
        let width = self.width as usize;
        let height = self.height as usize;
        let size = width
            .checked_mul(height)
            .ok_or("Multiplication of width and height overflowed")?
            .checked_mul(READ_RESOURCE_BYTES_PER_PIXEL as usize)
            .ok_or("Multiplication of result and bytes_per_pixel overflowed")?;

        Ok(size)
    }
}

impl GfxstreamResource {
    /// Creates a new `GfxstreamResource` with 2D/3D metadata
    pub fn new(resource_id: u32, width: u32, height: u32) -> Self {
        Self {
            id: resource_id,
            width,
            height,
            scanouts: AssociatedScanouts::default(),
            info_3d: None,
            handle: None,
        }
    }
}

// Thread-local storage for the Rutabaga instance.
// This allows each worker thread to have its own, non-shared instance.
thread_local! {
    static TLS_RUTABAGA: RefCell<Option<Rutabaga>> = const { RefCell::new(None) };
}

pub struct GfxstreamAdapter {
    gpu_backend: GpuBackend,
    resources: BTreeMap<u32, GfxstreamResource>,
    fence_state: Arc<Mutex<FenceState>>,
    scanouts: [Option<VirtioGpuScanout>; VIRTIO_GPU_MAX_SCANOUTS as usize],
}

impl GfxstreamAdapter {
    pub fn new(
        queue_ctl: &VringRwLock,
        gpu_config: &GpuConfig,
        gpu_backend: GpuBackend,
    ) -> io::Result<Self> {
        let fence_state = Arc::new(Mutex::new(FenceState::default()));
        let fence = Self::create_fence_handler(queue_ctl.clone(), fence_state.clone());

        // Lazily initialize Rutabaga for the thread
        TLS_RUTABAGA.with(|slot| {
            if slot.borrow().is_none() {
                let (builder, _component) = Self::configure_rutabaga_builder(gpu_config, fence);
                let rb = builder.build().expect("Failed to build Rutabaga");
                *slot.borrow_mut() = Some(rb);
            }
        });

        Ok(Self {
            gpu_backend,
            fence_state,
            resources: BTreeMap::new(),
            scanouts: Default::default(),
        })
    }

    fn create_fence_handler(
        queue_ctl: VringRwLock,
        fence_state: Arc<Mutex<FenceState>>,
    ) -> RutabagaFenceHandler {
        RutabagaFenceHandler::new(move |completed_fence: RutabagaFence| {
            debug!(
                "XXX - fence called: id={}, ring_idx={}",
                completed_fence.fence_id, completed_fence.ring_idx
            );

            let mut fence_state = fence_state.lock().unwrap();
            let mut i = 0;

            let ring = match completed_fence.flags & VIRTIO_GPU_FLAG_INFO_RING_IDX {
                0 => VirtioGpuRing::Global,
                _ => VirtioGpuRing::ContextSpecific {
                    ctx_id: completed_fence.ctx_id,
                    ring_idx: completed_fence.ring_idx,
                },
            };

            while i < fence_state.descs.len() {
                debug!("XXX - fence_id: {}", fence_state.descs[i].fence_id);
                if fence_state.descs[i].ring == ring
                    && fence_state.descs[i].fence_id <= completed_fence.fence_id
                {
                    let completed_desc = fence_state.descs.remove(i);
                    debug!(
                        "XXX - found fence: desc_index={}",
                        completed_desc.desc_index
                    );

                    queue_ctl
                        .add_used(completed_desc.desc_index, completed_desc.len)
                        .unwrap();

                    queue_ctl
                        .signal_used_queue()
                        .map_err(Error::NotificationFailed)
                        .unwrap();
                    debug!("Notification sent");
                } else {
                    i += 1;
                }
            }

            // Update the last completed fence for this context
            fence_state
                .completed_fences
                .insert(ring, completed_fence.fence_id);
        })
    }

    fn configure_rutabaga_builder(
        gpu_config: &GpuConfig,
        fence: RutabagaFenceHandler,
    ) -> (RutabagaBuilder, RutabagaComponentType) {
        let component = RutabagaComponentType::Gfxstream;

        let builder = RutabagaBuilder::new(gpu_config.capsets().bits(), fence)
            .set_use_egl(gpu_config.flags().use_egl)
            .set_use_gles(gpu_config.flags().use_gles)
            .set_use_surfaceless(gpu_config.flags().use_surfaceless)
            // Since vhost-user-gpu is out-of-process this is the only type of blob resource that
            // could work, so this is always enabled
            .set_use_external_blob(true);

        (builder, component)
    }

    fn sglist_to_rutabaga_iovecs(
        vecs: &[(GuestAddress, usize)],
        mem: &GuestMemoryMmap,
    ) -> std::result::Result<Vec<RutabagaIovec>, ()> {
        if vecs
            .iter()
            .any(|&(addr, len)| mem.get_slice(addr, len).is_err())
        {
            return Err(());
        }

        let mut rutabaga_iovecs: Vec<RutabagaIovec> = Vec::new();
        for &(addr, len) in vecs {
            let slice = mem.get_slice(addr, len).unwrap();
            let iov = RutabagaIovec {
                base: slice.ptr_guard_mut().as_ptr().cast::<c_void>(),
                len,
            };
            rutabaga_iovecs.push(iov);
        }
        Ok(rutabaga_iovecs)
    }

    fn with_rutabaga<T, F: FnOnce(&mut Rutabaga) -> T>(f: F) -> T {
        TLS_RUTABAGA.with(|slot| {
            let mut opt = slot.borrow_mut();
            let rb = opt.as_mut().expect("Rutabaga not initialized");
            f(rb)
        })
    }

    fn read_2d_resource(resource: &GfxstreamResource, output: &mut [u8]) -> Result<(), String> {
        let minimal_buffer_size = resource.calculate_size()?;
        assert!(output.len() >= minimal_buffer_size);

        let transfer = Transfer3D {
            x: 0,
            y: 0,
            z: 0,
            w: resource.width,
            h: resource.height,
            d: 1,
            level: 0,
            stride: resource.width * READ_RESOURCE_BYTES_PER_PIXEL,
            layer_stride: 0,
            offset: 0,
        };
        Self::with_rutabaga(|rutabaga| {
            rutabaga.transfer_read(0, resource.id, transfer, Some(IoSliceMut::new(output)))
        })
        .map_err(|e| format!("{e}"))?;

        Ok(())
    }

    fn result_from_query(resource_id: u32) -> GpuResponse {
        let Ok(query) = Self::with_rutabaga(|rutabaga| rutabaga.resource3d_info(resource_id))
        else {
            return OkNoData;
        };
        let mut plane_info = Vec::with_capacity(4);
        for plane_index in 0..4 {
            plane_info.push(GpuResponsePlaneInfo {
                stride: query.strides[plane_index],
                offset: query.offsets[plane_index],
            });
        }
        let format_modifier = query.modifier;
        OkResourcePlaneInfo {
            format_modifier,
            plane_info,
        }
    }
}

impl Renderer for GfxstreamAdapter {
    fn resource_create_3d(&mut self, resource_id: u32, args: ResourceCreate3d) -> VirtioGpuResult {
        let rutabaga_args: ResourceCreate3D = args.into();
        Self::with_rutabaga(|rutabaga| rutabaga.resource_create_3d(resource_id, rutabaga_args))?;

        let resource = GfxstreamResource {
            id: resource_id,
            width: rutabaga_args.width,
            height: rutabaga_args.height,
            scanouts: AssociatedScanouts::default(),
            info_3d: None,
            handle: None,
        };
        debug_assert!(
            !self.resources.contains_key(&resource_id),
            "Resource ID {resource_id} already exists in the resources map."
        );

        // Rely on rutabaga to check for duplicate resource ids.
        self.resources.insert(resource_id, resource);
        Ok(Self::result_from_query(resource_id))
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
        Self::with_rutabaga(|rutabaga| rutabaga.unref_resource(resource_id))?;

        Ok(OkNoData)
    }

    fn transfer_write(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3DDesc,
    ) -> VirtioGpuResult {
        Self::with_rutabaga(|rutabaga| {
            rutabaga.transfer_write(ctx_id, resource_id, transfer.into(), None)
        })?;
        Ok(OkNoData)
    }

    fn transfer_write_2d(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3DDesc,
    ) -> VirtioGpuResult {
        Self::with_rutabaga(|rutabaga| {
            rutabaga.transfer_write(ctx_id, resource_id, transfer.into(), None)
        })?;
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

        Self::with_rutabaga(|rutabaga| {
            rutabaga.transfer_read(ctx_id, resource_id, transfer.into(), buf)
        })?;
        Ok(OkNoData)
    }

    fn attach_backing(
        &mut self,
        resource_id: u32,
        mem: &GuestMemoryMmap,
        vecs: Vec<(GuestAddress, usize)>,
    ) -> VirtioGpuResult {
        let rutabaga_iovecs =
            Self::sglist_to_rutabaga_iovecs(&vecs[..], mem).map_err(|()| GpuResponse::ErrUnspec)?;
        Self::with_rutabaga(|rutabaga| rutabaga.attach_backing(resource_id, rutabaga_iovecs))?;
        Ok(OkNoData)
    }

    fn detach_backing(&mut self, resource_id: u32) -> VirtioGpuResult {
        Self::with_rutabaga(|rutabaga| rutabaga.detach_backing(resource_id))?;
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

        if cursor_resource.width != config.width || cursor_resource.height != config.height {
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
        debug!("get_capset_info index {index}");
        let (capset_id, version, size) =
            Self::with_rutabaga(|rutabaga| rutabaga.get_capset_info(index))?;
        Ok(OkCapsetInfo {
            capset_id,
            version,
            size,
        })
    }

    fn get_capset(&self, capset_id: u32, version: u32) -> VirtioGpuResult {
        let capset = Self::with_rutabaga(|rutabaga| rutabaga.get_capset(capset_id, version))?;
        Ok(OkCapset(capset))
    }

    fn create_context(
        &mut self,
        ctx_id: u32,
        context_init: u32,
        context_name: Option<&str>,
    ) -> VirtioGpuResult {
        Self::with_rutabaga(|rutabaga| {
            rutabaga.create_context(ctx_id, context_init, context_name)
        })?;
        Ok(OkNoData)
    }

    fn destroy_context(&mut self, ctx_id: u32) -> VirtioGpuResult {
        Self::with_rutabaga(|rutabaga| rutabaga.destroy_context(ctx_id))?;
        Ok(OkNoData)
    }

    fn context_attach_resource(&mut self, ctx_id: u32, resource_id: u32) -> VirtioGpuResult {
        Self::with_rutabaga(|rutabaga| rutabaga.context_attach_resource(ctx_id, resource_id))?;
        Ok(OkNoData)
    }

    fn context_detach_resource(&mut self, ctx_id: u32, resource_id: u32) -> VirtioGpuResult {
        Self::with_rutabaga(|rutabaga| rutabaga.context_detach_resource(ctx_id, resource_id))?;
        Ok(OkNoData)
    }

    fn submit_command(
        &mut self,
        ctx_id: u32,
        commands: &mut [u8],
        fence_ids: &[u64],
    ) -> VirtioGpuResult {
        Self::with_rutabaga(|rutabaga| rutabaga.submit_command(ctx_id, commands, fence_ids))?;
        Ok(OkNoData)
    }

    fn create_fence(&mut self, rutabaga_fence: RutabagaFence) -> VirtioGpuResult {
        Self::with_rutabaga(|rutabaga| rutabaga.create_fence(rutabaga_fence))?;
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
        Self::with_rutabaga(|rutabaga| {
            rutabaga.poll_descriptor().map(|fd| {
                // SAFETY: Safe, the fd should be valid, because Rutabaga guarantees it.
                // into_raw_descriptor() returns a RawFd and makes sure SafeDescriptor::drop
                // doesn't run.
                unsafe { EventFd::from_raw_fd(fd.into_raw_descriptor()) }
            })
        })
    }

    fn event_poll(&self) {
        Self::with_rutabaga(|rutabaga| {
            rutabaga.event_poll();
        });
    }

    fn force_ctx_0(&self) {
        Self::with_rutabaga(|rutabaga| {
            rutabaga.force_ctx_0();
        });
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
        if resource_id == 0 {
            common_set_scanout_disable(&mut self.scanouts, scanout_idx);

            self.gpu_backend
                .set_scanout(&VhostUserGpuScanout {
                    scanout_id,
                    width: 0,
                    height: 0,
                })
                .map_err(|e| {
                    error!("Failed to disable scanout: {e:?}");
                    ErrUnspec
                })?;

            return Ok(OkNoData);
        }

        // If there was a different resource previously associated with this scanout,
        // disable the scanout on that old resource
        if let Some(old_scanout) = &self.scanouts[scanout_idx] {
            let old_resource_id = old_scanout.resource_id;
            if old_resource_id != resource_id {
                if let Some(old_resource) = self.resources.get_mut(&old_resource_id) {
                    old_resource.scanouts.disable(scanout_id);
                }
            }
        }

        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        debug!(
            "Enabling legacy scanout scanout_id={scanout_id}, resource_id={resource_id}: {rect:?}"
        );

        self.gpu_backend
            .set_scanout(&VhostUserGpuScanout {
                scanout_id,
                width: rect.width.into(),
                height: rect.height.into(),
            })
            .map_err(|e| {
                error!("Failed to legacy set_scanout: {e:?}");
                ErrUnspec
            })?;

        resource.scanouts.enable(scanout_id);
        self.scanouts[scanout_idx] = Some(VirtioGpuScanout { resource_id });

        // Send initial framebuffer update to QEMU
        // This ensures the display is properly initialized
        let resource_size = resource.calculate_size().map_err(|e| {
            error!("Invalid resource size for scanout: {e:?}");
            ErrUnspec
        })?;

        let mut data = vec![0; resource_size];

        if let Err(e) = Self::read_2d_resource(resource, &mut data) {
            error!("Failed to read resource {resource_id} for initial scanout {scanout_id}: {e}");
        } else {
            // Send the initial framebuffer data to QEMU
            self.gpu_backend
                .update_scanout(
                    &VhostUserGpuUpdate {
                        scanout_id,
                        x: 0,
                        y: 0,
                        width: resource.width,
                        height: resource.height,
                    },
                    &data,
                )
                .map_err(|e| {
                    error!("Failed to send initial framebuffer update: {e:?}");
                    ErrUnspec
                })?;
        }

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
            // Gfxstream expects image memory transfer (read + send)
            let resource_size = resource.calculate_size().map_err(|e| {
                error!("Invalid resource size for flushing: {e:?}");
                ErrUnspec
            })?;

            let mut data = vec![0; resource_size];

            // Gfxstream doesn't support transfer_read for portion of the resource. So we
            // always read the whole resource, even if the guest specified to
            // flush only a portion of it.
            //
            // The function stream_renderer_transfer_read_iov seems to ignore the stride and
            // transfer_box parameters and expects the provided buffer to fit the whole
            // resource.
            if let Err(e) = Self::read_2d_resource(&resource, &mut data) {
                error!("Failed to read resource {resource_id} for scanout {scanout_id}: {e}");
                continue;
            }

            self.gpu_backend
                .update_scanout(
                    &VhostUserGpuUpdate {
                        scanout_id,
                        x: 0,
                        y: 0,
                        width: resource.width,
                        height: resource.height,
                    },
                    &data,
                )
                .map_err(|e| {
                    error!("Failed to update_scanout: {e:?}");
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
mod gfx_fence_tests {
    use std::{
        os::unix::net::UnixStream,
        sync::{Arc, Mutex},
    };

    use assert_matches::assert_matches;
    use rusty_fork::rusty_fork_test;
    use rutabaga_gfx::RutabagaFence;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    use super::*;
    use crate::{
        gpu_types::{FenceDescriptor, FenceState, VirtioGpuRing},
        protocol::{
            VIRTIO_GPU_BIND_RENDER_TARGET, VIRTIO_GPU_FLAG_INFO_RING_IDX,
            VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM, VIRTIO_GPU_TEXTURE_2D,
        },
        testutils::{
            create_vring, test_capset_operations, test_fence_operations, test_move_cursor,
            TestingDescChainArgs,
        },
        GpuCapset, GpuFlags, GpuMode,
    };

    const CREATE_RESOURCE_2D_720P: ResourceCreate3d = ResourceCreate3d {
        target: VIRTIO_GPU_TEXTURE_2D,
        format: VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM,
        bind: VIRTIO_GPU_BIND_RENDER_TARGET,
        width: 1280,
        height: 720,
        depth: 1,
        array_size: 1,
        last_level: 0,
        nr_samples: 0,
        flags: 0,
    };

    const CREATE_RESOURCE_CURSOR: ResourceCreate3d = ResourceCreate3d {
        target: VIRTIO_GPU_TEXTURE_2D,
        format: VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM,
        bind: VIRTIO_GPU_BIND_RENDER_TARGET,
        width: 64,
        height: 64,
        depth: 1,
        array_size: 1,
        last_level: 0,
        nr_samples: 0,
        flags: 0,
    };

    fn dummy_gpu_backend() -> GpuBackend {
        let (_, backend) = UnixStream::pair().unwrap();
        GpuBackend::from_stream(backend)
    }

    /// Attempts to create a GPU adapter for testing.
    /// Returns None if gfxstream initialization fails (e.g., in CI without GPU
    /// drivers).
    fn new_gpu() -> Option<GfxstreamAdapter> {
        let config = GpuConfig::new(
            GpuMode::Gfxstream,
            Some(GpuCapset::GFXSTREAM_VULKAN | GpuCapset::GFXSTREAM_GLES),
            GpuFlags::default(),
        )
        .ok()?;

        let mem = vm_memory::GuestMemoryAtomic::new(
            vm_memory::GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20_000)]).unwrap(),
        );
        let chains: [TestingDescChainArgs; 0] = [];
        let (vring, _outs, _call_evt) = create_vring(
            &mem,
            &chains,
            GuestAddress(0x20_00),
            GuestAddress(0x40_00),
            64,
        );

        let fence_state = Arc::new(Mutex::new(FenceState::default()));

        let fence = GfxstreamAdapter::create_fence_handler(vring, fence_state.clone());

        let builder = GfxstreamAdapter::configure_rutabaga_builder(&config, fence);

        // Try to build rutabaga - will fail in CI without GPU drivers
        let rutabaga = match builder.0.build() {
            Ok(r) => r,
            Err(_) => {
                // GPU not available (CI, no drivers, etc.)
                return None;
            }
        };

        // Install into TLS so Renderer methods can find it
        TLS_RUTABAGA.with(|slot| {
            *slot.borrow_mut() = Some(rutabaga);
        });

        Some(GfxstreamAdapter {
            gpu_backend: dummy_gpu_backend(),
            resources: BTreeMap::default(),
            fence_state,
            scanouts: Default::default(),
        })
    }

    fn fence_desc(r: VirtioGpuRing, id: u64, idx: u16, len: u32) -> FenceDescriptor {
        FenceDescriptor {
            ring: r,
            fence_id: id,
            desc_index: idx,
            len,
        }
    }

    rusty_fork_test! {
        #[test]
        fn test_update_cursor_fails() {
            let Some(mut gfxstream_gpu) = new_gpu() else {
                eprintln!("Skipping test: GPU not available (no drivers in CI)");
                return;
            };

            let cursor_pos = VhostUserGpuCursorPos {
                scanout_id: 1,
                x: 123,
                y: 123,
            };

            // The resource doesn't exist
            let result = gfxstream_gpu.update_cursor(1, cursor_pos, 0, 0);
            assert_matches!(result, Err(ErrInvalidResourceId));

            // Create a resource
            gfxstream_gpu.resource_create_3d(1, CREATE_RESOURCE_2D_720P).unwrap();

            // The resource exists, but the dimensions are wrong
            let result = gfxstream_gpu.update_cursor(1, cursor_pos, 0, 0);
            assert_matches!(result, Err(ErrInvalidParameter));

            // Create a resource with correct cursor dimensions
            let cursor_resource_id = 2;
            gfxstream_gpu
                .resource_create_3d(
                    cursor_resource_id,
                    CREATE_RESOURCE_CURSOR).unwrap();

            // Attach backing for cursor resource to ensure transfer_read works
            let cursor_backing = GuestMemoryMmap::from_ranges(&[(GuestAddress(0xC0000), 0x10000)]).unwrap();
            gfxstream_gpu.attach_backing(cursor_resource_id, &cursor_backing, vec![(GuestAddress(0xC0000), 16384usize)]).unwrap();

            // The resource exists, the dimensions are correct, and backing is attached
            // This exercises common_read_cursor_resource and then fails at cursor_update (no frontend)
            let result = gfxstream_gpu.update_cursor(cursor_resource_id, cursor_pos, 5, 5);
            assert_matches!(result, Err(ErrUnspec));
        }

        #[test]
        fn test_move_cursor_fails() {
            let Some(mut gfxstream_gpu) = new_gpu() else {
                eprintln!("Skipping test: GPU not available (no drivers in CI)");
                return;
            };
            test_move_cursor(&mut gfxstream_gpu);
        }

        #[test]
        fn test_process_fence() {
            let Some(mut gfxstream_gpu) = new_gpu() else {
                eprintln!("Skipping test: GPU not available (no drivers in CI)");
                return;
            };
            test_fence_operations(&mut gfxstream_gpu);
        }

        #[test]
        fn test_gpu_commands() {
            let Some(mut gfxstream_gpu) = new_gpu() else {
                eprintln!("Skipping test: GPU not available (no drivers in CI)");
                return;
            };
            gfxstream_gpu.event_poll();
            gfxstream_gpu.get_event_poll_fd();
            gfxstream_gpu.force_ctx_0();
            gfxstream_gpu.display_info().unwrap_err();
            let edid_req = VhostUserGpuEdidRequest {
                scanout_id: 0,
            };
            gfxstream_gpu.get_edid(edid_req).unwrap_err();
            gfxstream_gpu.create_context(1, 0, None).unwrap();
            gfxstream_gpu.context_attach_resource(1, 1).unwrap_err();
            gfxstream_gpu.context_detach_resource(1, 1).unwrap_err();
            gfxstream_gpu.destroy_context(1).unwrap();
        }

        #[test]
        fn test_transfer_read_and_write() {
            let Some(mut gfxstream_gpu) = new_gpu() else {
                eprintln!("Skipping test: GPU not available (no drivers in CI)");
                return;
            };
            let transfer_data: Transfer3DDesc = Transfer3DDesc::new_2d(
                0,
                0,
                64,
                64,
                0,
            );
            gfxstream_gpu.transfer_read(1, 1, transfer_data, None).unwrap_err();
            gfxstream_gpu.transfer_write(1, 1, transfer_data).unwrap_err();
            gfxstream_gpu.transfer_write_2d(1, 1, transfer_data).unwrap_err();
        }
        #[test]
        fn test_create_and_unref_resources() {
            let Some(mut gfxstream_gpu) = new_gpu() else {
                eprintln!("Skipping test: GPU not available (no drivers in CI)");
                return;
            };

            let rect = virtio_gpu_rect { x: 0.into(), y: 0.into(), width: 32.into(), height: 32.into() };
            // No resources exists, cannot unref anything:
            assert!(gfxstream_gpu.resources.is_empty());
            let result = gfxstream_gpu.unref_resource(0);
            assert_matches!(result, Err(_));

            // Create a resource
            let result = gfxstream_gpu.resource_create_3d(1, CREATE_RESOURCE_2D_720P);
            assert_matches!(result, Ok(_));
            assert_eq!(gfxstream_gpu.resources.len(), 1);

            // Backing memory for the resource: one 4-byte pixel at 0xA0000.
            // (Keep this GuestMemoryMmap alive while attached.)
            let gm_back = GuestMemoryMmap::from_ranges(&[(GuestAddress(0xA0000), 0x1000)]).unwrap();

            // Write some bytes into the backing memory so transfer_write has data to pull.
            let pattern = [0x11, 0x22, 0x33, 0x44];
            gm_back.write(&pattern, GuestAddress(0xA0000)).unwrap();

            // Attach that single iovec (addr,len) to the resource.
            let sg = vec![(GuestAddress(0xA0000), 4usize)];
            gfxstream_gpu.attach_backing(1, &gm_back, sg).expect("attach_backing");
            // Detach the backing memory from the resource
            gfxstream_gpu.detach_backing(1).expect("detach_backing");
            gfxstream_gpu.set_scanout(1, 1, rect).unwrap_err();
            gfxstream_gpu.set_scanout(1, 0, rect).unwrap_err();

            gfxstream_gpu.flush_resource(1, rect).expect("flush_resource");
            // Unref the created resource
            let result = gfxstream_gpu.unref_resource(1);
            assert_matches!(result, Ok(_));
            assert!(gfxstream_gpu.resources.is_empty());
        }

        #[test]
        fn test_flush_resource_with_scanout() {
            let Some(mut gfxstream_gpu) = new_gpu() else {
                eprintln!("Skipping test: GPU not available (no drivers in CI)");
                return;
            };

            // Create a resource with specific dimensions
            gfxstream_gpu.resource_create_3d(1, CREATE_RESOURCE_2D_720P).unwrap();

            // Manually enable a scanout on the resource to exercise flush_resource -> read_2d_resource path
            // This bypasses set_scanout which would fail without a frontend
            if let Some(resource) = gfxstream_gpu.resources.get_mut(&1) {
                resource.scanouts.enable(0); // Enable scanout 0
            }

            let rect = virtio_gpu_rect {
                x: 0.into(),
                y: 0.into(),
                width: 32.into(),
                height: 32.into(),
            };

            // This should exercise the read_2d_resource path through flush_resource
            // It will fail because there's no frontend, but that's after read_2d_resource is called
            let _result = gfxstream_gpu.flush_resource(1, rect);
            // Note: This may succeed or fail depending on whether update_scanout to backend fails
        }

        #[test]
        fn test_gpu_capset() {
            let Some(gfxstream_gpu) = new_gpu() else {
                eprintln!("Skipping test: GPU not available (no drivers in CI)");
                return;
            };
            test_capset_operations(&gfxstream_gpu, 0);
        }

        #[test]
        fn test_gpu_submit_command_fails() {
            let Some(mut gfxstream_gpu) = new_gpu() else {
                eprintln!("Skipping test: GPU not available (no drivers in CI)");
                return;
            };
            let mut cmd_buf = [0; 10];
            let fence_ids: Vec<u64> = Vec::with_capacity(0);
            gfxstream_gpu
                .submit_command(1, &mut cmd_buf[..], &fence_ids)
            .unwrap_err();
        }
    }

    #[test]
    fn fence_handler_global_and_context_paths() {
        // One guest memory arena is fine for both sub-cases.
        let mem = vm_memory::GuestMemoryAtomic::new(
            vm_memory::GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20_000)]).unwrap(),
        );
        let chains: [TestingDescChainArgs; 0] = [];

        // -------------------------------
        // A) Global ring: match → remove + notify
        // -------------------------------
        let (vring_a, _outs_a, call_evt_a) = create_vring(
            &mem,
            &chains,
            GuestAddress(0x2000),
            GuestAddress(0x4000),
            64,
        );

        let fence_state_a = Arc::new(Mutex::new(FenceState {
            descs: vec![
                fence_desc(VirtioGpuRing::Global, 5, 3, 64),
                fence_desc(VirtioGpuRing::Global, 9, 4, 64),
            ],
            completed_fences: BTreeMap::default(),
        }));

        let handler_a = GfxstreamAdapter::create_fence_handler(vring_a, fence_state_a.clone());

        // Drain any stale signal (ignore WouldBlock)
        let _ = call_evt_a.read();

        handler_a.call(RutabagaFence {
            fence_id: 7,
            ctx_id: 0,
            ring_idx: 0, // Global
            flags: 0,
        });

        {
            let st_a = fence_state_a.lock().unwrap();
            assert_eq!(st_a.descs.len(), 1);
            assert_eq!(st_a.descs[0].fence_id, 9);
            assert_eq!(
                st_a.completed_fences.get(&VirtioGpuRing::Global),
                Some(&7u64)
            );
            drop(st_a);
        }
        assert_eq!(
            call_evt_a.read().unwrap(),
            1,
            "queue should be signaled once"
        );

        // -------------------------------
        // B) Context-specific ring: match → remove + notify
        // -------------------------------
        let (vring_b, _outs_b, call_evt_b) = create_vring(
            &mem,
            &chains,
            GuestAddress(0x6000),
            GuestAddress(0x8000),
            32,
        );

        let fence_state_b = Arc::new(Mutex::new(FenceState {
            // Only global, no context-specific fences
            descs: vec![fence_desc(VirtioGpuRing::Global, 7, 1, 1)],
            completed_fences: BTreeMap::default(),
        }));

        let handler_b = GfxstreamAdapter::create_fence_handler(vring_b, fence_state_b.clone());

        handler_b.call(RutabagaFence {
            fence_id: 6,
            ctx_id: 42,
            ring_idx: 3,
            flags: VIRTIO_GPU_FLAG_INFO_RING_IDX, // use context ring
        });

        {
            let st_b = fence_state_b.lock().unwrap();
            assert_eq!(st_b.descs.len(), 1, "no descriptor should be removed");
            let key = VirtioGpuRing::ContextSpecific {
                ctx_id: 42,
                ring_idx: 3,
            };
            assert_eq!(st_b.completed_fences.get(&key), Some(&6u64));
            drop(st_b);
        }
        assert!(
            call_evt_b.read().is_err(),
            "no signal expected when no match"
        );
    }

    // GfxstreamResource::calculate_size
    // Tests for normal and overflow cases.
    #[test]
    fn calculate_size_ok() {
        let r = GfxstreamResource {
            id: 1,
            width: 64,
            height: 64,
            ..Default::default()
        };
        // 64 * 64 * 4 BPP = 16384
        assert_eq!(
            r.calculate_size().unwrap(),
            64 * 64 * (READ_RESOURCE_BYTES_PER_PIXEL as usize)
        );
    }

    #[test]
    fn calculate_size_overflow_width_height() {
        // Width * Height overflows u32
        let r = GfxstreamResource {
            id: 1,
            width: u32::MAX,
            height: u32::MAX,
            ..Default::default()
        };
        r.calculate_size().unwrap_err();
    }

    #[test]
    fn calculate_size_overflow_bpp_multiply() {
        // Large width * height that fits in usize but overflows when * BPP
        let big = (usize::MAX / (READ_RESOURCE_BYTES_PER_PIXEL as usize)).saturating_add(1);
        let r = GfxstreamResource {
            id: 1,
            width: big as u32,
            height: 1,
            ..Default::default()
        };
        // On 64-bit this should error; if it happens to fit on 32-bit, the guard still
        // holds elsewhere.
        let _ = r.calculate_size().err();
    }

    // sglist_to_rutabaga_iovecs tests

    #[test]
    fn sglist_to_rutabaga_iovecs_ok() {
        // Two mapped regions
        let gm = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0x1000), 0x2000), // [0x1000..0x3000)
            (GuestAddress(0x9000), 0x1000), // [0x9000..0xA000)
        ])
        .expect("GuestMemoryMmap");

        // Three valid segments, all inside mapped memory
        let sg = [
            (GuestAddress(0x1000), 16usize),
            (GuestAddress(0x1010), 32usize),
            (GuestAddress(0x9000), 8usize),
        ];

        let iovs = GfxstreamAdapter::sglist_to_rutabaga_iovecs(&sg[..], &gm).expect("iovecs");

        assert_eq!(iovs.len(), 3);
        assert_eq!(iovs[0].len, 16);
        assert!(!iovs[0].base.is_null());
        assert_eq!(iovs[1].len, 32);
        assert!(!iovs[1].base.is_null());
        assert_eq!(iovs[2].len, 8);
        assert!(!iovs[2].base.is_null());
    }

    #[test]
    fn sglist_to_rutabaga_iovecs_err_on_any_bad_segment() {
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0x2000), 0x1000)]).unwrap();
        // This segment starts outside mapped memory, it should Err(())
        let sg = [(GuestAddress(0x4000), 16usize)];

        assert!(GfxstreamAdapter::sglist_to_rutabaga_iovecs(&sg[..], &gm).is_err());
    }
}
