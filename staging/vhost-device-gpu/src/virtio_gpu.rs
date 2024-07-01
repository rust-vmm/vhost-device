// Copyright 2024 Red Hat Inc
// Copyright 2019 The ChromiumOS Authors
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use log::{debug, error, trace};
use std::{
    collections::BTreeMap,
    io::IoSliceMut,
    os::fd::{AsRawFd, FromRawFd},
    result::Result,
    sync::{Arc, Mutex},
};

use libc::c_void;
use rutabaga_gfx::{
    ResourceCreate3D, ResourceCreateBlob, Rutabaga, RutabagaBuilder, RutabagaFence,
    RutabagaFenceHandler, RutabagaIntoRawDescriptor, RutabagaIovec, RutabagaResult, Transfer3D,
    RUTABAGA_MAP_ACCESS_MASK, RUTABAGA_MAP_ACCESS_READ, RUTABAGA_MAP_ACCESS_RW,
    RUTABAGA_MAP_ACCESS_WRITE, RUTABAGA_MAP_CACHE_MASK, RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_FD,
};
use vhost::vhost_user::{
    gpu_message::{
        VhostUserGpuCursorPos, VhostUserGpuCursorUpdate, VhostUserGpuEdidRequest,
        VhostUserGpuScanout, VhostUserGpuUpdate, VirtioGpuRespDisplayInfo,
    },
    GpuBackend,
};
use vhost_user_backend::{VringRwLock, VringT};
use virtio_bindings::virtio_gpu::VIRTIO_GPU_BLOB_MEM_HOST3D;
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap, VolatileSlice};
use vmm_sys_util::eventfd::EventFd;

use crate::device::Error;
use crate::protocol::{
    virtio_gpu_rect, GpuResponse, GpuResponse::*, GpuResponsePlaneInfo, VirtioGpuResult,
    VIRTIO_GPU_BLOB_FLAG_CREATE_GUEST_HANDLE, VIRTIO_GPU_FLAG_INFO_RING_IDX,
    VIRTIO_GPU_MAX_SCANOUTS,
};

fn sglist_to_rutabaga_iovecs(
    vecs: &[(GuestAddress, usize)],
    mem: &GuestMemoryMmap,
) -> Result<Vec<RutabagaIovec>, ()> {
    if vecs
        .iter()
        .any(|&(addr, len)| mem.get_slice(addr, len).is_err())
    {
        return Err(());
    }

    let mut rutabaga_iovecs: Vec<RutabagaIovec> = Vec::new();
    for &(addr, len) in vecs {
        let slice = mem.get_slice(addr, len).unwrap();
        rutabaga_iovecs.push(RutabagaIovec {
            base: slice.ptr_guard_mut().as_ptr() as *mut c_void,
            len,
        });
    }
    Ok(rutabaga_iovecs)
}

#[derive(Default, Debug)]
pub struct Rectangle {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl From<virtio_gpu_rect> for Rectangle {
    fn from(r: virtio_gpu_rect) -> Self {
        Self {
            x: r.x,
            y: r.y,
            width: r.width,
            height: r.height,
        }
    }
}

pub trait VirtioGpu {
    /// Uses the hypervisor to unmap the blob resource.
    fn resource_unmap_blob(
        &mut self,
        resource_id: u32,
        shm_region: &VirtioShmRegion,
    ) -> VirtioGpuResult;

    /// Uses the hypervisor to map the rutabaga blob resource.
    ///
    /// When sandboxing is disabled, external_blob is unset and opaque fds are mapped by
    /// rutabaga as ExternalMapping.
    /// When sandboxing is enabled, external_blob is set and opaque fds must be mapped in the
    /// hypervisor process by Vulkano using metadata provided by Rutabaga::vulkan_info().
    fn resource_map_blob(
        &mut self,
        resource_id: u32,
        shm_region: &VirtioShmRegion,
        offset: u64,
    ) -> VirtioGpuResult;

    /// Creates a blob resource using rutabaga.
    fn resource_create_blob(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        resource_create_blob: ResourceCreateBlob,
        vecs: Vec<(GuestAddress, usize)>,
        mem: &GuestMemoryMmap,
    ) -> VirtioGpuResult;

    fn process_fence(
        &mut self,
        ring: VirtioGpuRing,
        fence_id: u64,
        desc_index: u16,
        len: u32,
    ) -> bool;

    /// Creates a fence with the RutabagaFence that can be used to determine when the previous
    /// command completed.
    fn create_fence(&mut self, rutabaga_fence: RutabagaFence) -> VirtioGpuResult;

    /// Submits a command buffer to a rutabaga context.
    fn submit_command(
        &mut self,
        ctx_id: u32,
        commands: &mut [u8],
        fence_ids: &[u64],
    ) -> VirtioGpuResult;

    /// Detaches a resource from a rutabaga context.
    fn context_detach_resource(&mut self, ctx_id: u32, resource_id: u32) -> VirtioGpuResult;

    /// Attaches a resource to a rutabaga context.
    fn context_attach_resource(&mut self, ctx_id: u32, resource_id: u32) -> VirtioGpuResult;

    /// Destroys a rutabaga context.
    fn destroy_context(&mut self, ctx_id: u32) -> VirtioGpuResult;
    fn force_ctx_0(&self);

    /// Gets the list of supported display resolutions as a slice of `(width, height, enabled)` tuples.
    fn display_info(&self, display_info: VirtioGpuRespDisplayInfo) -> Vec<(u32, u32, bool)>;

    /// Gets the EDID for the specified scanout ID. If that scanout is not enabled, it would return
    /// the EDID of a default display.
    fn get_edid(
        &self,
        gpu_backend: &mut GpuBackend,
        edid_req: VhostUserGpuEdidRequest,
    ) -> VirtioGpuResult;

    /// Sets the given resource id as the source of scanout to the display.
    fn set_scanout(
        &mut self,
        gpu_backend: &mut GpuBackend,
        scanout_id: u32,
        resource_id: u32,
        rect: Rectangle,
    ) -> VirtioGpuResult;

    /// Creates a 3D resource with the given properties and resource_id.
    fn resource_create_3d(
        &mut self,
        resource_id: u32,
        resource_create_3d: ResourceCreate3D,
    ) -> VirtioGpuResult;

    /// Releases guest kernel reference on the resource.
    fn unref_resource(&mut self, resource_id: u32) -> VirtioGpuResult;

    /// If the resource is the scanout resource, flush it to the display.
    fn flush_resource(
        &mut self,
        resource_id: u32,
        gpu_backend: &mut GpuBackend,
        rect: Rectangle,
    ) -> VirtioGpuResult;

    /// Copies data to host resource from the attached iovecs. Can also be used to flush caches.
    fn transfer_write(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3D,
    ) -> VirtioGpuResult;

    /// Copies data from the host resource to:
    ///    1) To the optional volatile slice
    ///    2) To the host resource's attached iovecs
    ///
    /// Can also be used to invalidate caches.
    fn transfer_read(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3D,
        buf: Option<VolatileSlice>,
    ) -> VirtioGpuResult;

    /// Attaches backing memory to the given resource, represented by a `Vec` of `(address, size)`
    /// tuples in the guest's physical address space. Converts to RutabagaIovec from the memory
    /// mapping.
    fn attach_backing(
        &mut self,
        resource_id: u32,
        mem: &GuestMemoryMmap,
        vecs: Vec<(GuestAddress, usize)>,
    ) -> VirtioGpuResult;

    /// Detaches any previously attached iovecs from the resource.
    fn detach_backing(&mut self, resource_id: u32) -> VirtioGpuResult;

    /// Updates the cursor's memory to the given resource_id, and sets its position to the given
    /// coordinates.
    fn update_cursor(
        &mut self,
        resource_id: u32,
        gpu_backend: &mut GpuBackend,
        cursor_pos: VhostUserGpuCursorPos,
        hot_x: u32,
        hot_y: u32,
    ) -> VirtioGpuResult;

    /// Moves the cursor's position to the given coordinates.
    fn move_cursor(
        &mut self,
        resource_id: u32,
        gpu_backend: &mut GpuBackend,
        cursor: VhostUserGpuCursorPos,
    ) -> VirtioGpuResult;

    /// Returns a uuid for the resource.
    fn resource_assign_uuid(&self, resource_id: u32) -> VirtioGpuResult;

    /// Gets rutabaga's capset information associated with `index`.
    fn get_capset_info(&self, index: u32) -> VirtioGpuResult;

    /// Gets a capset from rutabaga.
    fn get_capset(&self, capset_id: u32, version: u32) -> VirtioGpuResult;

    /// Creates a rutabaga context.
    fn create_context(
        &mut self,
        ctx_id: u32,
        context_init: u32,
        context_name: Option<&str>,
    ) -> VirtioGpuResult;

    /// Get an EventFd descriptor, that signals when to call event_poll.
    fn get_event_poll_fd(&self) -> Option<EventFd>;

    /// Polls the Rutabaga backend.
    fn event_poll(&self);
}

#[derive(Clone, Default)]
pub struct VirtioShmRegion {
    pub host_addr: u64,
    pub guest_addr: u64,
    pub size: usize,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub enum VirtioGpuRing {
    Global,
    ContextSpecific { ctx_id: u32, ring_idx: u8 },
}

struct FenceDescriptor {
    ring: VirtioGpuRing,
    fence_id: u64,
    desc_index: u16,
    len: u32,
}

#[derive(Default)]
pub struct FenceState {
    descs: Vec<FenceDescriptor>,
    completed_fences: BTreeMap<VirtioGpuRing, u64>,
}

#[derive(Copy, Clone, Debug, Default)]
struct AssociatedScanouts(u32);

impl AssociatedScanouts {
    fn enable(&mut self, scanout_id: u32) {
        self.0 |= 1 << scanout_id;
    }

    fn disable(&mut self, scanout_id: u32) {
        self.0 ^= 1 << scanout_id;
    }

    fn iter_enabled(self) -> impl Iterator<Item = u32> {
        (0..VIRTIO_GPU_MAX_SCANOUTS)
            .filter(move |i| ((self.0 >> i) & 1) == 1)
            .map(|n| n as u32)
    }
}

#[derive(Default)]
pub struct VirtioGpuResource {
    pub size: u64,
    pub shmem_offset: Option<u64>,
    pub rutabaga_external_mapping: bool,
    /// Stores information about which scanouts are associated with the given resource.
    /// Resource could be used for multiple scanouts (the displays are mirrored).
    scanouts: AssociatedScanouts,
}

impl VirtioGpuResource {
    /// Creates a new VirtioGpuResource with the given metadata.  Width and height are used by the
    /// display, while size is useful for hypervisor mapping.
    pub fn new(_resource_id: u32, _width: u32, _height: u32, size: u64) -> VirtioGpuResource {
        VirtioGpuResource {
            size,
            shmem_offset: None,
            rutabaga_external_mapping: false,
            scanouts: Default::default(),
        }
    }
}

pub struct VirtioGpuScanout {
    resource_id: u32,
}

pub struct RutabagaVirtioGpu {
    pub(crate) rutabaga: Rutabaga,
    pub(crate) resources: BTreeMap<u32, VirtioGpuResource>,
    pub(crate) fence_state: Arc<Mutex<FenceState>>,
    pub(crate) scanouts: [Option<VirtioGpuScanout>; VIRTIO_GPU_MAX_SCANOUTS],
}

const READ_RESOURCE_BYTES_PER_PIXEL: usize = 4;

impl RutabagaVirtioGpu {
    // TODO: this depends on Rutabaga builder, so this will need to be handled at runtime eventually
    pub const MAX_NUMBER_OF_CAPSETS: u32 = 3;

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

    pub fn new(queue_ctl: &VringRwLock) -> Self {
        let builder = RutabagaBuilder::new(rutabaga_gfx::RutabagaComponentType::VirglRenderer, 0)
            .set_use_egl(true)
            .set_use_gles(true)
            .set_use_glx(true)
            .set_use_surfaceless(true)
            .set_use_external_blob(true);

        let fence_state = Arc::new(Mutex::new(Default::default()));
        let fence = Self::create_fence_handler(queue_ctl.clone(), fence_state.clone());
        let rutabaga = builder
            .build(fence, None)
            .expect("Rutabaga initialization failed!");

        Self {
            rutabaga,
            resources: Default::default(),
            fence_state,
            scanouts: Default::default(),
        }
    }

    fn result_from_query(&mut self, resource_id: u32) -> GpuResponse {
        let Ok(query) = self.rutabaga.query(resource_id) else {
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

    fn read_2d_resource(
        &mut self,
        resource_id: u32,
        rect: &Rectangle,
        output: &mut [u8],
    ) -> RutabagaResult<()> {
        let width = rect.width as usize;
        let height = rect.height as usize;
        let bytes_per_pixel = READ_RESOURCE_BYTES_PER_PIXEL;
        let (result_len, overflowed) = width.overflowing_mul(height);
        assert!(!overflowed, "Multiplication of width and height overflowed");

        let (result_len, overflowed) = result_len.overflowing_mul(bytes_per_pixel);
        assert!(
            !overflowed,
            "Multiplication of result and bytes_per_pixel overflowed"
        );
        assert!(output.len() >= result_len);

        let transfer = Transfer3D {
            x: rect.x,
            y: rect.y,
            z: 0,
            w: rect.width,
            h: rect.height,
            d: 1,
            level: 0,
            stride: rect.width * READ_RESOURCE_BYTES_PER_PIXEL as u32,
            layer_stride: 0,
            offset: 0,
        };

        // ctx_id 0 seems to be special, crosvm uses it for this purpose too
        self.rutabaga
            .transfer_read(0, resource_id, transfer, Some(IoSliceMut::new(output)))?;

        Ok(())
    }
}

impl VirtioGpu for RutabagaVirtioGpu {
    fn force_ctx_0(&self) {
        self.rutabaga.force_ctx_0()
    }

    fn display_info(&self, display_info: VirtioGpuRespDisplayInfo) -> Vec<(u32, u32, bool)> {
        display_info
            .pmodes
            .iter()
            .map(|display| (display.r.width, display.r.height, display.enabled == 1))
            .collect::<Vec<_>>()
    }

    fn get_edid(
        &self,
        gpu_backend: &mut GpuBackend,
        edid_req: VhostUserGpuEdidRequest,
    ) -> VirtioGpuResult {
        debug!("edid request: {edid_req:?}");
        let edid = gpu_backend.get_edid(&edid_req).map_err(|e| {
            error!("Failed to get edid from frontend: {}", e);
            ErrUnspec
        })?;

        Ok(OkEdid {
            blob: Box::from(&edid.edid[..edid.size as usize]),
        })
    }

    fn set_scanout(
        &mut self,
        gpu_backend: &mut GpuBackend,
        scanout_id: u32,
        resource_id: u32,
        rect: Rectangle,
    ) -> VirtioGpuResult {
        let scanout = self
            .scanouts
            .get_mut(scanout_id as usize)
            .ok_or(ErrInvalidScanoutId)?;

        // If a resource is already associated with this scanout, make sure to disable this scanout for that resource
        if let Some(resource_id) = scanout.as_ref().map(|scanout| scanout.resource_id) {
            let resource = self
                .resources
                .get_mut(&resource_id)
                .ok_or(ErrInvalidResourceId)?;

            resource.scanouts.disable(scanout_id);
        }

        // Virtio spec: "The driver can use resource_id = 0 to disable a scanout."
        if resource_id == 0 {
            *scanout = None;
            debug!("Disabling scanout scanout_id={scanout_id}");
            gpu_backend
                .set_scanout(&VhostUserGpuScanout {
                    scanout_id,
                    width: 0,
                    height: 0,
                })
                .map_err(|e| {
                    error!("Failed to set_scanout: {e:?}");
                    ErrUnspec
                })?;
            return Ok(OkNoData);
        }

        debug!("Enabling scanout scanout_id={scanout_id}, resource_id={resource_id}: {rect:?}");

        // QEMU doesn't like (it lags) when we call set_scanout while the scanout is enabled
        if scanout.is_none() {
            gpu_backend
                .set_scanout(&VhostUserGpuScanout {
                    scanout_id,
                    width: rect.width,
                    height: rect.height,
                })
                .map_err(|e| {
                    error!("Failed to set_scanout: {e:?}");
                    ErrUnspec
                })?;
        }

        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        resource.scanouts.enable(scanout_id);
        *scanout = Some(VirtioGpuScanout { resource_id });
        Ok(OkNoData)
    }

    fn resource_create_3d(
        &mut self,
        resource_id: u32,
        resource_create_3d: ResourceCreate3D,
    ) -> VirtioGpuResult {
        self.rutabaga
            .resource_create_3d(resource_id, resource_create_3d)?;

        let resource = VirtioGpuResource::new(
            resource_id,
            resource_create_3d.width,
            resource_create_3d.height,
            0,
        );

        debug_assert!(
            !self.resources.contains_key(&resource_id),
            "Resource ID {} already exists in the resources map.",
            resource_id
        );

        // Rely on rutabaga to check for duplicate resource ids.
        self.resources.insert(resource_id, resource);
        Ok(self.result_from_query(resource_id))
    }

    fn unref_resource(&mut self, resource_id: u32) -> VirtioGpuResult {
        let resource = self
            .resources
            .remove(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        if resource.rutabaga_external_mapping {
            self.rutabaga.unmap(resource_id)?;
        }

        self.rutabaga.unref_resource(resource_id)?;
        Ok(OkNoData)
    }

    /// If the resource is the scanout resource, flush it to the display.
    fn flush_resource(
        &mut self,
        resource_id: u32,
        gpu_backend: &mut GpuBackend,
        rect: Rectangle,
    ) -> VirtioGpuResult {
        if resource_id == 0 {
            return Ok(OkNoData);
        }

        let resource = self
            .resources
            .get(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        for scanout_id in resource.scanouts.iter_enabled() {
            let width = rect.width as usize;
            let height = rect.height as usize;
            let bytes_per_pixel = READ_RESOURCE_BYTES_PER_PIXEL;
            let (result_len, overflowed) = width.overflowing_mul(height);
            assert!(!overflowed, "Multiplication of width and height overflowed");

            let (result_len, overflowed) = result_len.overflowing_mul(bytes_per_pixel);
            assert!(
                !overflowed,
                "Multiplication of result and bytes_per_pixel overflowed"
            );

            let mut data = vec![0; result_len];

            if let Err(e) = self.read_2d_resource(resource_id, &rect, &mut data) {
                log::error!("Failed to read resource {resource_id} for scanout {scanout_id}: {e}");
                continue;
            }

            gpu_backend
                .update_scanout(
                    &VhostUserGpuUpdate {
                        scanout_id,
                        x: rect.x,
                        y: rect.y,
                        width: rect.width,
                        height: rect.height,
                    },
                    &data,
                )
                .map_err(|e| {
                    error!("Failed to update_scanout: {e:?}");
                    ErrUnspec
                })?
        }

        #[cfg(windows)]
        match self.rutabaga.resource_flush(resource_id) {
            Ok(_) => return Ok(OkNoData),
            Err(RutabagaError::Unsupported) => {}
            Err(e) => return Err(ErrRutabaga(e)),
        }

        Ok(OkNoData)
    }

    fn transfer_write(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3D,
    ) -> VirtioGpuResult {
        trace!("transfer_write ctx_id {ctx_id}, resource_id {resource_id}, {transfer:?}");

        self.rutabaga
            .transfer_write(ctx_id, resource_id, transfer)?;
        Ok(OkNoData)
    }

    fn transfer_read(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3D,
        buf: Option<VolatileSlice>,
    ) -> VirtioGpuResult {
        let buf = buf.map(|vs| {
            IoSliceMut::new(
                // SAFETY: trivially safe
                unsafe { std::slice::from_raw_parts_mut(vs.ptr_guard_mut().as_ptr(), vs.len()) },
            )
        });
        self.rutabaga
            .transfer_read(ctx_id, resource_id, transfer, buf)?;
        Ok(OkNoData)
    }

    fn attach_backing(
        &mut self,
        resource_id: u32,
        mem: &GuestMemoryMmap,
        vecs: Vec<(GuestAddress, usize)>,
    ) -> VirtioGpuResult {
        let rutabaga_iovecs = sglist_to_rutabaga_iovecs(&vecs[..], mem).map_err(|_| ErrUnspec)?;
        self.rutabaga.attach_backing(resource_id, rutabaga_iovecs)?;
        Ok(OkNoData)
    }

    fn detach_backing(&mut self, resource_id: u32) -> VirtioGpuResult {
        self.rutabaga.detach_backing(resource_id)?;
        Ok(OkNoData)
    }

    fn update_cursor(
        &mut self,
        resource_id: u32,
        gpu_backend: &mut GpuBackend,
        cursor_pos: VhostUserGpuCursorPos,
        hot_x: u32,
        hot_y: u32,
    ) -> VirtioGpuResult {
        let mut data = Box::new([0; 4 * 64 * 64]);
        let cursor_rect = Rectangle {
            x: 0,
            y: 0,
            width: 64,
            height: 64,
        };

        self.read_2d_resource(resource_id, &cursor_rect, &mut data[..])
            .map_err(|e| {
                error!("Failed to read resource of cursor: {e}");
                ErrUnspec
            })?;

        let cursor_update = VhostUserGpuCursorUpdate {
            pos: cursor_pos,
            hot_x,
            hot_y,
        };

        gpu_backend
            .cursor_update(&cursor_update, &data)
            .map_err(|e| {
                error!("Failed to update cursor pos from frontend: {}", e);
                ErrUnspec
            })?;

        Ok(OkNoData)
    }

    fn move_cursor(
        &mut self,
        resource_id: u32,
        gpu_backend: &mut GpuBackend,
        cursor: VhostUserGpuCursorPos,
    ) -> VirtioGpuResult {
        if resource_id == 0 {
            gpu_backend.cursor_pos_hide(&cursor).map_err(|e| {
                error!("Failed to set cursor pos from frontend: {}", e);
                ErrUnspec
            })?;
        } else {
            gpu_backend.cursor_pos(&cursor).map_err(|e| {
                error!("Failed to set cursor pos from frontend: {}", e);
                ErrUnspec
            })?;
        }

        Ok(OkNoData)
    }

    fn resource_assign_uuid(&self, resource_id: u32) -> VirtioGpuResult {
        if !self.resources.contains_key(&resource_id) {
            return Err(ErrInvalidResourceId);
        }

        // TODO(stevensd): use real uuids once the virtio wayland protocol is updated to
        // handle more than 32 bits. For now, the virtwl driver knows that the uuid is
        // actually just the resource id.
        let mut uuid: [u8; 16] = [0; 16];
        for (idx, byte) in resource_id.to_be_bytes().iter().enumerate() {
            uuid[12 + idx] = *byte;
        }
        Ok(OkResourceUuid { uuid })
    }

    fn get_capset_info(&self, index: u32) -> VirtioGpuResult {
        let (capset_id, version, size) = self.rutabaga.get_capset_info(index)?;
        Ok(OkCapsetInfo {
            capset_id,
            version,
            size,
        })
    }

    fn get_capset(&self, capset_id: u32, version: u32) -> VirtioGpuResult {
        let capset = self.rutabaga.get_capset(capset_id, version)?;
        Ok(OkCapset(capset))
    }

    fn create_context(
        &mut self,
        ctx_id: u32,
        context_init: u32,
        context_name: Option<&str>,
    ) -> VirtioGpuResult {
        self.rutabaga
            .create_context(ctx_id, context_init, context_name)?;
        Ok(OkNoData)
    }

    fn destroy_context(&mut self, ctx_id: u32) -> VirtioGpuResult {
        self.rutabaga.destroy_context(ctx_id)?;
        Ok(OkNoData)
    }

    fn context_attach_resource(&mut self, ctx_id: u32, resource_id: u32) -> VirtioGpuResult {
        self.rutabaga.context_attach_resource(ctx_id, resource_id)?;
        Ok(OkNoData)
    }

    fn context_detach_resource(&mut self, ctx_id: u32, resource_id: u32) -> VirtioGpuResult {
        self.rutabaga.context_detach_resource(ctx_id, resource_id)?;
        Ok(OkNoData)
    }

    fn submit_command(
        &mut self,
        ctx_id: u32,
        commands: &mut [u8],
        fence_ids: &[u64],
    ) -> VirtioGpuResult {
        self.rutabaga.submit_command(ctx_id, commands, fence_ids)?;
        Ok(OkNoData)
    }

    fn create_fence(&mut self, rutabaga_fence: RutabagaFence) -> VirtioGpuResult {
        self.rutabaga.create_fence(rutabaga_fence)?;
        Ok(OkNoData)
    }

    fn process_fence(
        &mut self,
        ring: VirtioGpuRing,
        fence_id: u64,
        desc_index: u16,
        len: u32,
    ) -> bool {
        // In case the fence is signaled immediately after creation, don't add a return
        // FenceDescriptor.
        let mut fence_state = self.fence_state.lock().unwrap();
        if fence_id > *fence_state.completed_fences.get(&ring).unwrap_or(&0) {
            fence_state.descs.push(FenceDescriptor {
                ring,
                fence_id,
                desc_index,
                len,
            });

            false
        } else {
            true
        }
    }

    fn resource_create_blob(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        resource_create_blob: ResourceCreateBlob,
        vecs: Vec<(GuestAddress, usize)>,
        mem: &GuestMemoryMmap,
    ) -> VirtioGpuResult {
        let mut rutabaga_iovecs = None;

        if resource_create_blob.blob_flags & VIRTIO_GPU_BLOB_FLAG_CREATE_GUEST_HANDLE != 0 {
            panic!("GUEST_HANDLE unimplemented");
        } else if resource_create_blob.blob_mem != VIRTIO_GPU_BLOB_MEM_HOST3D {
            rutabaga_iovecs =
                Some(sglist_to_rutabaga_iovecs(&vecs[..], mem).map_err(|_| ErrUnspec)?);
        }

        self.rutabaga.resource_create_blob(
            ctx_id,
            resource_id,
            resource_create_blob,
            rutabaga_iovecs,
            None,
        )?;

        let resource = VirtioGpuResource::new(resource_id, 0, 0, resource_create_blob.size);

        debug_assert!(
            !self.resources.contains_key(&resource_id),
            "Resource ID {} already exists in the resources map.",
            resource_id
        );

        // Rely on rutabaga to check for duplicate resource ids.
        self.resources.insert(resource_id, resource);
        Ok(self.result_from_query(resource_id))
    }

    fn resource_map_blob(
        &mut self,
        resource_id: u32,
        shm_region: &VirtioShmRegion,
        offset: u64,
    ) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        let map_info = self.rutabaga.map_info(resource_id).map_err(|_| ErrUnspec)?;

        if let Ok(export) = self.rutabaga.export_blob(resource_id) {
            if export.handle_type != RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_FD {
                let prot = match map_info & RUTABAGA_MAP_ACCESS_MASK {
                    x if x == RUTABAGA_MAP_ACCESS_READ => libc::PROT_READ,
                    x if x == RUTABAGA_MAP_ACCESS_WRITE => libc::PROT_WRITE,
                    x if x == RUTABAGA_MAP_ACCESS_RW => libc::PROT_READ | libc::PROT_WRITE,
                    _ => return Err(ErrUnspec),
                };

                if offset + resource.size > shm_region.size as u64 {
                    error!("mapping DOES NOT FIT");
                }
                let addr = shm_region.host_addr + offset;
                debug!(
                    "mapping: host_addr={:x}, addr={:x}, size={}",
                    shm_region.host_addr, addr, resource.size
                );
                let ret = unsafe {
                    libc::mmap(
                        addr as *mut libc::c_void,
                        resource.size as usize,
                        prot,
                        libc::MAP_SHARED | libc::MAP_FIXED,
                        export.os_handle.as_raw_fd(),
                        0 as libc::off_t,
                    )
                };
                if ret == libc::MAP_FAILED {
                    return Err(ErrUnspec);
                }
            } else {
                return Err(ErrUnspec);
            }
        } else {
            return Err(ErrUnspec);
        }

        resource.shmem_offset = Some(offset);
        // Access flags not a part of the virtio-gpu spec.
        Ok(OkMapInfo {
            map_info: map_info & RUTABAGA_MAP_CACHE_MASK,
        })
    }

    fn resource_unmap_blob(
        &mut self,
        resource_id: u32,
        shm_region: &VirtioShmRegion,
    ) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        let shmem_offset = resource.shmem_offset.ok_or(ErrUnspec)?;

        let addr = shm_region.host_addr + shmem_offset;

        let ret = unsafe {
            libc::mmap(
                addr as *mut libc::c_void,
                resource.size as usize,
                libc::PROT_NONE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
                -1,
                0_i64,
            )
        };
        if ret == libc::MAP_FAILED {
            panic!("UNMAP failed");
        }

        resource.shmem_offset = None;

        Ok(OkNoData)
    }

    fn get_event_poll_fd(&self) -> Option<EventFd> {
        self.rutabaga.poll_descriptor().map(|fd| {
            // SAFETY: Safe, the fd should be valid, because Rutabaga guarantees it.
            // into_raw_descriptor() returns a RawFd and makes sure SafeDescriptor::drop doesn't run.
            unsafe { EventFd::from_raw_fd(fd.into_raw_descriptor()) }
        })
    }

    fn event_poll(&self) {
        self.rutabaga.event_poll()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{RutabagaVirtioGpu, VirtioGpu, VirtioGpuResource, VirtioGpuRing, VirtioShmRegion};
    use rutabaga_gfx::{
        ResourceCreateBlob, RutabagaBuilder, RutabagaComponentType, RutabagaHandler,
    };
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    fn new_2d() -> RutabagaVirtioGpu {
        let rutabaga = RutabagaBuilder::new(RutabagaComponentType::Rutabaga2D, 0)
            .build(RutabagaHandler::new(|_| {}), None)
            .unwrap();
        RutabagaVirtioGpu {
            rutabaga,
            resources: Default::default(),
            fence_state: Arc::new(Mutex::new(Default::default())),
            scanouts: Default::default(),
        }
    }

    #[test]
    fn test_gpu_backend_success() {
        let mut virtio_gpu = new_2d();
        virtio_gpu.get_capset(0, 0).unwrap();
        virtio_gpu.process_fence(VirtioGpuRing::Global, 0, 0, 0);
    }

    #[test]
    fn test_gpu_backend_failure() {
        let mut virtio_gpu = new_2d();

        virtio_gpu.get_capset_info(0).unwrap_err();
        let resource_create_blob = ResourceCreateBlob::default();
        let vecs = vec![(GuestAddress(0), 10)];
        let mem = &GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        virtio_gpu
            .resource_create_blob(1, 1, resource_create_blob, vecs, mem)
            .unwrap_err();

        let shm_region = VirtioShmRegion::default();
        let resource = VirtioGpuResource::default();
        virtio_gpu.resources.insert(1, resource);
        virtio_gpu.resource_map_blob(1, &shm_region, 0).unwrap_err();
        virtio_gpu.resource_unmap_blob(1, &shm_region).unwrap_err();
        let mut cmd_buf = vec![0; 10];
        let fence_ids: Vec<u64> = Vec::with_capacity(0);
        virtio_gpu
            .submit_command(0, &mut cmd_buf[..], &fence_ids)
            .unwrap_err();
    }
}
