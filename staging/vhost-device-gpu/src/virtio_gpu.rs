// Copyright 2024 Red Hat Inc
// Copyright 2019 The ChromiumOS Authors
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    collections::BTreeMap,
    io::IoSliceMut,
    os::fd::FromRawFd,
    result::Result,
    sync::{Arc, Mutex},
};

use libc::c_void;
use log::{debug, error, trace, warn};
use rutabaga_gfx::{
    ResourceCreate3D, ResourceCreateBlob, Rutabaga, RutabagaBuilder, RutabagaComponentType,
    RutabagaFence, RutabagaFenceHandler, RutabagaIntoRawDescriptor, RutabagaIovec, Transfer3D,
};
use vhost::vhost_user::{
    gpu_message::{
        VhostUserGpuCursorPos, VhostUserGpuCursorUpdate, VhostUserGpuEdidRequest,
        VhostUserGpuScanout, VhostUserGpuUpdate,
    },
    GpuBackend,
};
use vhost_user_backend::{VringRwLock, VringT};
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap, VolatileSlice};
use vmm_sys_util::eventfd::EventFd;

use crate::{
    device::Error,
    protocol::{
        virtio_gpu_rect, GpuResponse,
        GpuResponse::{
            ErrInvalidParameter, ErrInvalidResourceId, ErrInvalidScanoutId, ErrUnspec, OkCapset,
            OkCapsetInfo, OkDisplayInfo, OkEdid, OkNoData, OkResourcePlaneInfo,
        },
        GpuResponsePlaneInfo, VirtioGpuResult, VIRTIO_GPU_FLAG_INFO_RING_IDX,
        VIRTIO_GPU_MAX_SCANOUTS,
    },
    GpuConfig, GpuMode,
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
            base: slice.ptr_guard_mut().as_ptr().cast::<c_void>(),
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
            x: r.x.into(),
            y: r.y.into(),
            width: r.width.into(),
            height: r.height.into(),
        }
    }
}

#[cfg_attr(test, mockall::automock)]
// We need to specify some lifetimes explicitly, for mockall::automock attribute to compile
#[allow(clippy::needless_lifetimes)]
pub trait VirtioGpu {
    /// Uses the hypervisor to unmap the blob resource.
    fn resource_unmap_blob(&mut self, resource_id: u32) -> VirtioGpuResult;

    /// Uses the hypervisor to map the rutabaga blob resource.
    ///
    /// When sandboxing is disabled, `external_blob` is unset and opaque fds are
    /// mapped by rutabaga as `ExternalMapping`.
    /// When sandboxing is enabled, `external_blob` is set and opaque fds must
    /// be mapped in the hypervisor process by Vulkano using metadata
    /// provided by `Rutabaga::vulkan_info()`.
    fn resource_map_blob(&mut self, resource_id: u32, offset: u64) -> VirtioGpuResult;

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

    /// Creates a fence with the `RutabagaFence` that can be used to determine
    /// when the previous command completed.
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

    /// Gets the list of supported display resolutions
    fn display_info(&self) -> VirtioGpuResult;

    /// Gets the EDID for the specified scanout ID. If that scanout is not
    /// enabled, it would return the EDID of a default display.
    fn get_edid(&self, edid_req: VhostUserGpuEdidRequest) -> VirtioGpuResult;

    /// Sets the given resource id as the source of scanout to the display.
    fn set_scanout(
        &mut self,
        scanout_id: u32,
        resource_id: u32,
        rect: Rectangle,
    ) -> VirtioGpuResult;

    /// Creates a 3D resource with the given properties and `resource_id`.
    fn resource_create_3d(
        &mut self,
        resource_id: u32,
        resource_create_3d: ResourceCreate3D,
    ) -> VirtioGpuResult;

    /// Releases guest kernel reference on the resource.
    fn unref_resource(&mut self, resource_id: u32) -> VirtioGpuResult;

    /// If the resource is the scanout resource, flush it to the display.
    fn flush_resource(&mut self, resource_id: u32, rect: Rectangle) -> VirtioGpuResult;

    /// Copies data to host resource from the attached iovecs. Can also be used
    /// to flush caches.
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
    fn transfer_read<'a>(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3D,
        buf: Option<VolatileSlice<'a>>,
    ) -> VirtioGpuResult;

    /// Attaches backing memory to the given resource, represented by a `Vec` of
    /// `(address, size)` tuples in the guest's physical address space.
    /// Converts to `RutabagaIovec` from the memory mapping.
    fn attach_backing(
        &mut self,
        resource_id: u32,
        mem: &GuestMemoryMmap,
        vecs: Vec<(GuestAddress, usize)>,
    ) -> VirtioGpuResult;

    /// Detaches any previously attached iovecs from the resource.
    fn detach_backing(&mut self, resource_id: u32) -> VirtioGpuResult;

    /// Updates the cursor's memory to the given `resource_id`, and sets its
    /// position to the given coordinates.
    fn update_cursor(
        &mut self,
        resource_id: u32,
        cursor_pos: VhostUserGpuCursorPos,
        hot_x: u32,
        hot_y: u32,
    ) -> VirtioGpuResult;

    /// Moves the cursor's position to the given coordinates.
    fn move_cursor(&mut self, resource_id: u32, cursor: VhostUserGpuCursorPos) -> VirtioGpuResult;

    /// Returns a uuid for the resource.
    fn resource_assign_uuid(&self, resource_id: u32) -> VirtioGpuResult;

    /// Gets rutabaga's capset information associated with `index`.
    fn get_capset_info(&self, index: u32) -> VirtioGpuResult;

    /// Gets a capset from rutabaga.
    fn get_capset(&self, capset_id: u32, version: u32) -> VirtioGpuResult;

    /// Creates a rutabaga context.
    fn create_context<'a>(
        &mut self,
        ctx_id: u32,
        context_init: u32,
        context_name: Option<&'a str>,
    ) -> VirtioGpuResult;

    /// Get an `EventFd` descriptor, that signals when to call `event_poll`.
    fn get_event_poll_fd(&self) -> Option<EventFd>;

    /// Polls the Rutabaga backend.
    fn event_poll(&self);
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

    const fn has_any_enabled(self) -> bool {
        self.0 != 0
    }

    fn iter_enabled(self) -> impl Iterator<Item = u32> {
        (0..VIRTIO_GPU_MAX_SCANOUTS).filter(move |i| ((self.0 >> i) & 1) == 1)
    }
}

#[derive(Default, Copy, Clone)]
pub struct VirtioGpuResource {
    id: u32,
    width: u32,
    height: u32,
    /// Stores information about which scanouts are associated with the given
    /// resource. Resource could be used for multiple scanouts (the displays
    /// are mirrored).
    scanouts: AssociatedScanouts,
}

impl VirtioGpuResource {
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

impl VirtioGpuResource {
    /// Creates a new `VirtioGpuResource` with 2D/3D metadata
    pub fn new(resource_id: u32, width: u32, height: u32) -> Self {
        Self {
            id: resource_id,
            width,
            height,
            scanouts: AssociatedScanouts::default(),
        }
    }
}

pub struct VirtioGpuScanout {
    resource_id: u32,
}

pub struct RutabagaVirtioGpu {
    pub(crate) rutabaga: Rutabaga,
    pub(crate) gpu_backend: GpuBackend,
    pub(crate) resources: BTreeMap<u32, VirtioGpuResource>,
    pub(crate) fence_state: Arc<Mutex<FenceState>>,
    pub(crate) scanouts: [Option<VirtioGpuScanout>; VIRTIO_GPU_MAX_SCANOUTS as usize],
}

const READ_RESOURCE_BYTES_PER_PIXEL: u32 = 4;

impl RutabagaVirtioGpu {
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

    fn configure_rutabaga_builder(gpu_config: &GpuConfig) -> RutabagaBuilder {
        let component = match gpu_config.gpu_mode() {
            GpuMode::VirglRenderer => RutabagaComponentType::VirglRenderer,
            #[cfg(feature = "gfxstream")]
            GpuMode::Gfxstream => RutabagaComponentType::Gfxstream,
        };

        RutabagaBuilder::new(component, gpu_config.capsets().bits())
            .set_use_egl(gpu_config.flags().use_egl)
            .set_use_glx(gpu_config.flags().use_glx)
            .set_use_gles(gpu_config.flags().use_gles)
            .set_use_surfaceless(gpu_config.flags().use_surfaceless)
            // Since vhost-user-gpu is out-of-process this is the only type of blob resource that
            // could work, so this is always enabled
            .set_use_external_blob(true)
    }

    pub fn new(queue_ctl: &VringRwLock, gpu_config: &GpuConfig, gpu_backend: GpuBackend) -> Self {
        let fence_state = Arc::new(Mutex::new(FenceState::default()));
        let fence = Self::create_fence_handler(queue_ctl.clone(), fence_state.clone());
        let rutabaga = Self::configure_rutabaga_builder(gpu_config)
            .build(fence, None)
            .expect("Rutabaga initialization failed!");

        Self {
            rutabaga,
            gpu_backend,
            resources: BTreeMap::default(),
            fence_state,
            scanouts: Default::default(),
        }
    }

    fn result_from_query(&self, resource_id: u32) -> GpuResponse {
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
        resource: VirtioGpuResource,
        output: &mut [u8],
    ) -> Result<(), String> {
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

        // ctx_id 0 seems to be special, crosvm uses it for this purpose too
        self.rutabaga
            .transfer_read(0, resource.id, transfer, Some(IoSliceMut::new(output)))
            .map_err(|e| format!("{e}"))?;

        Ok(())
    }
}

impl VirtioGpu for RutabagaVirtioGpu {
    fn force_ctx_0(&self) {
        self.rutabaga.force_ctx_0();
    }

    fn display_info(&self) -> VirtioGpuResult {
        let backend_display_info = self.gpu_backend.get_display_info().map_err(|e| {
            error!("Failed to get display info: {e:?}");
            ErrUnspec
        })?;

        let display_info = backend_display_info
            .pmodes
            .iter()
            .map(|display| (display.r.width, display.r.height, display.enabled == 1))
            .collect::<Vec<_>>();

        debug!("Displays: {:?}", display_info);
        Ok(OkDisplayInfo(display_info))
    }

    fn get_edid(&self, edid_req: VhostUserGpuEdidRequest) -> VirtioGpuResult {
        debug!("edid request: {edid_req:?}");
        let edid = self.gpu_backend.get_edid(&edid_req).map_err(|e| {
            error!("Failed to get edid from frontend: {}", e);
            ErrUnspec
        })?;

        Ok(OkEdid {
            blob: Box::from(&edid.edid[..edid.size as usize]),
        })
    }

    fn set_scanout(
        &mut self,
        scanout_id: u32,
        resource_id: u32,
        rect: Rectangle,
    ) -> VirtioGpuResult {
        let scanout = self
            .scanouts
            .get_mut(scanout_id as usize)
            .ok_or(ErrInvalidScanoutId)?;

        // If a resource is already associated with this scanout, make sure to disable
        // this scanout for that resource
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
            self.gpu_backend
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

        // QEMU doesn't like (it lags) when we call set_scanout while the scanout is
        // enabled
        if scanout.is_none() {
            self.gpu_backend
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
        );

        debug_assert!(
            !self.resources.contains_key(&resource_id),
            "Resource ID {resource_id} already exists in the resources map."
        );

        // Rely on rutabaga to check for duplicate resource ids.
        self.resources.insert(resource_id, resource);
        Ok(self.result_from_query(resource_id))
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
        self.rutabaga.unref_resource(resource_id)?;
        Ok(OkNoData)
    }

    /// If the resource is the scanout resource, flush it to the display.
    fn flush_resource(&mut self, resource_id: u32, _rect: Rectangle) -> VirtioGpuResult {
        if resource_id == 0 {
            return Ok(OkNoData);
        }

        let resource = *self
            .resources
            .get(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        for scanout_id in resource.scanouts.iter_enabled() {
            let resource_size = resource.calculate_size().map_err(|e| {
                error!(
                    "Resource {id} size calculation failed: {e}",
                    id = resource.id
                );
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
            if let Err(e) = self.read_2d_resource(resource, &mut data) {
                log::error!("Failed to read resource {resource_id} for scanout {scanout_id}: {e}");
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
        let rutabaga_iovecs = sglist_to_rutabaga_iovecs(&vecs[..], mem).map_err(|()| ErrUnspec)?;
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
        cursor_pos: VhostUserGpuCursorPos,
        hot_x: u32,
        hot_y: u32,
    ) -> VirtioGpuResult {
        const CURSOR_WIDTH: u32 = 64;
        const CURSOR_HEIGHT: u32 = 64;

        let mut data = Box::new(
            [0; READ_RESOURCE_BYTES_PER_PIXEL as usize
                * CURSOR_WIDTH as usize
                * CURSOR_HEIGHT as usize],
        );

        let cursor_resource = self
            .resources
            .get(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        if cursor_resource.width != CURSOR_WIDTH || cursor_resource.height != CURSOR_HEIGHT {
            error!("Cursor resource has invalid dimensions");
            return Err(ErrInvalidParameter);
        }

        self.read_2d_resource(*cursor_resource, &mut data[..])
            .map_err(|e| {
                error!("Failed to read resource of cursor: {e}");
                ErrUnspec
            })?;

        let cursor_update = VhostUserGpuCursorUpdate {
            pos: cursor_pos,
            hot_x,
            hot_y,
        };

        self.gpu_backend
            .cursor_update(&cursor_update, &data)
            .map_err(|e| {
                error!("Failed to update cursor pos from frontend: {}", e);
                ErrUnspec
            })?;

        Ok(OkNoData)
    }

    fn move_cursor(&mut self, resource_id: u32, cursor: VhostUserGpuCursorPos) -> VirtioGpuResult {
        if resource_id == 0 {
            self.gpu_backend.cursor_pos_hide(&cursor).map_err(|e| {
                error!("Failed to set cursor pos from frontend: {}", e);
                ErrUnspec
            })?;
        } else {
            self.gpu_backend.cursor_pos(&cursor).map_err(|e| {
                error!("Failed to set cursor pos from frontend: {}", e);
                ErrUnspec
            })?;
        }

        Ok(OkNoData)
    }

    fn resource_assign_uuid(&self, _resource_id: u32) -> VirtioGpuResult {
        error!("Not implemented: resource_assign_uuid");
        Err(ErrUnspec)
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
        _ctx_id: u32,
        _resource_id: u32,
        _resource_create_blob: ResourceCreateBlob,
        _vecs: Vec<(GuestAddress, usize)>,
        _mem: &GuestMemoryMmap,
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

    fn get_event_poll_fd(&self) -> Option<EventFd> {
        self.rutabaga.poll_descriptor().map(|fd| {
            // SAFETY: Safe, the fd should be valid, because Rutabaga guarantees it.
            // into_raw_descriptor() returns a RawFd and makes sure SafeDescriptor::drop
            // doesn't run.
            unsafe { EventFd::from_raw_fd(fd.into_raw_descriptor()) }
        })
    }

    fn event_poll(&self) {
        self.rutabaga.event_poll();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::net::UnixStream,
        sync::{Arc, Mutex},
    };

    use assert_matches::assert_matches;
    use rusty_fork::rusty_fork_test;
    use rutabaga_gfx::{
        RutabagaFence, RutabagaHandler, RUTABAGA_PIPE_BIND_RENDER_TARGET, RUTABAGA_PIPE_TEXTURE_2D,
    };

    use super::*;
    use crate::{protocol::VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM, GpuCapset, GpuFlags};

    const CREATE_RESOURCE_2D_720P: ResourceCreate3D = ResourceCreate3D {
        target: RUTABAGA_PIPE_TEXTURE_2D,
        format: VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM,
        bind: RUTABAGA_PIPE_BIND_RENDER_TARGET,
        width: 1280,
        height: 720,
        depth: 1,
        array_size: 1,
        last_level: 0,
        nr_samples: 0,
        flags: 0,
    };

    const CREATE_RESOURCE_CURSOR: ResourceCreate3D = ResourceCreate3D {
        target: RUTABAGA_PIPE_TEXTURE_2D,
        format: VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM,
        bind: RUTABAGA_PIPE_BIND_RENDER_TARGET,
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

    fn new_gpu() -> RutabagaVirtioGpu {
        let config = GpuConfig::new(
            GpuMode::VirglRenderer,
            Some(GpuCapset::VIRGL | GpuCapset::VIRGL2),
            GpuFlags::default(),
        )
        .unwrap();
        let builder = RutabagaVirtioGpu::configure_rutabaga_builder(&config);
        let rutabaga = builder.build(RutabagaHandler::new(|_| {}), None).unwrap();
        RutabagaVirtioGpu {
            rutabaga,
            gpu_backend: dummy_gpu_backend(),
            resources: BTreeMap::default(),
            fence_state: Arc::new(Mutex::new(FenceState::default())),
            scanouts: Default::default(),
        }
    }

    #[test]
    fn test_virtio_gpu_associated_scanouts() {
        use super::AssociatedScanouts;

        let mut scanouts = AssociatedScanouts::default();

        assert!(!scanouts.has_any_enabled());
        assert_eq!(scanouts.iter_enabled().next(), None);

        scanouts.enable(1);
        assert!(scanouts.has_any_enabled());
        scanouts.disable(1);
        assert!(!scanouts.has_any_enabled());

        (0..VIRTIO_GPU_MAX_SCANOUTS).for_each(|scanout| scanouts.enable(scanout));
        assert!(scanouts.has_any_enabled());
        assert_eq!(
            scanouts.iter_enabled().collect::<Vec<u32>>(),
            (0..VIRTIO_GPU_MAX_SCANOUTS).collect::<Vec<u32>>()
        );

        (0..VIRTIO_GPU_MAX_SCANOUTS)
            .filter(|&i| i % 2 == 0)
            .for_each(|scanout| scanouts.disable(scanout));
        assert_eq!(
            scanouts.iter_enabled().collect::<Vec<u32>>(),
            (1..VIRTIO_GPU_MAX_SCANOUTS)
                .step_by(2)
                .collect::<Vec<u32>>()
        );

        (0..VIRTIO_GPU_MAX_SCANOUTS)
            .filter(|&i| i % 2 != 0)
            .for_each(|scanout| scanouts.disable(scanout));
        assert!(!scanouts.has_any_enabled());
    }

    rusty_fork_test! {
        #[test]
        fn test_update_cursor_fails() {
            let mut virtio_gpu = new_gpu();

            let cursor_pos = VhostUserGpuCursorPos {
                scanout_id: 1,
                x: 123,
                y: 123,
            };

            // The resource doesn't exist
            let result = virtio_gpu.update_cursor(1, cursor_pos, 0, 0);
            assert_matches!(result, Err(ErrInvalidResourceId));

            // Create a resource
            virtio_gpu.resource_create_3d(1, CREATE_RESOURCE_2D_720P).unwrap();

            // The resource exists, but the dimensions are wrong
            let result = virtio_gpu.update_cursor(1, cursor_pos, 0, 0);
            assert_matches!(result, Err(ErrInvalidParameter));

            // Create a resource with correct cursor dimensions
            let cursor_resource_id = 2;
            virtio_gpu
                .resource_create_3d(
                    cursor_resource_id,
                    CREATE_RESOURCE_CURSOR).unwrap();

            // The resource exists, the dimensions are correct but the test
            // fails to update cursor position from frontend
            let result = virtio_gpu.update_cursor(cursor_resource_id, cursor_pos, 5, 5);
            assert_matches!(result, Err(ErrUnspec));
        }

        #[test]
        fn test_move_cursor_fails() {
            let mut virtio_gpu = new_gpu();
            let cursor_pos = VhostUserGpuCursorPos {
                scanout_id: 1,
                x: 123,
                y: 123,
            };

            // No resources exists, but the test fails to set cursor position from frontend
            let result = virtio_gpu.move_cursor(0, cursor_pos);
            assert_matches!(result, Err(ErrUnspec));

            // Resources exists, but the test fails to set cursor position from frontend
            let result = virtio_gpu.move_cursor(1, cursor_pos);
            assert_matches!(result, Err(ErrUnspec));
        }

        #[test]
        fn test_process_fence() {
            let mut virtio_gpu = new_gpu();
            let fence = RutabagaFence {
                flags: 0,
                fence_id: 0,
                ctx_id: 1,
                ring_idx: 0,
            };

            // Test creating a fence with the `RutabagaFence` that can be used to determine when the previous
            // command completed.
            let result = virtio_gpu.create_fence(fence);
            assert_matches!(result, Ok(OkNoData));

            // Test processing gpu fence: If the fence has already been signaled return true
            let ring = VirtioGpuRing::Global;
            let result = virtio_gpu.process_fence(ring.clone(), 0, 0, 0);
            assert_matches!(result, true);

            // Test processing gpu fence: If the fence has not yet been signaled return false
            let result = virtio_gpu.process_fence(ring, 1, 0, 0);
            assert_matches!(result, false);
        }

        #[test]
        fn test_event_poll() {
            let virtio_gpu = new_gpu();
            virtio_gpu.event_poll();
        }

        #[test]
        fn test_create_and_unref_resources() {
            let mut virtio_gpu = new_gpu();

            // No resources exists, cannot unref anything:
            assert!(virtio_gpu.resources.is_empty());
            let result = virtio_gpu.unref_resource(0);
            assert_matches!(result, Err(_));

            // Create a resource
            let result = virtio_gpu.resource_create_3d(1, CREATE_RESOURCE_2D_720P);
            assert_matches!(result, Ok(_));
            assert_eq!(virtio_gpu.resources.len(), 1);

            // Unref the created resource
            let result = virtio_gpu.unref_resource(1);
            assert_matches!(result, Ok(_));
            assert!(virtio_gpu.resources.is_empty());
        }

        #[test]
        fn test_gpu_capset() {
            let virtio_gpu = new_gpu();

            let capset_info = virtio_gpu.get_capset_info(0);
            assert_matches!(capset_info, Ok(OkCapsetInfo { .. }));

            let Ok(OkCapsetInfo {capset_id, version, ..}) = capset_info else {
                unreachable!("Response should have been checked by assert")
            };

            let capset_info = virtio_gpu.get_capset(capset_id, version);
            assert_matches!(capset_info, Ok(OkCapset(_)));
        }

        #[test]
        fn test_gpu_submit_command_fails() {
            let mut virtio_gpu = new_gpu();
            let mut cmd_buf = [0; 10];
            let fence_ids: Vec<u64> = Vec::with_capacity(0);
            virtio_gpu
                .submit_command(1, &mut cmd_buf[..], &fence_ids)
            .unwrap_err();
        }
    }
}
