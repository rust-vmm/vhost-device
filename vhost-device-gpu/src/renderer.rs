// Copyright 2025 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use rutabaga_gfx::RutabagaFence;
use vhost::vhost_user::gpu_message::{VhostUserGpuCursorPos, VhostUserGpuEdidRequest};
use vm_memory::{GuestAddress, GuestMemoryMmap, VolatileSlice};
use vmm_sys_util::eventfd::EventFd;

use crate::{
    gpu_types::{ResourceCreate3d, Transfer3DDesc, VirtioGpuRing},
    protocol::{virtio_gpu_rect, VirtioGpuResult},
};

/// Trait defining the interface for GPU renderers.
pub trait Renderer: Send + Sync {
    fn resource_create_3d(&mut self, resource_id: u32, req: ResourceCreate3d) -> VirtioGpuResult;
    fn unref_resource(&mut self, resource_id: u32) -> VirtioGpuResult;
    fn transfer_write(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        req: Transfer3DDesc,
    ) -> VirtioGpuResult;
    fn transfer_write_2d(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        req: Transfer3DDesc,
    ) -> VirtioGpuResult;
    fn transfer_read(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        req: Transfer3DDesc,
        buf: Option<VolatileSlice>,
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
    fn move_cursor(&mut self, resource_id: u32, cursor: VhostUserGpuCursorPos) -> VirtioGpuResult;
    fn resource_assign_uuid(&self, resource_id: u32) -> VirtioGpuResult;
    fn get_capset_info(&self, index: u32) -> VirtioGpuResult;
    fn get_capset(&self, capset_id: u32, version: u32) -> VirtioGpuResult;
    fn create_context(
        &mut self,
        ctx_id: u32,
        context_init: u32,
        context_name: Option<&str>,
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
    fn create_fence(&mut self, rutabaga_fence: RutabagaFence) -> VirtioGpuResult;
    fn process_fence(
        &mut self,
        ring: VirtioGpuRing,
        fence_id: u64,
        desc_index: u16,
        len: u32,
    ) -> bool;
    fn get_event_poll_fd(&self) -> Option<EventFd>;
    fn event_poll(&self);
    fn force_ctx_0(&self);
    fn display_info(&self) -> VirtioGpuResult;
    fn get_edid(&self, edid_req: VhostUserGpuEdidRequest) -> VirtioGpuResult;
    fn set_scanout(
        &mut self,
        scanout_id: u32,
        resource_id: u32,
        rect: virtio_gpu_rect,
    ) -> VirtioGpuResult;
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
}
