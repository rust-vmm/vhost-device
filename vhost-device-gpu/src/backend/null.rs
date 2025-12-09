// Null backend
// Copyright 2025 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use log::trace;
use rutabaga_gfx::RutabagaFence;
use vhost::vhost_user::{
    gpu_message::{VhostUserGpuCursorPos, VhostUserGpuEdidRequest},
    GpuBackend,
};
use vm_memory::{GuestAddress, GuestMemoryMmap, VolatileSlice};
use vmm_sys_util::eventfd::EventFd;

use crate::{
    gpu_types::{ResourceCreate3d, ResourceCreateBlob, Transfer3DDesc, VirtioGpuRing},
    protocol::{virtio_gpu_rect, GpuResponse, VirtioGpuResult},
    renderer::Renderer,
    GpuConfig,
};

pub struct NullAdapter {
    _gpu_backend: GpuBackend,
}

impl NullAdapter {
    pub fn new(
        _queue_ctl: &vhost_user_backend::VringRwLock,
        _config: &GpuConfig,
        _backend: vhost::vhost_user::Backend,
        gpu_backend: GpuBackend,
    ) -> Self {
        trace!("NullAdapter created");
        Self {
            _gpu_backend: gpu_backend,
        }
    }
}

impl Renderer for NullAdapter {
    fn resource_create_3d(
        &mut self,
        _resource_id: u32,
        _args: ResourceCreate3d,
    ) -> VirtioGpuResult {
        trace!("NullAdapter::resource_create_3d - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn unref_resource(&mut self, _resource_id: u32) -> VirtioGpuResult {
        trace!("NullAdapter::unref_resource - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn transfer_write(
        &mut self,
        _ctx_id: u32,
        _resource_id: u32,
        _transfer: Transfer3DDesc,
    ) -> VirtioGpuResult {
        trace!("NullAdapter::transfer_write - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn transfer_write_2d(
        &mut self,
        _ctx_id: u32,
        _resource_id: u32,
        _transfer: Transfer3DDesc,
    ) -> VirtioGpuResult {
        trace!("NullAdapter::transfer_write_2d - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn transfer_read(
        &mut self,
        _ctx_id: u32,
        _resource_id: u32,
        _transfer: Transfer3DDesc,
        _buf: Option<VolatileSlice>,
    ) -> VirtioGpuResult {
        trace!("NullAdapter::transfer_read - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn attach_backing(
        &mut self,
        _resource_id: u32,
        _mem: &GuestMemoryMmap,
        _vecs: Vec<(GuestAddress, usize)>,
    ) -> VirtioGpuResult {
        trace!("NullAdapter::attach_backing - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn detach_backing(&mut self, _resource_id: u32) -> VirtioGpuResult {
        trace!("NullAdapter::detach_backing - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn update_cursor(
        &mut self,
        _resource_id: u32,
        _cursor_pos: VhostUserGpuCursorPos,
        _hot_x: u32,
        _hot_y: u32,
    ) -> VirtioGpuResult {
        trace!("NullAdapter::update_cursor - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn move_cursor(
        &mut self,
        _resource_id: u32,
        _cursor: VhostUserGpuCursorPos,
    ) -> VirtioGpuResult {
        trace!("NullAdapter::move_cursor - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn resource_assign_uuid(&self, _resource_id: u32) -> VirtioGpuResult {
        trace!("NullAdapter::resource_assign_uuid - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn get_capset_info(&self, _capset_index: u32) -> VirtioGpuResult {
        trace!("NullAdapter::get_capset_info - no capsets");
        Ok(GpuResponse::OkNoData)
    }

    fn get_capset(&self, _capset_id: u32, _capset_version: u32) -> VirtioGpuResult {
        trace!("NullAdapter::get_capset - no capsets");
        Ok(GpuResponse::OkNoData)
    }

    fn create_context(
        &mut self,
        _ctx_id: u32,
        _context_init: u32,
        _context_name: Option<&str>,
    ) -> VirtioGpuResult {
        trace!("NullAdapter::create_context - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn destroy_context(&mut self, _ctx_id: u32) -> VirtioGpuResult {
        trace!("NullAdapter::destroy_context - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn context_attach_resource(&mut self, _ctx_id: u32, _resource_id: u32) -> VirtioGpuResult {
        trace!("NullAdapter::context_attach_resource - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn context_detach_resource(&mut self, _ctx_id: u32, _resource_id: u32) -> VirtioGpuResult {
        trace!("NullAdapter::context_detach_resource - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn submit_command(
        &mut self,
        _ctx_id: u32,
        _commands: &mut [u8],
        _fence_ids: &[u64],
    ) -> VirtioGpuResult {
        trace!("NullAdapter::submit_command - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn create_fence(&mut self, _rutabaga_fence: RutabagaFence) -> VirtioGpuResult {
        trace!("NullAdapter::create_fence - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn process_fence(
        &mut self,
        _ring: VirtioGpuRing,
        _fence_id: u64,
        _desc_index: u16,
        _len: u32,
    ) -> bool {
        trace!("NullAdapter::process_fence - no-op");
        true
    }

    fn get_event_poll_fd(&self) -> Option<EventFd> {
        trace!("NullAdapter::get_event_poll_fd - no-op");
        None
    }

    fn event_poll(&self) {
        trace!("NullAdapter::event_poll - no-op");
    }

    fn force_ctx_0(&self) {
        trace!("NullAdapter::force_ctx_0 - no-op");
    }

    fn display_info(&self) -> VirtioGpuResult {
        trace!("NullAdapter::display_info - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn get_edid(&self, _edid_req: VhostUserGpuEdidRequest) -> VirtioGpuResult {
        trace!("NullAdapter::get_edid - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn set_scanout(
        &mut self,
        _scanout_id: u32,
        _resource_id: u32,
        _rect: virtio_gpu_rect,
    ) -> VirtioGpuResult {
        trace!("NullAdapter::set_scanout - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn flush_resource(&mut self, _resource_id: u32, _rect: virtio_gpu_rect) -> VirtioGpuResult {
        trace!("NullAdapter::flush_resource - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn resource_create_blob(
        &mut self,
        _ctx_id: u32,
        _resource_create_blob: ResourceCreateBlob,
        _vecs: Vec<(vm_memory::GuestAddress, usize)>,
        _mem: &vm_memory::GuestMemoryMmap,
    ) -> VirtioGpuResult {
        trace!("NullAdapter::resource_create_blob - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn resource_map_blob(&mut self, _resource_id: u32, _offset: u64) -> VirtioGpuResult {
        trace!("NullAdapter::resource_map_blob - no-op");
        Ok(GpuResponse::OkNoData)
    }

    fn resource_unmap_blob(&mut self, _resource_id: u32) -> VirtioGpuResult {
        trace!("NullAdapter::resource_unmap_blob - no-op");
        Ok(GpuResponse::OkNoData)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;

    use vhost_user_backend::{VringRwLock, VringT};
    use vm_memory::{GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    use super::*;
    use crate::{GpuFlags, GpuMode};

    fn create_null_adapter() -> NullAdapter {
        let (stream1, stream2) = UnixStream::pair().unwrap();
        let backend = vhost::vhost_user::Backend::from_stream(stream1);
        let gpu_backend = GpuBackend::from_stream(stream2);
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem, 0x100).unwrap();
        let config = GpuConfig::new(GpuMode::Null, None, GpuFlags::default()).unwrap();

        NullAdapter::new(&vring, &config, backend, gpu_backend)
    }

    #[test]
    fn test_null_adapter_creation() {
        // Verify that NullAdapter can be successfully created
        let _adapter = create_null_adapter();
    }

    #[test]
    fn test_null_adapter_resource_operations() {
        let mut adapter = create_null_adapter();

        // Verify resource creation returns success without doing anything
        let resource_create = ResourceCreate3d {
            target: 2,
            format: 1,
            bind: 1,
            width: 640,
            height: 480,
            depth: 1,
            array_size: 1,
            last_level: 0,
            nr_samples: 0,
            flags: 0,
        };
        let result = adapter.resource_create_3d(1, resource_create);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));

        // Verify unreferencing a resource succeeds
        let result = adapter.unref_resource(1);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));

        // Verify attaching and detaching backing memory succeeds
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let result = adapter.attach_backing(1, &mem, vec![]);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));

        let result = adapter.detach_backing(1);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));
    }

    #[test]
    fn test_null_adapter_transfer_operations() {
        let mut adapter = create_null_adapter();
        let transfer = Transfer3DDesc::new_2d(0, 0, 640, 480, 0);

        // Verify 3D transfer write succeeds
        let result = adapter.transfer_write(0, 1, transfer);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));

        // Verify 2D transfer write succeeds
        let result = adapter.transfer_write_2d(0, 1, transfer);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));

        // Verify transfer read succeeds
        let result = adapter.transfer_read(0, 1, transfer, None);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));
    }

    #[test]
    fn test_null_adapter_context_operations() {
        let mut adapter = create_null_adapter();

        // Verify context creation succeeds
        let result = adapter.create_context(1, 0, Some("test"));
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));

        // Verify attaching a resource to a context succeeds
        let result = adapter.context_attach_resource(1, 1);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));

        // Verify detaching a resource from a context succeeds
        let result = adapter.context_detach_resource(1, 1);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));

        // Verify context destruction succeeds
        let result = adapter.destroy_context(1);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));
    }

    #[test]
    fn test_null_adapter_display_operations() {
        let mut adapter = create_null_adapter();

        // Verify getting display info succeeds
        let result = adapter.display_info();
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));

        // Verify getting EDID info succeeds
        let result = adapter.get_edid(VhostUserGpuEdidRequest { scanout_id: 0 });
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));

        // Verify setting scanout succeeds
        let result = adapter.set_scanout(0, 1, virtio_gpu_rect::default());
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));

        // Verify flushing a resource succeeds
        let result = adapter.flush_resource(1, virtio_gpu_rect::default());
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));
    }

    #[test]
    fn test_null_adapter_cursor_operations() {
        let mut adapter = create_null_adapter();
        let cursor_pos = VhostUserGpuCursorPos {
            scanout_id: 0,
            x: 0,
            y: 0,
        };

        // Verify updating cursor succeeds
        let result = adapter.update_cursor(1, cursor_pos, 0, 0);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));

        // Verify moving cursor succeeds
        let result = adapter.move_cursor(1, cursor_pos);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));
    }

    #[test]
    fn test_null_adapter_capset_operations() {
        let adapter = create_null_adapter();

        // Verify getting capset info returns success (null backend has no capsets)
        let result = adapter.get_capset_info(0);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));

        // Verify getting capset returns success (null backend has no capsets)
        let result = adapter.get_capset(0, 0);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));
    }

    #[test]
    fn test_null_adapter_command_operations() {
        let mut adapter = create_null_adapter();
        let mut commands = vec![0u8; 64];

        // Verify submitting commands succeeds
        let result = adapter.submit_command(1, &mut commands, &[]);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));
    }

    #[test]
    fn test_null_adapter_fence_operations() {
        let mut adapter = create_null_adapter();
        let fence = RutabagaFence {
            flags: 0,
            fence_id: 1,
            ctx_id: 0,
            ring_idx: 0,
        };

        // Verify creating a fence succeeds
        let result = adapter.create_fence(fence);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));

        // Verify processing fence returns true (fence is immediately ready in null
        // backend)
        let ready = adapter.process_fence(VirtioGpuRing::Global, 1, 0, 0);
        assert!(ready);
    }

    #[test]
    fn test_null_adapter_blob_operations() {
        let mut adapter = create_null_adapter();
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        // Verify blob resource creation succeeds
        let result = adapter.resource_create_blob(
            0,
            ResourceCreateBlob {
                resource_id: 1,
                blob_id: 1,
                blob_mem: 0,
                blob_flags: 0,
                size: 4096,
            },
            vec![],
            &mem,
        );
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));

        // Verify mapping blob resource succeeds
        let result = adapter.resource_map_blob(1, 0);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));

        // Verify unmapping blob resource succeeds
        let result = adapter.resource_unmap_blob(1);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));
    }

    #[test]
    fn test_null_adapter_misc_operations() {
        let adapter = create_null_adapter();

        // Verify assigning UUID to resource succeeds
        let result = adapter.resource_assign_uuid(1);
        assert!(matches!(result, Ok(GpuResponse::OkNoData)));

        // Verify no event poll fd is provided (null backend has no events)
        let event_fd = adapter.get_event_poll_fd();
        assert!(event_fd.is_none());

        // Verify event polling and force_ctx_0 don't panic (they're no-ops)
        adapter.event_poll();
        adapter.force_ctx_0();
    }
}
