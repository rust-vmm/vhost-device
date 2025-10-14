// src/backend/common.rs

use std::sync::{Arc, Mutex};

use log::{debug, error};
use vhost::vhost_user::{
    gpu_message::{VhostUserGpuCursorPos, VhostUserGpuCursorUpdate, VhostUserGpuEdidRequest},
    GpuBackend,
};

use crate::{
    gpu_types::{FenceDescriptor, FenceState, VirtioGpuRing},
    protocol::{
        GpuResponse,
        GpuResponse::{ErrUnspec, OkDisplayInfo, OkEdid, OkNoData},
        VirtioGpuResult, VIRTIO_GPU_MAX_SCANOUTS,
    },
};

#[derive(Debug, Clone)]
pub struct VirtioGpuScanout {
    pub resource_id: u32,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct AssociatedScanouts(u32);

impl AssociatedScanouts {
    pub const fn enable(&mut self, scanout_id: u32) {
        self.0 |= 1 << scanout_id;
    }

    pub const fn disable(&mut self, scanout_id: u32) {
        self.0 ^= 1 << scanout_id;
    }

    pub const fn has_any_enabled(self) -> bool {
        self.0 != 0
    }

    pub fn iter_enabled(self) -> impl Iterator<Item = u32> {
        (0..VIRTIO_GPU_MAX_SCANOUTS).filter(move |i| ((self.0 >> i) & 1) == 1)
    }
}

pub const VHOST_USER_GPU_MAX_CURSOR_DATA_SIZE: usize = 16384; // 4*4*1024
pub const READ_RESOURCE_BYTES_PER_PIXEL: usize = 4;

#[derive(Copy, Clone, Debug, Default)]
pub struct CursorConfig {
    pub width: u32,
    pub height: u32,
}

impl CursorConfig {
    pub const fn expected_buffer_len(&self) -> usize {
        self.width as usize * self.height as usize * READ_RESOURCE_BYTES_PER_PIXEL
    }
}

pub fn common_display_info(gpu_backend: &GpuBackend) -> VirtioGpuResult {
    let backend_display_info = gpu_backend.get_display_info().map_err(|e| {
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

pub fn common_get_edid(
    gpu_backend: &GpuBackend,
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

pub fn common_process_fence(
    fence_state: &Arc<Mutex<FenceState>>,
    ring: VirtioGpuRing,
    fence_id: u64,
    desc_index: u16,
    len: u32,
) -> bool {
    // In case the fence is signaled immediately after creation, don't add a return
    // FenceDescriptor.
    let mut fence_state = fence_state.lock().unwrap();
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

pub fn common_move_cursor(
    gpu_backend: &GpuBackend,
    resource_id: u32,
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

    Ok(GpuResponse::OkNoData)
}

pub fn common_update_cursor(
    gpu_backend: &GpuBackend,
    cursor_pos: VhostUserGpuCursorPos,
    hot_x: u32,
    hot_y: u32,
    data: Box<[u8]>,
    config: CursorConfig,
) -> VirtioGpuResult {
    let expected_len = config.expected_buffer_len();

    if data.len() != expected_len {
        error!(
            "Mismatched cursor data size: expected {}, got {}",
            expected_len,
            data.len()
        );
        return Err(ErrUnspec);
    }

    let data_ref: &[u8] = &data;
    let cursor_update = VhostUserGpuCursorUpdate {
        pos: cursor_pos,
        hot_x,
        hot_y,
    };
    let mut padded_data = [0u8; VHOST_USER_GPU_MAX_CURSOR_DATA_SIZE];
    padded_data[..data_ref.len()].copy_from_slice(data_ref);

    gpu_backend
        .cursor_update(&cursor_update, &padded_data)
        .map_err(|e| {
            error!("Failed to update cursor: {}", e);
            ErrUnspec
        })?;

    Ok(OkNoData)
}

pub fn common_set_scanout_disable(scanouts: &mut [Option<VirtioGpuScanout>], scanout_idx: usize) {
    scanouts[scanout_idx] = None;
    debug!("Disabling scanout scanout_id={scanout_idx}");
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::net::UnixStream,
        sync::{Arc, Mutex},
    };

    use assert_matches::assert_matches;

    use super::*;
    use crate::{
        gpu_types::VirtioGpuRing,
        protocol::{GpuResponse::ErrUnspec, VIRTIO_GPU_MAX_SCANOUTS},
    };

    const CURSOR_POS: VhostUserGpuCursorPos = VhostUserGpuCursorPos {
        scanout_id: 0,
        x: 0,
        y: 0,
    };
    const CURSOR_CONFIG: CursorConfig = CursorConfig {
        width: 4,
        height: 4,
    };
    const BYTES_PER_PIXEL: usize = 4;
    const EXPECTED_LEN: usize =
        (CURSOR_CONFIG.width as usize) * (CURSOR_CONFIG.height as usize) * BYTES_PER_PIXEL;

    fn dummy_gpu_backend() -> GpuBackend {
        let (_, backend) = UnixStream::pair().unwrap();
        GpuBackend::from_stream(backend)
    }

    // AssociatedScanouts
    // Test that enabling, disabling, iterating, and checking any enabled works as
    // expected.
    #[test]
    fn associated_scanouts_enable_disable_iter_and_any() {
        let mut assoc = AssociatedScanouts::default();

        // No scanouts initially
        assert!(!assoc.has_any_enabled());
        assert_eq!(assoc.iter_enabled().count(), 0);

        // Enable a couple
        assoc.enable(0);
        assoc.enable(3);
        assert!(assoc.has_any_enabled());
        assert_eq!(assoc.iter_enabled().collect::<Vec<u32>>(), vec![0u32, 3u32]);

        // Disable one
        assoc.disable(3);
        assert!(assoc.has_any_enabled());
        assert_eq!(assoc.iter_enabled().collect::<Vec<u32>>(), vec![0u32]);

        // Disable last
        assoc.disable(0);
        assert!(!assoc.has_any_enabled());
        assert_eq!(assoc.iter_enabled().count(), 0);
    }

    // CursorConfig
    // Test that expected_buffer_len computes the correct size.
    #[test]
    fn cursor_config_expected_len() {
        let cfg = CursorConfig {
            width: 64,
            height: 64,
        };
        assert_eq!(
            cfg.expected_buffer_len(),
            64 * 64 * READ_RESOURCE_BYTES_PER_PIXEL
        );
    }

    // Update cursor
    // Test that updating the cursor with mismatched data size fails.
    #[test]
    fn update_cursor_mismatched_data_size_fails() {
        let gpu_backend = dummy_gpu_backend();

        // Data has length 1 (expected is 64)
        let bad_data = Box::from([0u8]);

        let result = common_update_cursor(&gpu_backend, CURSOR_POS, 0, 0, bad_data, CURSOR_CONFIG);

        assert_matches!(result, Err(ErrUnspec), "Should fail due to mismatched size");
    }

    // Test that updating the cursor with correct data size but backend failure
    // returns ErrUnspec.
    #[test]
    fn update_cursor_backend_failure() {
        let gpu_backend = dummy_gpu_backend();

        // Data has the correct length (64 bytes)
        let correct_data = vec![0u8; EXPECTED_LEN].into_boxed_slice();

        let result =
            common_update_cursor(&gpu_backend, CURSOR_POS, 0, 0, correct_data, CURSOR_CONFIG);

        assert_matches!(
            result,
            Err(ErrUnspec),
            "Should fail due to failure to update cursor"
        );
    }

    // Fence handling
    // Test that processing a fence pushes a descriptor when the fence is new.
    #[test]
    fn process_fence_pushes_descriptor_when_new() {
        let fence_state = Arc::new(Mutex::new(FenceState::default()));
        let ring = VirtioGpuRing::Global;

        // Clone because common_process_fence takes ownership of ring
        let ret = common_process_fence(&fence_state, ring.clone(), 42, 7, 512);
        assert!(!ret, "New fence should not complete immediately");

        let st = fence_state.lock().unwrap();
        assert_eq!(st.descs.len(), 1);
        assert_eq!(st.descs[0].ring, ring);
        assert_eq!(st.descs[0].fence_id, 42);
        assert_eq!(st.descs[0].desc_index, 7);
        assert_eq!(st.descs[0].len, 512);
    }

    // Test that processing a fence that is already completed returns true
    // immediately.
    #[test]
    fn process_fence_immediately_completes_when_already_done() {
        let ring = VirtioGpuRing::Global;

        // Seed state so that ring's 100 is already completed.
        let mut seeded = FenceState::default();
        seeded.completed_fences.insert(ring.clone(), 100);
        let fence_state = Arc::new(Mutex::new(seeded));

        let ret = common_process_fence(&fence_state, ring, 100, 1, 4);
        assert!(ret, "already-completed fence should return true");

        let st = fence_state.lock().unwrap();
        assert!(st.descs.is_empty());
    }

    // Test that disabling a scanout clears the corresponding slot.
    #[test]
    fn set_scanout_disable_clears_slot() {
        const N: usize = VIRTIO_GPU_MAX_SCANOUTS as usize;
        let mut scanouts: [Option<VirtioGpuScanout>; N] = Default::default();

        scanouts[5] = Some(VirtioGpuScanout { resource_id: 123 });
        common_set_scanout_disable(&mut scanouts, 5);
        assert!(scanouts[5].is_none());
    }
}
