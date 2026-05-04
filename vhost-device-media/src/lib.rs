// Copyright 2026 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod media_allocator;
mod media_backends;
pub mod vhu_media;
mod vhu_media_thread;
mod virtio;

use std::{path::PathBuf, sync::Arc};

use ::virtio_media::protocol::VirtioMediaDeviceConfig;
use log::debug;
use thiserror::Error as ThisError;
use vhost_user_backend::VhostUserDaemon;
use vhu_media::VuMediaBackend;
pub use vhu_media::{BackendType, VuMediaError};
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(any(feature = "simple-capture", feature = "ffmpeg"))]
const VIRTIO_V4L2_CARD_NAME_LEN: usize = 32;

/// V4L2 device types as defined by the V4L2 framework.
///
/// These correspond to the VFL_TYPE_* constants in the Linux kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V4l2DeviceType {
    Video = 0, // VFL_TYPE_VIDEO
    Vbi = 1,   // VFL_TYPE_VBI
    Radio = 2, // VFL_TYPE_RADIO
    Sdr = 3,   // VFL_TYPE_SDR
    Touch = 5, // VFL_TYPE_TOUCH
}

impl V4l2DeviceType {
    fn from_path(device_path: &std::path::Path) -> Self {
        // Resolve symlinks (e.g., /dev/v4l/by-id/...) to the actual device node
        let actual_path =
            std::fs::canonicalize(device_path).unwrap_or_else(|_| device_path.to_path_buf());

        let filename = actual_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        match filename {
            f if f.starts_with("video") => Self::Video,
            f if f.starts_with("vbi") => Self::Vbi,
            f if f.starts_with("radio") => Self::Radio,
            f if f.starts_with("swradio") || f.starts_with("sdr") => Self::Sdr,
            f if f.starts_with("touch") => Self::Touch,
            _ => Self::Video, // Default to VIDEO for unknown paths
        }
    }
}

#[derive(Debug, ThisError)]
/// Errors related to vhost-device-media daemon.
pub enum Error {
    #[error("Could not create backend: {0}")]
    CouldNotCreateBackend(vhu_media::VuMediaError),
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
}

#[derive(Debug, Eq, PartialEq)]
pub struct VuMediaConfig {
    pub socket_path: PathBuf,
    pub v4l2_device: PathBuf,
    pub backend: BackendType,
}

#[cfg(feature = "simple-capture")]
pub fn create_simple_capture_device_config() -> VirtioMediaDeviceConfig {
    use v4l2r::ioctl::Capabilities;
    let mut card = [0u8; VIRTIO_V4L2_CARD_NAME_LEN];
    let card_name = "simple_device";
    card[0..card_name.len()].copy_from_slice(card_name.as_bytes());
    VirtioMediaDeviceConfig {
        device_caps: (Capabilities::VIDEO_CAPTURE | Capabilities::STREAMING).bits(),
        device_type: V4l2DeviceType::Video as u32,
        card,
    }
}

#[cfg(feature = "v4l2-proxy")]
pub fn create_v4l2_proxy_device_config(device_path: &PathBuf) -> VirtioMediaDeviceConfig {
    use virtio_media::v4l2r::ioctl::Capabilities;

    let device = virtio_media::v4l2r::device::Device::open(
        device_path.as_ref(),
        virtio_media::v4l2r::device::DeviceConfig::new().non_blocking_dqbuf(),
    )
    .unwrap();
    let mut device_caps = device.caps().device_caps();

    // We are only exposing one device worth of capabilities.
    device_caps.remove(Capabilities::DEVICE_CAPS);

    // Read-write is not supported by design.
    device_caps.remove(Capabilities::READWRITE);

    let mut config = VirtioMediaDeviceConfig {
        device_caps: device_caps.bits(),
        device_type: V4l2DeviceType::from_path(device_path.as_path()) as u32,
        card: Default::default(),
    };
    let card = &device.caps().card;
    let name_slice = card[0..std::cmp::min(card.len(), config.card.len())].as_bytes();
    config.card.as_mut_slice()[0..name_slice.len()].copy_from_slice(name_slice);

    config
}

#[cfg(feature = "ffmpeg")]
pub fn create_ffmpeg_decoder_config() -> VirtioMediaDeviceConfig {
    use v4l2r::ioctl::Capabilities;
    let mut card = [0u8; VIRTIO_V4L2_CARD_NAME_LEN];
    let card_name = "ffmpeg_decoder";
    card[0..card_name.len()].copy_from_slice(card_name.as_bytes());
    VirtioMediaDeviceConfig {
        device_caps: (Capabilities::VIDEO_M2M_MPLANE
            | Capabilities::EXT_PIX_FORMAT
            | Capabilities::STREAMING
            | Capabilities::DEVICE_CAPS)
            .bits(),
        device_type: V4l2DeviceType::Video as u32,
        card,
    }
}

#[cfg(feature = "simple-capture")]
fn serve_simple_capture(media_config: &VuMediaConfig) -> Result<()> {
    let vu_media_backend = Arc::new(
        VuMediaBackend::new(
            media_config.v4l2_device.as_path(),
            create_simple_capture_device_config(),
            move |event_queue, _, host_mapper| {
                Ok(virtio_media::devices::SimpleCaptureDevice::new(
                    event_queue,
                    host_mapper,
                ))
            },
        )
        .map_err(Error::CouldNotCreateBackend)?,
    );
    let mut daemon = VhostUserDaemon::new(
        "vhost-device-media".to_owned(),
        vu_media_backend.clone(),
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .unwrap();

    vu_media_backend.set_thread_workers(&mut daemon.get_epoll_handlers());

    daemon
        .serve(&media_config.socket_path)
        .map_err(Error::ServeFailed)?;

    Ok(())
}

#[cfg(feature = "v4l2-proxy")]
fn serve_v4l2_proxy_daemon(media_config: &VuMediaConfig) -> Result<()> {
    let path = media_config.v4l2_device.clone();
    let vu_media_backend = Arc::new(
        VuMediaBackend::new(
            media_config.v4l2_device.as_path(),
            create_v4l2_proxy_device_config(&path),
            move |event_queue, guest_mapper, host_mapper| {
                Ok(virtio_media::devices::V4l2ProxyDevice::new(
                    path.clone(),
                    event_queue,
                    guest_mapper,
                    host_mapper,
                ))
            },
        )
        .map_err(Error::CouldNotCreateBackend)?,
    );
    let mut daemon = VhostUserDaemon::new(
        "vhost-device-media".to_owned(),
        vu_media_backend.clone(),
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .unwrap();

    vu_media_backend.set_thread_workers(&mut daemon.get_epoll_handlers());
    daemon
        .serve(&media_config.socket_path)
        .map_err(Error::ServeFailed)?;

    Ok(())
}

#[cfg(feature = "ffmpeg")]
fn serve_ffmpeg_decoder(media_config: &VuMediaConfig) -> Result<()> {
    let vu_media_backend = Arc::new(
        VuMediaBackend::new(
            media_config.v4l2_device.as_path(),
            create_ffmpeg_decoder_config(),
            move |event_queue, _, host_mapper| {
                Ok(virtio_media::devices::video_decoder::VideoDecoder::new(
                    virtio_media_ffmpeg_decoder::FfmpegDecoder::new(),
                    event_queue,
                    host_mapper,
                ))
            },
        )
        .map_err(Error::CouldNotCreateBackend)?,
    );

    let mut daemon = VhostUserDaemon::new(
        "vhost-device-media".to_owned(),
        vu_media_backend.clone(),
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .unwrap();

    vu_media_backend.set_thread_workers(&mut daemon.get_epoll_handlers());
    daemon
        .serve(&media_config.socket_path)
        .map_err(Error::ServeFailed)?;

    Ok(())
}

pub fn start_backend(media_config: VuMediaConfig) -> Result<()> {
    loop {
        debug!("Starting backend");
        match media_config.backend {
            #[cfg(feature = "simple-capture")]
            BackendType::SimpleCapture => serve_simple_capture(&media_config),
            #[cfg(feature = "v4l2-proxy")]
            BackendType::V4l2Proxy => serve_v4l2_proxy_daemon(&media_config),
            #[cfg(feature = "ffmpeg")]
            BackendType::FfmpegDecoder => serve_ffmpeg_decoder(&media_config),
        }?;
        debug!("Finishing backend");
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use rstest::*;
    use tempfile::tempdir;
    #[cfg(any(feature = "simple-capture", feature = "ffmpeg"))]
    use virtio_media::protocol::VirtioMediaDeviceConfig;

    use super::*;

    #[rstest]
    #[case("/dev/video0", V4l2DeviceType::Video)]
    #[case("/dev/video1", V4l2DeviceType::Video)]
    #[case("/dev/video99", V4l2DeviceType::Video)]
    #[case("/dev/vbi0", V4l2DeviceType::Vbi)]
    #[case("/dev/vbi1", V4l2DeviceType::Vbi)]
    #[case("/dev/radio0", V4l2DeviceType::Radio)]
    #[case("/dev/radio1", V4l2DeviceType::Radio)]
    #[case("/dev/swradio0", V4l2DeviceType::Sdr)]
    #[case("/dev/sdr0", V4l2DeviceType::Sdr)]
    #[case("/dev/sdr1", V4l2DeviceType::Sdr)]
    #[case("/dev/touch0", V4l2DeviceType::Touch)]
    #[case("/dev/touch1", V4l2DeviceType::Touch)]
    fn test_v4l2_device_type_from_path(
        #[case] device_path: &str,
        #[case] expected_type: V4l2DeviceType,
    ) {
        assert_eq!(
            V4l2DeviceType::from_path(Path::new(device_path)) as u32,
            expected_type as u32
        );
    }

    #[rstest]
    #[case("/dev/unknown0")]
    #[case("/dev/other")]
    fn test_v4l2_device_type_from_path_unknown_defaults_to_video(#[case] device_path: &str) {
        // Unknown device types should default to Video
        assert_eq!(
            V4l2DeviceType::from_path(Path::new(device_path)) as u32,
            V4l2DeviceType::Video as u32
        );
    }

    #[rstest]
    #[case("/")]
    #[case("/dev/")]
    fn test_v4l2_device_type_from_path_no_filename(#[case] device_path: &str) {
        // Paths without a filename should default to Video
        assert_eq!(
            V4l2DeviceType::from_path(Path::new(device_path)) as u32,
            V4l2DeviceType::Video as u32
        );
    }

    #[test]
    fn test_v4l2_device_type_from_path_symlink() {
        // Test symlink resolution by creating a temporary symlink
        let temp_dir = tempdir().unwrap();
        let target = temp_dir.path().join("vbi0");
        let symlink = temp_dir.path().join("link-to-vbi0");

        // Create a dummy file to symlink to
        std::fs::File::create(&target).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &symlink).unwrap();

        // On Unix, the symlink should resolve to the target (vbi0) -> Vbi
        // On non-Unix, canonicalize fails, so it falls back to Video
        let expected = if cfg!(unix) {
            V4l2DeviceType::Vbi as u32
        } else {
            V4l2DeviceType::Video as u32
        };
        assert_eq!(V4l2DeviceType::from_path(&symlink) as u32, expected);
    }

    #[cfg(feature = "simple-capture")]
    #[rstest]
    #[case(create_simple_capture_device_config(), 13, b"simple_device")]
    fn test_simple_capture_device_config_shape(
        #[case] cfg: VirtioMediaDeviceConfig,
        #[case] card_name_len: usize,
        #[case] expected_card_prefix: &[u8],
    ) {
        assert_eq!(cfg.device_type, 0);
        assert!(cfg.device_caps != 0);
        assert_eq!(cfg.card.len(), VIRTIO_V4L2_CARD_NAME_LEN);
        assert_eq!(&cfg.card[..card_name_len], expected_card_prefix);
    }

    #[cfg(feature = "ffmpeg")]
    #[rstest]
    #[case(create_ffmpeg_decoder_config(), 14, b"ffmpeg_decoder")]
    fn test_ffmpeg_decoder_config_shape(
        #[case] cfg: VirtioMediaDeviceConfig,
        #[case] card_name_len: usize,
        #[case] expected_card_prefix: &[u8],
    ) {
        assert_eq!(cfg.device_type, 0);
        assert!(cfg.device_caps != 0);
        assert_eq!(cfg.card.len(), VIRTIO_V4L2_CARD_NAME_LEN);
        assert_eq!(&cfg.card[..card_name_len], expected_card_prefix);
    }
}
