// Copyright 2026 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod media_allocator;
mod media_backends;
pub mod vhu_media;
mod vhu_media_thread;
mod virtio;

pub use vhu_media::{BackendType, VuMediaError};

use std::{path::PathBuf, sync::Arc};

use ::virtio_media::protocol::VirtioMediaDeviceConfig;
use log::debug;
use thiserror::Error as ThisError;
use vhost_user_backend::VhostUserDaemon;
use vhu_media::VuMediaBackend;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(any(feature = "simple-capture", feature = "ffmpeg"))]
const VIRTIO_V4L2_CARD_NAME_LEN: usize = 32;

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
        device_type: 0,
        card,
    }
}

#[cfg(feature = "v4l2-proxy")]
pub fn create_v4l2_proxy_device_config(
    device_path: &PathBuf,
) -> VirtioMediaDeviceConfig {
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
        // VFL_TYPE_VIDEO
        // TODO should not be hardcoded!
        device_type: 0,
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
        device_type: 0,
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
    #[cfg(any(feature = "simple-capture", feature = "ffmpeg"))]
    use rstest::*;
    #[cfg(any(feature = "simple-capture", feature = "ffmpeg"))]
    use virtio_media::protocol::VirtioMediaDeviceConfig;
    #[cfg(any(feature = "simple-capture", feature = "ffmpeg"))]
    use super::*;

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
