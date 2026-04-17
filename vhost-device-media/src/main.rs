// Copyright 2026 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

extern crate vhost_device_media;

use std::path::PathBuf;

use clap::Parser;
use vhost_device_media::{start_backend, BackendType, Error, VuMediaConfig};

#[derive(Clone, Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct MediaArgs {
    /// Unix socket to which a hypervisor connects to and sets up the control
    /// path with the device.
    #[clap(short, long)]
    socket_path: PathBuf,

    /// Path to the V4L2 media device file. Defaults to /dev/video0.
    #[clap(short = 'd', long, default_value = "/dev/video0")]
    v4l2_device: PathBuf,

    /// Media backend to be used.
    #[clap(short, long, default_value = "simple-capture")]
    #[clap(value_enum)]
    backend: BackendType,
}

impl From<MediaArgs> for VuMediaConfig {
    fn from(args: MediaArgs) -> Self {
        Self {
            socket_path: args.socket_path,
            v4l2_device: args.v4l2_device,
            backend: args.backend,
        }
    }
}

fn main() -> std::result::Result<(), Error> {
    env_logger::init();

    start_backend(VuMediaConfig::from(MediaArgs::parse()))
}

#[cfg(test)]
mod tests {
    use rstest::*;

    use super::*;

    #[rstest]
    #[cfg_attr(
        feature = "simple-capture",
        case::simple_capture("simple-capture", BackendType::SimpleCapture)
    )]
    #[cfg_attr(
        feature = "v4l2-proxy",
        case::v4l2_proxy("v4l2-proxy", BackendType::V4l2Proxy)
    )]
    #[cfg_attr(
        feature = "ffmpeg",
        case::ffmpeg_decoder("ffmpeg-decoder", BackendType::FfmpegDecoder)
    )]
    fn test_cli_backend_arg(#[case] backend_name: &str, #[case] backend: BackendType) {
        let args = MediaArgs::try_parse_from([
            "vhost-device-media",
            "--socket-path",
            "/tmp/vmedia.sock",
            "--backend",
            backend_name,
        ])
        .unwrap();

        assert_eq!(args.backend, backend);
    }

    #[rstest]
    #[cfg_attr(
        feature = "simple-capture",
        case::simple_capture(
            "simple-capture",
            BackendType::SimpleCapture,
            "/tmp/vmedia.sock",
            "/dev/video7"
        )
    )]
    #[cfg_attr(
        feature = "v4l2-proxy",
        case::v4l2_proxy_alt(
            "v4l2-proxy",
            BackendType::V4l2Proxy,
            "/tmp/other.sock",
            "/dev/video0"
        )
    )]
    #[cfg_attr(
        feature = "ffmpeg",
        case::ffmpeg_decoder(
            "ffmpeg-decoder",
            BackendType::FfmpegDecoder,
            "/tmp/ffmpeg.sock",
            "/dev/video3"
        )
    )]
    fn test_media_args_parse_explicit_values(
        #[case] backend_name: &str,
        #[case] expected_backend: BackendType,
        #[case] socket: &str,
        #[case] device: &str,
    ) {
        let args = MediaArgs::try_parse_from([
            "vhost-device-media",
            "--socket-path",
            socket,
            "--v4l2-device",
            device,
            "--backend",
            backend_name,
        ])
        .unwrap();

        assert_eq!(args.socket_path, PathBuf::from(socket));
        assert_eq!(args.v4l2_device, PathBuf::from(device));
        assert_eq!(args.backend, expected_backend);
    }

    #[test]
    fn test_media_args_parse_defaults() {
        let res = MediaArgs::try_parse_from([
            "vhost-device-media",
            "--socket-path",
            "/tmp/vmedia-default.sock",
        ]);

        #[cfg(feature = "simple-capture")]
        {
            let args = res.unwrap();
            assert_eq!(args.socket_path, PathBuf::from("/tmp/vmedia-default.sock"));
            assert_eq!(args.v4l2_device, PathBuf::from("/dev/video0"));
            // Default CLI backend is simple-capture.
            assert_eq!(args.backend, BackendType::SimpleCapture);
        }

        #[cfg(not(feature = "simple-capture"))]
        {
            // If simple-capture is compiled out, the hardcoded default backend
            // becomes invalid and clap should reject parsing.
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_media_args_parse_missing_socket_fails() {
        let res = MediaArgs::try_parse_from(["vhost-device-media"]);
        assert!(res.is_err());
    }

    #[test]
    fn test_media_args_parse_invalid_backend_fails() {
        let res = MediaArgs::try_parse_from([
            "vhost-device-media",
            "--socket-path",
            "/tmp/vmedia-invalid.sock",
            "--backend",
            "not-a-backend",
        ]);
        assert!(res.is_err());
    }

    #[test]
    #[cfg(feature = "simple-capture")]
    fn test_from_media_args_for_vu_media_config() {
        let args = MediaArgs {
            socket_path: PathBuf::from("/tmp/a.sock"),
            v4l2_device: PathBuf::from("/dev/video99"),
            backend: BackendType::SimpleCapture,
        };

        let config = VuMediaConfig::from(args.clone());
        assert_eq!(config.socket_path, args.socket_path);
        assert_eq!(config.v4l2_device, args.v4l2_device);
        assert_eq!(config.backend, args.backend);
    }
}
