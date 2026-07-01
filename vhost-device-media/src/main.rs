// Copyright 2026 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

extern crate vhost_device_media;

use clap::Parser;
use vhost_device_media::{args::MediaArgs, start_backend, Error, VuMediaConfig};

fn main() -> std::result::Result<(), Error> {
    env_logger::init();

    start_backend(VuMediaConfig::from(MediaArgs::parse()))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    #[cfg(any(feature = "simple-capture", feature = "v4l2-proxy", feature = "ffmpeg"))]
    use rstest::*;
    use vhost_device_media::BackendType;

    use super::*;

    #[cfg(any(feature = "simple-capture", feature = "v4l2-proxy", feature = "ffmpeg"))]
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

    #[cfg(any(feature = "simple-capture", feature = "v4l2-proxy", feature = "ffmpeg"))]
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
            res.unwrap_err();
        }
    }

    #[test]
    fn test_cli_backend_null() {
        let args = MediaArgs::try_parse_from([
            "vhost-device-media",
            "--socket-path",
            "/tmp/vmedia-null.sock",
            "--backend",
            "null",
        ])
        .unwrap();
        assert_eq!(args.backend, BackendType::Null);
    }

    #[test]
    fn test_media_args_parse_missing_socket_fails() {
        let res = MediaArgs::try_parse_from(["vhost-device-media"]);
        res.unwrap_err();
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
        res.unwrap_err();
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
