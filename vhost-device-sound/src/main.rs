// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// Stefano Garzarella <sgarzare@redhat.com>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::os::unix::{net::UnixListener, prelude::*};

use clap::Parser;
use vhost::vhost_user::Listener;
use vhost_device_sound::{args::SoundArgs, start_backend_server, SoundConfig};

fn main() {
    env_logger::init();

    let args = SoundArgs::parse();
    let config = SoundConfig::new(false, args.backend).with_capture(!args.no_capture);

    let mut listener = if let Some(fd) = args.socket_fd {
        // SAFETY: user has assured us this is safe.
        unsafe { UnixListener::from_raw_fd(fd) }.into()
    } else if let Some(path) = args.socket {
        Listener::new(path, true).unwrap()
    } else {
        unreachable!()
    };

    loop {
        if let Err(e) = start_backend_server(&mut listener, config.clone()) {
            log::error!("Error running vhost-device-sound backend: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser;
    use rstest::*;
    use vhost_device_sound::BackendType;

    use super::*;

    #[test]
    fn test_cli_socket_arg() {
        let args: SoundArgs = Parser::parse_from([
            "",
            "--socket",
            "/tmp/vhost-sound.socket",
            "--backend",
            "null",
        ]);
        assert_eq!(args.socket, Some(PathBuf::from("/tmp/vhost-sound.socket")));
    }

    #[test]
    fn test_cli_no_capture_arg() {
        let args: SoundArgs = Parser::parse_from(["", "--socket-fd", "3", "--backend", "null"]);
        assert!(!args.no_capture);
        assert!(SoundConfig::new(false, args.backend)
            .with_capture(!args.no_capture)
            .get_capture());

        let args: SoundArgs =
            Parser::parse_from(["", "--socket-fd", "3", "--backend", "null", "--no-capture"]);
        assert!(args.no_capture);
        assert!(!SoundConfig::new(false, args.backend)
            .with_capture(!args.no_capture)
            .get_capture());
    }

    #[test]
    fn test_cli_socket_fd_arg() {
        let args: SoundArgs = Parser::parse_from(["", "--socket-fd", "3", "--backend", "null"]);
        assert_eq!(args.socket_fd, Some(3));
    }

    #[rstest]
    #[case::null_backend("null", BackendType::Null)]
    #[cfg_attr(
        all(feature = "pw-backend", target_env = "gnu"),
        case::pipewire("pipewire", BackendType::Pipewire)
    )]
    #[cfg_attr(
        all(feature = "alsa-backend", target_env = "gnu"),
        case::alsa("alsa", BackendType::Alsa)
    )]
    #[cfg_attr(
        all(feature = "gst-backend", target_env = "gnu"),
        case::gstreamer("gstreamer", BackendType::GStreamer)
    )]
    fn test_cli_backend_arg(#[case] backend_name: &str, #[case] backend: BackendType) {
        let args: SoundArgs = Parser::parse_from([
            "",
            "--socket",
            "/tmp/vhost-sound.socket ",
            "--backend",
            backend_name,
        ]);

        let config = SoundConfig::new(false, args.backend);
        assert_eq!(config.get_audio_backend(), backend);
    }
}
