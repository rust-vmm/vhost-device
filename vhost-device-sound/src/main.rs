// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// Stefano Garzarella <sgarzare@redhat.com>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use clap::Parser;
use vhost_device_sound::{args::SoundArgs, start_backend_server, SoundConfig};

fn main() {
    env_logger::init();

    let config = SoundConfig::from(SoundArgs::parse());

    loop {
        start_backend_server(config.clone());
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use clap::Parser;
    use rstest::*;
    use vhost_device_sound::BackendType;

    use super::*;

    fn init_logger() {
        std::env::set_var("RUST_LOG", "trace");
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_sound_config_setup() {
        init_logger();
        let args = SoundArgs {
            socket: PathBuf::from("/tmp/vhost-sound.socket"),
            backend: BackendType::default(),
        };
        let config = SoundConfig::from(args);

        assert_eq!(
            config.get_socket_path(),
            Path::new("/tmp/vhost-sound.socket")
        );
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

        let config = SoundConfig::from(args);
        assert_eq!(config.get_audio_backend(), backend);
    }
}
