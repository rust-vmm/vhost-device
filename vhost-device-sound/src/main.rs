// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// Stefano Garzarella <sgarzare@redhat.com>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
use std::convert::TryFrom;

use clap::Parser;
use vhost_device_sound::{start_backend_server, BackendType, Error, Result, SoundConfig};

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct SoundArgs {
    /// vhost-user Unix domain socket path.
    #[clap(long)]
    socket: String,
    /// audio backend to be used
    #[clap(long)]
    #[clap(value_enum)]
    backend: BackendType,
}

impl TryFrom<SoundArgs> for SoundConfig {
    type Error = Error;

    fn try_from(cmd_args: SoundArgs) -> Result<Self> {
        let socket = cmd_args.socket.trim().to_string();

        Ok(Self::new(socket, false, cmd_args.backend))
    }
}

fn main() {
    env_logger::init();

    let config = SoundConfig::try_from(SoundArgs::parse()).unwrap();

    loop {
        start_backend_server(config.clone());
    }
}

#[cfg(test)]
mod tests {
    use rstest::*;

    use super::*;

    impl SoundArgs {
        fn from_args(socket: &str) -> Self {
            Self {
                socket: socket.to_string(),
                backend: BackendType::default(),
            }
        }
    }

    fn init_logger() {
        std::env::set_var("RUST_LOG", "trace");
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_sound_config_setup() {
        init_logger();
        let args = SoundArgs::from_args("/tmp/vhost-sound.socket");

        let config = SoundConfig::try_from(args);
        assert!(config.is_ok());

        let config = config.unwrap();
        assert_eq!(config.get_socket_path(), "/tmp/vhost-sound.socket");
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
    fn test_cli_backend_arg(#[case] backend_name: &str, #[case] backend: BackendType) {
        let args: SoundArgs = Parser::parse_from([
            "",
            "--socket",
            "/tmp/vhost-sound.socket ",
            "--backend",
            backend_name,
        ]);

        let config = SoundConfig::try_from(args);
        assert!(config.is_ok());

        let config = config.unwrap();
        assert_eq!(config.get_audio_backend(), backend);
    }
}
