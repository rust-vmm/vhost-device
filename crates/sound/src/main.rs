// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// Stefano Garzarella <sgarzare@redhat.com>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
use std::convert::TryFrom;

use clap::Parser;
use vhost_user_sound::{start_backend_server, Error, Result, SoundConfig};

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct SoundArgs {
    /// vhost-user Unix domain socket path.
    #[clap(long)]
    socket: String,
    /// audio backend to be used (supported: null)
    #[clap(long)]
    backend: String,
}

impl TryFrom<SoundArgs> for SoundConfig {
    type Error = Error;

    fn try_from(cmd_args: SoundArgs) -> Result<Self> {
        let socket = cmd_args.socket.trim().to_string();
        let backend = cmd_args.backend.trim().to_string();

        Ok(SoundConfig::new(socket, false, backend))
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
    use serial_test::serial;

    use super::*;

    impl SoundArgs {
        fn from_args(socket: &str) -> Self {
            SoundArgs {
                socket: socket.to_string(),
                backend: "null".to_string(),
            }
        }
    }

    #[test]
    #[serial]
    fn test_vsock_config_setup() {
        let args = SoundArgs::from_args("/tmp/vhost-sound.socket");

        let config = SoundConfig::try_from(args);
        assert!(config.is_ok());

        let config = config.unwrap();
        assert_eq!(config.get_socket_path(), "/tmp/vhost-sound.socket");
    }
}
