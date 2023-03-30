// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod vhu_sound;

use std::{
    convert::TryFrom,
    sync::{Arc, RwLock},
};

use clap::Parser;
use log::{info, warn};
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

use crate::vhu_sound::{Error, Result, SoundConfig, VhostUserSoundBackend};

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct SoundArgs {
    /// vhost-user Unix domain socket path.
    #[clap(long)]
    socket: String,
}

impl TryFrom<SoundArgs> for SoundConfig {
    type Error = Error;

    fn try_from(cmd_args: SoundArgs) -> Result<Self> {
        let socket = cmd_args.socket.trim().to_string();

        Ok(SoundConfig::new(socket))
    }
}

/// This is the public API through which an external program starts the
/// vhost-user-sound backend server.
pub(crate) fn start_backend_server(config: SoundConfig) {
    loop {
        let backend = Arc::new(RwLock::new(
            VhostUserSoundBackend::new(config.clone()).unwrap(),
        ));

        let listener = Listener::new(config.get_socket_path(), true).unwrap();

        let mut daemon = VhostUserDaemon::new(
            String::from("vhost-user-sound"),
            backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .unwrap();

        daemon.start(listener).unwrap();

        match daemon.wait() {
            Ok(()) => {
                info!("Stopping cleanly");
            }
            Err(vhost_user_backend::Error::HandleRequest(vhost_user::Error::PartialMessage)) => {
                info!("vhost-user connection closed with partial message. If the VM is shutting down, this is expected behavior; otherwise, it might be a bug.");
            }
            Err(e) => {
                warn!("Error running daemon: {:?}", e);
            }
        }

        // No matter the result, we need to shut down the worker thread.
        backend.read().unwrap().exit_event.write(1).unwrap();
    }
}

fn main() {
    env_logger::init();

    let config = SoundConfig::try_from(SoundArgs::parse()).unwrap();
    start_backend_server(config);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    impl SoundArgs {
        fn from_args(socket: &str) -> Self {
            SoundArgs {
                socket: socket.to_string(),
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
