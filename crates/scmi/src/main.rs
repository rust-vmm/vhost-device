// SPDX-FileCopyrightText: Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0
// Based on implementation of other devices here, Copyright by Linaro Ltd.

mod scmi;
mod vhu_scmi;

use std::process::exit;
use std::sync::{Arc, RwLock};

use clap::Parser;
use log::{debug, error, info, warn};

use vhost::vhost_user;
use vhost::vhost_user::Listener;
use vhost_user_backend::VhostUserDaemon;
use vhu_scmi::{VuScmiBackend, VuScmiError};
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

type Result<T> = std::result::Result<T, VuScmiError>;

#[derive(Parser)]
struct ScmiArgs {
    // Location of vhost-user Unix domain socket.
    #[clap(short, long, help = "vhost-user socket to use")]
    socket_path: String,
}

struct VuScmiConfig {
    socket_path: String,
}

impl TryFrom<ScmiArgs> for VuScmiConfig {
    type Error = VuScmiError;

    fn try_from(cmd_args: ScmiArgs) -> Result<Self> {
        let socket_path = cmd_args.socket_path.trim().to_string();
        Ok(Self { socket_path })
    }
}

fn start_backend(config: VuScmiConfig) -> Result<()> {
    loop {
        debug!("Starting backend");
        let backend = Arc::new(RwLock::new(VuScmiBackend::new().unwrap()));
        let listener = Listener::new(config.socket_path.clone(), true).unwrap();
        let mut daemon = VhostUserDaemon::new(
            "vhost-device-scmi".to_owned(),
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
                info!(
                    "vhost-user connection closed with partial message.
                       If the VM is shutting down, this is expected behavior;
                       otherwise, it might be a bug."
                );
            }
            Err(e) => {
                warn!("Error running daemon: {:?}", e);
            }
        }

        // No matter the result, we need to shut down the worker thread.
        backend.read().unwrap().exit_event.write(1).unwrap();
        debug!("Finishing backend");
    }
}

fn main() {
    env_logger::init();
    if let Err(error) = start_backend(VuScmiConfig::try_from(ScmiArgs::parse()).unwrap()) {
        error!("{error}");
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_line() {
        let path = "/foo/scmi.sock".to_owned();
        let command_line = format!("-s {path}");
        let args: ScmiArgs = Parser::parse_from(["", &command_line]);
        let config: VuScmiConfig = args.try_into().unwrap();
        assert_eq!(config.socket_path, path);
    }
}
