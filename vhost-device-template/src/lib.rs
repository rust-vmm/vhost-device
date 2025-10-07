// VIRTIO FOO Emulation via vhost-user
//
// Copyright 2023 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

pub mod backend;

use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
    thread::{spawn, JoinHandle},
};

use backend::VhostUserFooBackend;
use log::error;
use thiserror::Error as ThisError;
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, ThisError)]
/// Errors related to low level foo helpers
pub enum Error {
    #[error("Could not create backend: {0}")]
    CouldNotCreateBackend(backend::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
}

#[derive(PartialEq, Debug)]
pub struct FooConfiguration {
    pub socket_path: PathBuf,
}

#[derive(Copy, Clone)]
pub struct FooInfo {
    counter: u32,
}

impl FooInfo {
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    pub fn counter(&mut self) -> u32 {
        self.counter += 1;
        self.counter
    }
}

impl Default for FooInfo {
    fn default() -> Self {
        Self::new()
    }
}

pub fn start_backend(config: FooConfiguration) -> Result<()> {
    let socket_path = config.socket_path.clone();
    let info = FooInfo::new();

    let handle: JoinHandle<Result<()>> = spawn(move || loop {
        // There isn't much value in complicating code here to return an error from the
        // threads, and so the code uses unwrap() instead. The panic on a thread
        // won't cause trouble to the main() function and should be safe for the
        // daemon.
        let backend = Arc::new(RwLock::new(
            VhostUserFooBackend::new(info).map_err(Error::CouldNotCreateBackend)?,
        ));

        let mut daemon = VhostUserDaemon::new(
            String::from("vhost-device-template-backend"),
            backend,
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .map_err(Error::CouldNotCreateDaemon)?;

        daemon.serve(&socket_path).map_err(Error::ServeFailed)?;
    });

    handle.join().map_err(std::panic::resume_unwind).unwrap()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn test_fail_listener() {
        // This will fail the listeners and thread will panic.
        let socket_path = Path::new("/proc/foo/path/not/present").to_path_buf();
        let cmd_args = FooConfiguration { socket_path };

        assert_matches!(start_backend(cmd_args).unwrap_err(), Error::ServeFailed(_));
    }
}
