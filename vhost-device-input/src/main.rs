//
// Copyright 2023 Linaro Ltd. All Rights Reserved.
// Leo Yan <leo.yan@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod input;
mod vhu_input;

use clap::Parser;
use evdev::Device;
use log::error;
use std::{
    any::Any,
    collections::HashMap,
    path::PathBuf,
    process::exit,
    sync::{Arc, RwLock},
    thread,
};

use thiserror::Error as ThisError;
use vhost_user_backend::VhostUserDaemon;
use vhu_input::VuInputBackend;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::epoll::EventSet;

use crate::input::*;

#[derive(Debug, ThisError)]
/// Errors related to vhost-device-input daemon.
pub(crate) enum Error {
    #[error("Event device file doesn't exists or can't be accessed")]
    AccessEventDeviceFile,
    #[error("Could not create backend: {0}")]
    CouldNotCreateBackend(std::io::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
    #[error("Could not register input event into vring epoll")]
    CouldNotRegisterInputEvent,
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
    #[error("Thread `{0}` panicked")]
    ThreadPanic(String, Box<dyn Any + Send>),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Parser, Debug, PartialEq)]
#[clap(author, version, about, long_about = None)]
struct InputArgs {
    // Location of vhost-user Unix domain socket.
    #[clap(short, long, value_name = "SOCKET")]
    socket_path: PathBuf,

    // Path for reading input events.
    #[clap(
        short = 'e',
        long,
        use_value_delimiter = true,
        value_delimiter = ',',
        required = true
    )]
    event_list: Vec<PathBuf>,
}

impl InputArgs {
    pub fn generate_socket_paths(&self) -> Vec<PathBuf> {
        let socket_file_name = self
            .socket_path
            .file_name()
            .expect("socket_path has no filename.");
        let socket_file_parent = self
            .socket_path
            .parent()
            .expect("socket_path has no parent directory.");

        let make_socket_path = |i: usize| -> PathBuf {
            let mut file_name = socket_file_name.to_os_string();
            file_name.push(std::ffi::OsStr::new(&i.to_string()));
            socket_file_parent.join(&file_name)
        };

        (0..self.event_list.len()).map(make_socket_path).collect()
    }
}

// This is the public API through which an external program starts the
/// vhost-device-input backend server.
pub(crate) fn start_backend_server<D: 'static + InputDevice + Send + Sync>(
    socket: PathBuf,
    event: PathBuf,
) -> Result<()> {
    loop {
        let ev_dev = D::open(event.clone()).map_err(|_| Error::AccessEventDeviceFile)?;
        let raw_fd = ev_dev.get_raw_fd();

        // If creating the VuInputBackend isn't successful there isn't much else to do than
        // killing the thread, which .unwrap() does.  When that happens an error code is
        // generated and displayed by the runtime mechanic.  Killing a thread doesn't affect
        // the other threads spun-off by the daemon.
        let vu_input_backend = Arc::new(RwLock::new(
            VuInputBackend::new(ev_dev).map_err(Error::CouldNotCreateBackend)?,
        ));

        let mut daemon = VhostUserDaemon::new(
            String::from("vhost-device-input-backend"),
            Arc::clone(&vu_input_backend),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .map_err(Error::CouldNotCreateDaemon)?;

        let handlers = daemon.get_epoll_handlers();
        handlers[0]
            .register_listener(raw_fd, EventSet::IN, vhu_input::EVENT_ID_IN_VRING_EPOLL)
            .map_err(|_| Error::CouldNotRegisterInputEvent)?;

        daemon.serve(&socket).map_err(Error::ServeFailed)?;
    }
}

pub(crate) fn start_backend<D: 'static + InputDevice + Send + Sync>(
    config: InputArgs,
) -> Result<()> {
    let mut handles = HashMap::new();
    let (senders, receiver) = std::sync::mpsc::channel();

    for (thread_id, (socket, event)) in config
        .generate_socket_paths()
        .into_iter()
        .zip(config.event_list.iter().cloned())
        .enumerate()
    {
        let name = format!("vhu-vsock-input-{:?}", event);
        let sender = senders.clone();
        let handle = thread::Builder::new()
            .name(name.clone())
            .spawn(move || {
                let result =
                    std::panic::catch_unwind(move || start_backend_server::<D>(socket, event));

                // Notify the main thread that we are done.
                sender.send(thread_id).unwrap();

                result.map_err(|e| Error::ThreadPanic(name, e))?
            })
            .unwrap();
        handles.insert(thread_id, handle);
    }

    while !handles.is_empty() {
        let thread_id = receiver.recv().unwrap();
        handles
            .remove(&thread_id)
            .unwrap()
            .join()
            .map_err(std::panic::resume_unwind)
            .unwrap()?;
    }

    Ok(())
}

fn main() {
    env_logger::init();

    if let Err(e) = start_backend::<Device>(InputArgs::parse()) {
        error!("{e}");
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use evdev::{BusType, FetchEventsSynced, InputId};
    use std::io::{self};
    use std::os::fd::RawFd;

    use super::*;

    struct MockDevice;

    impl InputDevice for MockDevice {
        fn open(_path: PathBuf) -> io::Result<Self> {
            Ok(Self {})
        }

        fn fetch_events(&mut self) -> io::Result<FetchEventsSynced<'_>> {
            unreachable!()
        }

        fn get_raw_fd(&self) -> RawFd {
            0 as RawFd
        }

        fn input_id(&self) -> InputId {
            InputId::new(BusType::BUS_USB, 0x46d, 0x4023, 0x111)
        }
    }

    #[test]
    fn verify_cmd_line_arguments() {
        // All parameters have default values, except for the socket path.  White spaces are
        // introduced on purpose to make sure Strings are trimmed properly.
        let default_args: InputArgs = Parser::parse_from([
            "",
            "--socket-path=/some/socket_path",
            "--event-list=/dev/input/event1,/dev/input/event2",
        ]);

        // A valid configuration that should be equal to the above default configuration.
        let args = InputArgs {
            socket_path: PathBuf::from("/some/socket_path"),
            event_list: vec![
                PathBuf::from("/dev/input/event1"),
                PathBuf::from("/dev/input/event2"),
            ],
        };

        // All configuration elements should be what we expect them to be.  Using
        // VuInputConfig::try_from() ensures that strings have been properly trimmed.
        assert_eq!(default_args, args);

        // Test short arguments
        let default_args: InputArgs = Parser::parse_from([
            "",
            "-s=/some/socket_path",
            "-e=/dev/input/event1,/dev/input/event2",
        ]);

        assert_eq!(default_args, args);
    }

    #[test]
    fn test_fail_listener() {
        let config = InputArgs {
            socket_path: PathBuf::from("/invalid/path"),
            event_list: vec![PathBuf::from("/invalid/path")],
        };

        // An invalid socket path should trigger daemon failure.
        assert_matches!(
            start_backend::<MockDevice>(config).unwrap_err(),
            Error::ServeFailed(_)
        );
    }
}
