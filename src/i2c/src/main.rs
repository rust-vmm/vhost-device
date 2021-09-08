// VIRTIO I2C Emulation via vhost-user
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

mod i2c;
mod vhu_i2c;

use clap::{load_yaml, App, ArgMatches};
use i2c::{I2cAdapter, I2cAdapterTrait, I2cMap};
use std::sync::{Arc, RwLock};
use std::thread::spawn;
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::VhostUserDaemon;
use vhu_i2c::VhostUserI2cBackend;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

fn start_daemon<T: I2cAdapterTrait>(
    backend: Arc<RwLock<VhostUserI2cBackend<T>>>,
    listener: Listener,
) -> bool {
    let mut daemon = VhostUserDaemon::new(
        String::from("vhost-device-i2c-backend"),
        backend.clone(),
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .unwrap();

    daemon.start(listener).unwrap();

    match daemon.wait() {
        Ok(()) => {
            println!("Stopping cleanly.");
        }
        Err(vhost_user_backend::Error::HandleRequest(vhost_user::Error::PartialMessage)) => {
            println!("vhost-user connection closed with partial message. If the VM is shutting down, this is expected behavior; otherwise, it might be a bug.");
        }
        Err(e) => {
            println!("Error running daemon: {:?}", e);
        }
    }

    // No matter the result, we need to shut down the worker thread.
    backend
        .read()
        .unwrap()
        .exit_event
        .write(1)
        .expect("Shutting down worker thread");

    false
}

fn start_backend<T: I2cAdapterTrait>(
    cmd_args: ArgMatches,
    start_daemon: fn(Arc<RwLock<VhostUserI2cBackend<T>>>, Listener) -> bool,
) -> Result<(), String> {
    let mut handles = Vec::new();

    let path = cmd_args
        .value_of("socket_path")
        .ok_or("Invalid socket path")?;

    let count = cmd_args
        .value_of("socket_count")
        .unwrap_or("1")
        .parse::<u32>()
        .map_err(|_| "Invalid socket_count")?;

    let list = cmd_args.value_of("devices").ok_or("Invalid devices list")?;

    // The same i2c_map structure instance is shared between all the guests
    let i2c_map =
        Arc::new(I2cMap::<T>::new(list).map_err(|e| format!("Failed to create i2c_map ({})", e))?);

    for i in 0..count {
        let socket = path.to_owned() + &i.to_string();
        let i2c_map = i2c_map.clone();

        let handle = spawn(move || loop {
            let backend = Arc::new(RwLock::new(
                VhostUserI2cBackend::new(i2c_map.clone()).unwrap(),
            ));
            let listener = Listener::new(socket.clone(), true).unwrap();

            if start_daemon(backend, listener) {
                break;
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().map_err(|_| "Failed to join threads")?;
    }

    Ok(())
}

fn main() -> Result<(), String> {
    let yaml = load_yaml!("cli.yaml");
    let cmd_args = App::from(yaml).get_matches();

    start_backend::<I2cAdapter>(cmd_args, start_daemon)
}

#[cfg(test)]
mod tests {
    use super::*;
    use i2c::tests::I2cMockAdapter;

    fn get_cmd_args(name: &str, devices: &str, count: u32) -> ArgMatches {
        let yaml = load_yaml!("cli.yaml");
        let app = App::from(yaml);

        if count != 0 {
            app.try_get_matches_from(vec![
                "prog",
                "-s",
                name,
                "-l",
                devices,
                "-c",
                &count.to_string(),
            ])
            .unwrap()
        } else {
            app.try_get_matches_from(vec!["prog", "-s", name, "-l", devices])
                .unwrap()
        }
    }

    fn mock_start_daemon<T: I2cAdapterTrait>(
        _backend: Arc<RwLock<VhostUserI2cBackend<T>>>,
        _listener: Listener,
    ) -> bool {
        true
    }

    #[test]
    fn test_backend_single() {
        let cmd_args = get_cmd_args("vi2c.sock_single", "1:4,2:32:21,5:5:23", 0);
        assert!(start_backend::<I2cMockAdapter>(cmd_args, mock_start_daemon).is_ok());
    }

    #[test]
    fn test_backend_multiple() {
        let cmd_args = get_cmd_args("vi2c.sock", "1:4,2:32:21,5:5:23", 5);
        assert!(start_backend::<I2cMockAdapter>(cmd_args, mock_start_daemon).is_ok());
    }

    #[test]
    fn test_backend_failure() {
        let cmd_args = get_cmd_args("vi2c.sock_failure", "1:4d", 5);
        assert!(start_backend::<I2cMockAdapter>(cmd_args, mock_start_daemon).is_err());
    }

    #[test]
    fn test_backend_failure_duplicate_device4() {
        let cmd_args = get_cmd_args("vi2c.sock_duplicate", "1:4,2:32:21,5:4:23", 5);
        assert!(start_backend::<I2cMockAdapter>(cmd_args, mock_start_daemon).is_err());
    }
}
