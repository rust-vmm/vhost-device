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

fn start_backend<T: I2cAdapterTrait>(cmd_args: ArgMatches) -> Result<(), String> {
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

            let mut daemon =
                VhostUserDaemon::new(String::from("vhost-device-i2c-backend"), backend.clone())
                    .unwrap();

            daemon.start(listener).unwrap();

            match daemon.wait() {
                Ok(()) => {
                    println!("Stopping cleanly.");
                }
                Err(vhost_user_backend::Error::HandleRequest(
                    vhost_user::Error::PartialMessage,
                )) => {
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

    start_backend::<I2cAdapter>(cmd_args)
}
