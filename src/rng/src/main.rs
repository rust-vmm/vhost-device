// VIRTIO RNG Emulation via vhost-user
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
// Mathieu Poirier <mathieu.poirier@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

mod vhu_rng;

use clap::{load_yaml, App};
use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::VhostUserDaemon;
use vhu_rng::VuRngBackend;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

fn start_backend(cmd_args: clap::ArgMatches, dry_run: bool) -> Result<(), String> {
    let mut handles = Vec::new();

    let path = cmd_args
        .value_of("socket_path")
        .ok_or("Invalid socket path")?;

    let count = cmd_args
        .value_of("socket_count")
        .unwrap_or("1")
        .parse::<u32>()
        .map_err(|_| "Invalid socket_count")?;

    let source = match cmd_args.value_of("rng_source") {
        Some(source) => {
            if Path::new(source).is_file() {
                source.to_string()
            } else {
                return Err(String::from("Enable to access RNG source file"));
            }
        }
        None => "/dev/urandom".to_string(),
    };

    let random_file = match File::open(source) {
        Ok(random_file) => Arc::new(Mutex::new(random_file)),
        Err(e) => return Err(e.to_string()),
    };

    let period_ms: u128 = match cmd_args.value_of("period") {
        Some(period_ms) => match period_ms.parse::<u128>() {
            Ok(value) => {
                if value > (1 << 16) {
                    return Err(format!(
                        "Input period too big, maximum value is {}",
                        1 << 16
                    ));
                }
                value
            }
            Err(e) => {
                return Err(e.to_string());
            }
        },
        None => 1 << 16,
    };

    let mut max_bytes: usize = match cmd_args.value_of("max_bytes") {
        Some(max_bytes) => match max_bytes.parse::<usize>() {
            // No point in checking for a maximum value like above,
            // the library parsing code will do that for us.
            Ok(value) => value,
            Err(_) => {
                return Err(String::from("Enable to process max-bytes"));
            }
        },
        None => usize::MAX,
    };

    // Divide available bandwidth by the number of threads in order
    // to avoid overwhelming the HW.
    max_bytes /= count as usize;

    for i in 0..count {
        let socket = path.to_owned() + &i.to_string();
        let random = Arc::clone(&random_file);

        let handle = thread::spawn(move || loop {
            let rng_backend = match VuRngBackend::new(random.clone(), period_ms, max_bytes) {
                Ok(rng_backend) => rng_backend,
                Err(_) => {
                    println!("Error creating RNG backend on thread: {}", i);
                    return;
                }
            };

            let vu_rng_backend = Arc::new(RwLock::new(rng_backend));

            if dry_run {
                return;
            }

            let listener = match Listener::new(socket.clone(), true) {
                Ok(listener) => listener,
                Err(_) => {
                    println!("Error creating RNG listener daemon on thread: {}", i);
                    return;
                }
            };

            let mut daemon = match VhostUserDaemon::new(
                String::from("vhost-user-RNG-daemon"),
                vu_rng_backend.clone(),
                GuestMemoryAtomic::new(GuestMemoryMmap::new()),
            ) {
                Ok(daemon) => daemon,
                Err(_) => {
                    println!("Error creating RNG vhost user daemon on thread: {}", i);
                    return;
                }
            };

            if daemon.start(listener).is_err() {
                println!("Error starting RNG vhost user daemon on thread: {}", i);
                return;
            }

            match daemon.wait() {
                Ok(()) => println!("Stopping cleanly."),
                Err(vhost_user_backend::Error::HandleRequest(
                    vhost_user::Error::PartialMessage,
                )) => {
                    println!("vhost-user connection closed with partial message. If the VM is shutting down, this is expected behavior; otherwise, it might be a bug.");
                }
                Err(e) => println!("Error running daemon: {:?}", e),
            }

            // No matter the result, we need to shut down the worker thread.
            vu_rng_backend
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

    start_backend(cmd_args, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_cmd_args(option: &str, value: &str) -> clap::ArgMatches {
        let yaml = load_yaml!("cli.yaml");
        App::from(yaml).get_matches_from(vec![
            "vhost-device-rng",
            "-s",
            "socket.file",
            option,
            value,
        ])
    }

    #[test]
    fn invalid_random_file_input() {
        assert!(start_backend(get_cmd_args("-f", "/dev/doesnotexists"), true).is_err());
    }

    #[test]
    fn invalid_period_too_big() {
        assert!(start_backend(get_cmd_args("-p", "100000"), true).is_err());
    }

    #[test]
    fn invalid_period_malformed() {
        assert!(start_backend(get_cmd_args("-p", "invalid"), true).is_err());
    }
}
