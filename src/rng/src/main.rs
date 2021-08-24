// VIRTIO RNG Emulation via vhost-user
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
//          Mathieu Poirier <mathieu.poirier@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

mod vhu_rng;

use clap::{load_yaml, App};

use std::sync::{Arc, RwLock};
use std::thread;
use vhost::vhost_user::Listener;
use vhost_user_backend::VhostUserDaemon;
use vhu_rng::VuRngBackend;

fn start_backend(cmd_args: clap::ArgMatches) {
    let mut handles = Vec::new();

    let path = cmd_args.value_of("socket_path").ok_or("Invalid socket path")?;

    let count = match cmd_args.value_of("socket_count") {
        Some(count) => count.parse::<u32>().unwrap(),
        None => 1,
    };

    let source = match cmd_args.value_of("rng_source") {
        Some(source) => source.to_string(),
        None => "/dev/urandom".to_string(),
    };

    let period_ms: u128 = match cmd_args.value_of("period") {
        Some(period_ms) => period_ms.parse::<u128>().unwrap(),
        None => 1 << 16,
    };

    let max_bytes: usize = match cmd_args.value_of("max_bytes") {
        Some(max_bytes) => max_bytes.parse::<usize>().unwrap(),
        None => std::u64::MAX as usize,
    };

    for i in 0..count {
        let socket = path.to_owned() + &i.to_string();
        let source = source.clone();

        let handle = thread::spawn(move ||
            loop {
                let vu_rng_backend = Arc::new(RwLock::new(
                                        VuRngBackend::new(source.clone().as_str(),
                                        period_ms, max_bytes).unwrap()));

                let listener = Listener::new(socket.clone(), true).unwrap();
                let mut daemon = VhostUserDaemon::new(String::from("vhost-user-RNG-daemon"),
                                                      vu_rng_backend.clone()).unwrap();
                daemon.start(listener).unwrap();

                if let Err(e) = daemon.wait() {
                    println!("Error running daemon: {:?}", e);
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
        handle.join().unwrap();
    }
}

fn main() {
    let yaml = load_yaml!("cli.yaml");
    let cmd_args = App::from(yaml).get_matches();

    start_backend(cmd_args);
}