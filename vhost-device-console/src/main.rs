// VIRTIO CONSOLE Emulation via vhost-user
//
// Copyright 2023-2024 VIRTUAL OPEN SYSTEMS SAS. All Rights Reserved.
//          Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod backend;
mod console;
mod vhu_console;
mod virtio_console;
use std::{path::PathBuf, process::exit};

use clap::Parser;
use log::error;

use crate::console::BackendType;

pub type Result<T> = std::result::Result<T, Error>;
use crate::backend::{start_backend, Error, VuConsoleConfig};

const DEFAULT_QUEUE_SIZE: usize = 128;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ConsoleArgs {
    /// Location of vhost-user Unix domain socket. This is suffixed by
    /// `0,1,2..(socket_count-1)`.
    #[clap(short = 's', long, value_name = "SOCKET")]
    socket_path: PathBuf,

    /// Number of guests (sockets) to connect to.
    #[clap(short = 'c', long, default_value_t = 1)]
    socket_count: u32,

    /// Console backend (Network, Nested) to be used.
    #[clap(short = 'b', long, value_enum, default_value = "nested")]
    backend: BackendType,

    /// Initial tcp port to be used with `network` backend. If socket_count is
    /// `N` then the following tcp ports will be created: `tcp_port`,
    /// `tcp_port + 1`, ... , `tcp_port + (N - 1)`.
    #[clap(short = 'p', long, value_name = "PORT", default_value = "12345")]
    tcp_port: String,

    /// Specify the maximum size of virtqueue, the default is 128.
    #[clap(short = 'q', long, default_value_t = DEFAULT_QUEUE_SIZE)]
    max_queue_size: usize,
}

impl TryFrom<ConsoleArgs> for VuConsoleConfig {
    type Error = Error;

    fn try_from(args: ConsoleArgs) -> Result<Self> {
        if args.socket_count == 0 {
            return Err(Error::SocketCountInvalid(0));
        }

        if (args.backend == BackendType::Nested) && (args.socket_count != 1) {
            return Err(Error::WrongBackendSocket);
        }

        let ConsoleArgs {
            socket_path,
            backend,
            tcp_port,
            socket_count,
            max_queue_size,
        } = args;

        Ok(Self {
            socket_path,
            backend,
            tcp_port,
            socket_count,
            max_queue_size,
        })
    }
}

fn main() {
    env_logger::init();
    if let Err(e) = VuConsoleConfig::try_from(ConsoleArgs::parse()).and_then(start_backend) {
        error!("{e}");
        exit(1);
    }
}
