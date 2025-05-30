// VIRTIO CONSOLE Emulation via vhost-user
//
// Copyright 2023-2024 VIRTUAL OPEN SYSTEMS SAS. All Rights Reserved.
//          Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
#![deny(
    clippy::undocumented_unsafe_blocks,
    /* groups */
    clippy::correctness,
    clippy::suspicious,
    clippy::complexity,
    clippy::perf,
    clippy::style,
    clippy::nursery,
    //* restriction */
    clippy::dbg_macro,
    clippy::rc_buffer,
    clippy::as_underscore,
    clippy::assertions_on_result_states,
    //* pedantic */
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::ptr_as_ptr,
    clippy::bool_to_int_with_if,
    clippy::borrow_as_ptr,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_lossless,
    clippy::cast_ptr_alignment,
    clippy::naive_bytecount
)]

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

    /// Virtual machine communication endpoint.
    /// Unix domain socket path (e.g., "/tmp/vm.sock").
    #[clap(long, required(false), value_name = "VM_SOCKET")]
    uds_path: Option<PathBuf>,

    /// Number of guests (sockets) to connect to.
    #[clap(short = 'c', long, default_value_t = 1)]
    socket_count: u32,

    /// Console backend (Network, Nested, Uds) to be used.
    #[clap(short = 'b', long, value_enum, default_value = "nested")]
    backend: BackendType,

    /// Initial tcp port to be used with `network` backend. If socket_count is
    /// `N` then the following tcp ports will be created: `tcp_port`,
    /// `tcp_port + 1`, ... , `tcp_port + (N - 1)`.
    #[clap(short = 'p', long, value_name = "PORT")]
    tcp_port: Option<String>,

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

        if args.backend == BackendType::Nested {
            if args.socket_count != 1 {
                return Err(Error::WrongBackendSocket);
            }

            if (args.tcp_port.as_ref().map_or(false, |s| !s.is_empty()))
                || (args
                    .uds_path
                    .as_ref()
                    .map_or(false, |path| !path.as_os_str().is_empty()))
            {
                return Err(Error::InvalidCmdlineOption);
            }
        }

        if args.backend == BackendType::Network
            && args
                .uds_path
                .as_ref()
                .map_or(false, |path| !path.as_os_str().is_empty())
        {
            return Err(Error::InvalidCmdlineOption);
        }

        if args.backend == BackendType::Uds
            && args.tcp_port.as_ref().map_or(false, |s| !s.is_empty())
        {
            return Err(Error::InvalidCmdlineOption);
        }

        let ConsoleArgs {
            socket_path,
            uds_path,
            backend,
            tcp_port,
            socket_count,
            max_queue_size,
        } = args;

        // check validation of uds_path under Uds mode.
        if backend == BackendType::Uds {
            let path = uds_path
                .as_ref()
                .filter(|p| !p.as_os_str().is_empty())
                .ok_or(Error::InvalidUdsFile)?;

            if let Some(parent_dir) = path.parent() {
                if !parent_dir.exists() {
                    return Err(Error::InvalidUdsFile);
                }
            }
        }

        Ok(Self {
            socket_path,
            uds_path: uds_path.unwrap_or_default(),
            backend,
            tcp_port: tcp_port.unwrap_or_default(),
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
