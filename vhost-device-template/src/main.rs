// VIRTIO FOO Emulation via vhost-user
//
// Copyright 2023 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{path::PathBuf, process::exit};

use clap::Parser;
use vhost_device_template::{start_backend, Error, FooConfiguration, Result};
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct FooArgs {
    /// Location of vhost-user Unix domain socket.
    #[clap(short, long, value_name = "SOCKET")]
    socket_path: PathBuf,
}

impl TryFrom<FooArgs> for FooConfiguration {
    type Error = Error;

    fn try_from(args: FooArgs) -> Result<Self> {
        // Even though this try_from() conversion always succeeds, in cases where the
        // device's configuration type needs to validate arguments and/or make
        // operations that can fail a TryFrom<_> implementation will be
        // necessary.
        Ok(FooConfiguration {
            socket_path: args.socket_path,
        })
    }
}

fn main() {
    env_logger::init();

    let config = FooConfiguration::try_from(FooArgs::parse()).unwrap();
    if let Err(e) = start_backend(config) {
        log::error!("{e}");
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    impl FooArgs {
        pub(crate) fn from_args(path: &Path) -> FooArgs {
            FooArgs {
                socket_path: path.to_path_buf(),
            }
        }
    }

    #[test]
    fn test_parse_successful() {
        let socket_name = Path::new("vfoo.sock");

        let cmd_args = FooArgs::from_args(socket_name);
        let config = FooConfiguration::try_from(cmd_args).unwrap();

        let expected_config = FooConfiguration {
            socket_path: socket_name.into(),
        };

        assert_eq!(config, expected_config);
    }
}
