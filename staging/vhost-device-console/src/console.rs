// Console backend device
//
// Copyright 2023-2024 VIRTUAL OPEN SYSTEMS SAS. All Rights Reserved.
//          Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use crate::virtio_console::VirtioConsoleConfig;
use clap::ValueEnum;
use log::trace;

#[derive(ValueEnum, Clone, Copy, Default, Debug, Eq, PartialEq)]
pub enum BackendType {
    #[default]
    Nested,
    Network,
}

#[derive(Debug)]
pub(crate) struct ConsoleController {
    config: VirtioConsoleConfig,
    pub backend: BackendType,
    pub exit: bool,
}

impl ConsoleController {
    pub(crate) fn new(backend: BackendType) -> ConsoleController {
        ConsoleController {
            config: VirtioConsoleConfig {
                cols: 20.into(),
                rows: 20.into(),
                max_nr_ports: 1.into(),
                emerg_wr: 64.into(),
            },
            backend,
            exit: false,
        }
    }

    pub(crate) fn config(&self) -> &VirtioConsoleConfig {
        trace!("Get config\n");
        &self.config
    }
}
