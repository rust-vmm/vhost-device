// Console backend device
//
// Copyright 2023-2024 VIRTUAL OPEN SYSTEMS SAS. All Rights Reserved.
//          Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use clap::ValueEnum;
use log::trace;

use crate::virtio_console::VirtioConsoleConfig;

#[derive(ValueEnum, Clone, Copy, Default, Debug, Eq, PartialEq)]
pub enum BackendType {
    #[default]
    Nested,
    Network,
    Uds,
}

#[derive(Debug)]
pub struct ConsoleController {
    config: VirtioConsoleConfig,
    pub backend: BackendType,
}

impl ConsoleController {
    pub fn new(backend: BackendType) -> Self {
        Self {
            config: VirtioConsoleConfig {
                cols: 20.into(),
                rows: 20.into(),
                max_nr_ports: 1.into(),
                emerg_wr: 64.into(),
            },
            backend,
        }
    }

    pub fn config(&self) -> &VirtioConsoleConfig {
        trace!("Get config");
        &self.config
    }
}
