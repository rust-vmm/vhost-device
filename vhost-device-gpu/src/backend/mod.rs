// Copyright 2025 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

#[cfg(any(feature = "backend-virgl", feature = "backend-gfxstream"))]
mod common;
#[cfg(feature = "backend-gfxstream")]
pub mod gfxstream;
pub mod null;
#[cfg(feature = "backend-virgl")]
pub mod virgl;
