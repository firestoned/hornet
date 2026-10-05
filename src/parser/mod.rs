// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

pub mod common;
pub mod named_conf;
pub mod zone_file;

pub use named_conf::parse_named_conf;
pub use zone_file::parse_zone_file;
