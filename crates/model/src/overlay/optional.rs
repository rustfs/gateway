// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Optional scalar readers for operation, shape, field and attribute overlays.
//!
//! Responsible for: accepting absent values and rejecting present values of the wrong type or range.
//! NOT responsible for: deciding what a well-typed protocol value means or parsing TOML syntax.
//! Upstream: `overlay` and `toml_lite`. Downstream: typed overlay values consumed by lowering.

use crate::error::{Error, Result};
use crate::toml_lite::Toml;

fn optional<T>(table: &Toml, key: &str, what: &str, read: impl FnOnce(&Toml) -> Option<T>, expected: &str) -> Result<Option<T>> {
    table
        .get(key)
        .map(|value| read(value).ok_or_else(|| Error::Overlay(format!("{what}.{key} must be {expected}"))))
        .transpose()
}

pub(super) fn opt_str(table: &Toml, key: &str, what: &str) -> Result<Option<String>> {
    optional(table, key, what, |value| value.as_str().map(str::to_owned), "a string")
}

pub(super) fn opt_bool(table: &Toml, key: &str, what: &str) -> Result<Option<bool>> {
    optional(table, key, what, Toml::as_bool, "a boolean")
}

pub(super) fn opt_int(table: &Toml, key: &str, what: &str) -> Result<Option<i64>> {
    optional(table, key, what, Toml::as_int, "an integer")
}

pub(super) fn opt_u32(table: &Toml, key: &str, what: &str) -> Result<Option<u32>> {
    optional(
        table,
        key,
        what,
        |value| value.as_int().and_then(|integer| u32::try_from(integer).ok()),
        "an integer in 0..=4294967295",
    )
}

pub(super) fn opt_u16(table: &Toml, key: &str, what: &str) -> Result<Option<u16>> {
    optional(
        table,
        key,
        what,
        |value| value.as_int().and_then(|integer| u16::try_from(integer).ok()),
        "an integer in 0..=65535",
    )
}

pub(super) fn opt_u64(table: &Toml, key: &str, what: &str) -> Result<Option<u64>> {
    optional(
        table,
        key,
        what,
        |value| value.as_int().and_then(|integer| u64::try_from(integer).ok()),
        "a non-negative integer",
    )
}

pub(super) fn alt_success_statuses(table: &Toml, what: &str) -> Result<Vec<u16>> {
    let Some(value) = table.get("alt_success_statuses") else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| Error::Overlay(format!("{what}.alt_success_statuses must be an array of integers")))?;
    items
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .as_int()
                .and_then(|integer| u16::try_from(integer).ok())
                .ok_or_else(|| Error::Overlay(format!("{what}.alt_success_statuses[{index}] must be an integer in 0..=65535")))
        })
        .collect()
}
