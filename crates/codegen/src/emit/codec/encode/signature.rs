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

//! Width-aware Rust signatures for generated response shape writers.
//!
//! Responsible for: matching the repository formatter without changing a writer signature.
//! NOT responsible for: field bindings, XML layout, or deciding which shapes need writers.
//! Upstream: response shape emission. Downstream: generated codec source.

/// rustfmt's `max_width` for this repository.
const MAX_WIDTH: usize = 130;

/// The signature of one shape writer, laid out the way rustfmt would lay it out.
///
/// `cargo fmt` follows `#[path]` into `generated/`, so a signature past `max_width` makes
/// `cargo xtask spec verify` fail the moment anybody formats the tree — and the shape names are
/// upstream's, so how long they get is not something this emitter controls.
///
/// `encodes` adds the url-encoding decision, for a shape that has a member to apply it to.
pub(super) fn shape_writer_signature(module: &str, type_name: &str, encodes: bool) -> String {
    let encoding = if encodes { ", url_encoding: value::UrlEncoding" } else { "" };
    let single = format!(
        "fn write_{module}(writer: &mut rustfs_gateway_xml::XmlWriter, value: &dto::{type_name}{encoding}) -> Result<(), CodecError> {{\n"
    );
    if single.len().saturating_sub(1) <= MAX_WIDTH {
        return single;
    }
    let wrapped = if encodes {
        "\n    url_encoding: value::UrlEncoding,"
    } else {
        ""
    };
    format!(
        "fn write_{module}(\n    writer: &mut rustfs_gateway_xml::XmlWriter,\n    value: &dto::{type_name},{wrapped}\n) -> Result<(), CodecError> {{\n"
    )
}
