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

//! Fuzzes Select event-stream framing and sequence boundaries with arbitrary call scripts.
//!
//! Responsible for: the libFuzzer entry point for the `event_stream_frame` property.
//! NOT responsible for: the property itself, or the fixed-seed replay that runs it on stable.
//! Upstream: libFuzzer bytes; seed it from `fuzz/seeds/event_stream_frame/`, listed after a
//! writable corpus directory so new inputs never land among the committed seeds:
//! `cargo +nightly fuzz run event_stream_frame fuzz/corpus/event_stream_frame fuzz/seeds/event_stream_frame`.
//! Downstream: `rustfs_gateway_core::ops::shared::event_stream`, through
//! `fuzz/support/event_stream_frame.rs`.

#![no_main]

#[path = "../support/event_stream_frame.rs"]
mod event_stream_frame;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _ = event_stream_frame::check(input);
});
