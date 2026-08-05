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

//! The kernel-side transfer negotiation, refusal by refusal.
//!
//! Responsible for: that every refusal is attributable, that the security order holds, that a
//! refusal never consumes the payload, and that every refusal reaches a counter.
//! NOT responsible for: performing a transfer; nothing here opens a socket.
//! Upstream: `zero_copy`, `payload`, `metrics`. Downstream: nothing.

#![cfg(unix)]

use bytes::Bytes;

use crate::metrics::StreamMetrics;
use crate::payload::Payload;
use crate::zero_copy::{NoZeroCopy, TransportCaps, VerificationObligation, ZeroCopyQuery};

fn file_region(len: u64) -> crate::file_region::FileRegion {
    use std::os::fd::OwnedFd;

    let file = std::fs::File::open("/dev/null").expect("/dev/null is readable");
    crate::file_region::FileRegion::new(OwnedFd::from(file), 0, len).expect("the region does not overflow")
}

fn sendfile() -> TransportCaps {
    TransportCaps::VECTORED | TransportCaps::SENDFILE
}

/// Positive: a file-backed body, a transport that can send it, and nothing left to verify.
#[test]
fn a_capable_transport_takes_the_file_region() {
    let metrics = StreamMetrics::new();
    let query = ZeroCopyQuery::new(sendfile(), VerificationObligation::None);

    let region = Payload::File(file_region(4096))
        .try_into_file_region_for(&query, &metrics)
        .expect("a capable transport may take a file region");

    assert_eq!(region.len(), 4096);
    assert_eq!(metrics.zero_copy_refusals_total(), 0);
}

/// Positive: `splice` alone is a kernel-side path too.
#[test]
fn splice_alone_counts_as_a_kernel_side_path() {
    let query = ZeroCopyQuery::new(TransportCaps::SPLICE, VerificationObligation::None);
    assert_eq!(query.refusal(), None);
}

/// Negative: an in-memory body is refused by name, and comes back whole.
#[test]
fn an_in_memory_body_is_refused_as_not_file_backed_and_is_returned() {
    let metrics = StreamMetrics::new();
    let query = ZeroCopyQuery::new(sendfile(), VerificationObligation::None);

    let (payload, reason) = Payload::from_bytes(Bytes::from_static(b"twelve bytes"))
        .try_into_file_region_for(&query, &metrics)
        .expect_err("an in-memory body has no descriptor");

    assert_eq!(reason, NoZeroCopy::NotFileBacked);
    assert_eq!(payload.len_hint(), Some(12), "the refusal must not consume the body");
    assert_eq!(metrics.zero_copy_refusals(NoZeroCopy::NotFileBacked), 1);
    assert_eq!(metrics.zero_copy_refused_bytes_total(), 12);
}

/// Negative: no kernel-side path, so a 1 GiB response degrades — and the degradation is visible
/// as a count *and* as a byte total, which is the whole point of not returning `None`.
#[test]
fn a_transport_without_sendfile_is_refused_and_the_degradation_is_counted() {
    let metrics = StreamMetrics::new();
    let query = ZeroCopyQuery::new(TransportCaps::VECTORED, VerificationObligation::None);
    let gib = 1024 * 1024 * 1024;

    let (payload, reason) = Payload::File(file_region(gib))
        .try_into_file_region_for(&query, &metrics)
        .expect_err("this transport cannot send a file region");

    assert_eq!(reason, NoZeroCopy::TransportLacksSendfile);
    assert_eq!(payload.len_hint(), Some(gib));
    assert_eq!(metrics.zero_copy_refusals(NoZeroCopy::TransportLacksSendfile), 1);
    assert_eq!(metrics.zero_copy_refused_bytes_total(), gib);
}

/// Negative: TLS has to read every byte, so a file region cannot be handed to the kernel.
#[test]
fn tls_in_the_path_is_refused_by_that_name() {
    let metrics = StreamMetrics::new();
    let query = ZeroCopyQuery::new(sendfile() | TransportCaps::TLS_IN_PATH, VerificationObligation::None);

    let (_, reason) = Payload::File(file_region(64))
        .try_into_file_region_for(&query, &metrics)
        .expect_err("TLS must see the bytes");

    assert_eq!(reason, NoZeroCopy::TlsInPath);
    assert_eq!(metrics.zero_copy_refusals(NoZeroCopy::TlsInPath), 1);
}

/// Negative, and the one that matters: a body that still owes a verification is refused even by
/// the most capable transport. A fast path that moves unverified bytes is a validation bypass.
#[test]
fn an_outstanding_verification_obligation_refuses_the_most_capable_transport() {
    let metrics = StreamMetrics::new();
    let query = ZeroCopyQuery::new(sendfile() | TransportCaps::SPLICE, VerificationObligation::Present);

    let (payload, reason) = Payload::File(file_region(64))
        .try_into_file_region_for(&query, &metrics)
        .expect_err("an unverified body may not be moved unseen");

    assert_eq!(reason, NoZeroCopy::VerificationObligationPresent);
    assert_eq!(payload.len_hint(), Some(64));
    assert_eq!(metrics.zero_copy_refusals(NoZeroCopy::VerificationObligationPresent), 1);
}

/// Negative: the refusal order is the security order. With an obligation *and* TLS *and* no
/// kernel path, the reported reason is the obligation — the one that would still refuse if the
/// other two were fixed.
#[test]
fn the_obligation_outranks_every_other_reason() {
    let query = ZeroCopyQuery::new(TransportCaps::TLS_IN_PATH, VerificationObligation::Present);
    assert_eq!(query.refusal(), Some(NoZeroCopy::VerificationObligationPresent));

    let query = ZeroCopyQuery::new(TransportCaps::TLS_IN_PATH, VerificationObligation::None);
    assert_eq!(query.refusal(), Some(NoZeroCopy::TlsInPath));

    let query = ZeroCopyQuery::new(TransportCaps::empty(), VerificationObligation::None);
    assert_eq!(query.refusal(), Some(NoZeroCopy::TransportLacksSendfile));
}

/// Negative: an obligation refuses before the payload's own shape is even looked at, so the
/// counter attributes it to the obligation and not to "not file backed".
#[test]
fn an_obligation_is_reported_before_the_payload_shape() {
    let metrics = StreamMetrics::new();
    let query = ZeroCopyQuery::new(sendfile(), VerificationObligation::Present);

    let (_, reason) = Payload::from_bytes(Bytes::from_static(b"x"))
        .try_into_file_region_for(&query, &metrics)
        .expect_err("the obligation refuses first");

    assert_eq!(reason, NoZeroCopy::VerificationObligationPresent);
    assert_eq!(metrics.zero_copy_refusals(NoZeroCopy::NotFileBacked), 0);
}

/// Negative: the payload-only form can only ever say "not file backed"; it must not be mistaken
/// for the transport-aware negotiation.
#[test]
fn the_payload_only_form_never_invents_a_transport_reason() {
    let (_, reason) = Payload::Empty
        .try_into_file_region()
        .expect_err("an empty payload is not a file region");
    assert_eq!(reason, NoZeroCopy::NotFileBacked);
}

/// Every reason has a distinct label, so a metric label cannot collapse two of them.
#[test]
fn every_refusal_reason_has_a_distinct_label() {
    let labels = [
        NoZeroCopy::NotFileBacked.as_str(),
        NoZeroCopy::TransportLacksSendfile.as_str(),
        NoZeroCopy::VerificationObligationPresent.as_str(),
        NoZeroCopy::TlsInPath.as_str(),
    ];
    for (index, label) in labels.iter().enumerate() {
        assert!(!labels[index + 1..].contains(label), "duplicate refusal label {label}");
    }
}
