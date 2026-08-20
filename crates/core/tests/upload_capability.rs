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

//! The upload-id exchange: what it refuses, and what it refuses to even look up.
//!
//! Responsible for: the two halves of the ownership resolution — that a genuine id belonging to
//! another bucket or another key is refused exactly as an invented one is, and that the shapes an
//! id can never have are refused *before* storage is consulted — plus the single refusal every
//! path renders, which is what stops the error document from telling a caller whether the id it
//! guessed is real.
//! NOT responsible for: how any backend stores an upload (the lookup is a closure here), the
//! wire status the code maps to (`model/overlays/error-status.toml` owns that), or the conformance
//! corpus's end-to-end view of the same rule (`cases/mpu/c-mpu-0028`..`0031`).
//! Upstream: `rustfs_gateway_core::ops::shared::upload_id`. Downstream: nothing.

use std::cell::Cell;

use rustfs_gateway_core::ops::shared::upload_id::{RecordedUpload, UploadIdClaim, UploadRejection, resolve_upload};
use rustfs_gateway_types::{BucketName, ErrorCode, ObjectKey};

/// One upload as a backend recorded it.
struct Recorded {
    bucket: &'static str,
    key: &'static str,
}

impl RecordedUpload for Recorded {
    fn bucket(&self) -> &str {
        self.bucket
    }

    fn key(&self) -> &str {
        self.key
    }
}

fn bucket(name: &str) -> BucketName {
    BucketName::new(name).expect("the test names a legal bucket")
}

fn key(name: &str) -> ObjectKey {
    ObjectKey::new(name).expect("the test names a legal key")
}

/// A storage stub that counts how many times it was asked, so "storage was never consulted" is an
/// observation rather than a claim.
struct Store {
    record: Option<Recorded>,
    asked: Cell<usize>,
}

impl Store {
    fn holding(bucket: &'static str, key: &'static str) -> Self {
        Self {
            record: Some(Recorded { bucket, key }),
            asked: Cell::new(0),
        }
    }

    fn empty() -> Self {
        Self {
            record: None,
            asked: Cell::new(0),
        }
    }

    fn lookup(&self, _id: &str) -> Option<&Recorded> {
        self.asked.set(self.asked.get() + 1);
        self.record.as_ref()
    }
}

/// Resolves `id` against `conf-mpu`/`the-right-key` in `store`, returning the outcome and how many
/// times storage was asked.
fn resolve_in(store: &Store, id: &str) -> (Result<String, UploadRejection>, usize) {
    let claim = UploadIdClaim::from_wire(id);
    let outcome = resolve_upload(&claim, &bucket("conf-mpu"), &key("the-right-key"), |raw| store.lookup(raw))
        .map(|(handle, _record)| handle.id().to_owned());
    (outcome, store.asked.get())
}

/// Negative — a genuine id minted for another bucket buys nothing here.
///
/// This is s3s#51 in one assertion: the id exists, so every check that asks only "does this id
/// exist" admits it, and the caller's bytes land in an upload somebody else completes.
#[test]
fn n_an_id_recorded_against_another_bucket_is_refused() {
    let store = Store::holding("conf-mpu-other", "the-right-key");
    let (outcome, asked) = resolve_in(&store, "conformance-upload-0001");

    let rejection = outcome.expect_err("an id from another bucket resolves to nothing here");
    assert_eq!(rejection.code(), &ErrorCode::NO_SUCH_UPLOAD);
    // The record was read, which is the point: the refusal comes from comparing it, not from
    // failing to find it.
    assert_eq!(asked, 1, "the record has to be read before it can be compared");
}

/// Negative — same bucket, same credentials, wrong object.
///
/// The case a bucket-scoped check misses. `c-mpu-0030` is the wire-level form.
#[test]
fn n_an_id_recorded_against_another_key_in_the_same_bucket_is_refused() {
    let store = Store::holding("conf-mpu", "some-other-key");
    let (outcome, asked) = resolve_in(&store, "conformance-upload-0001");

    assert_eq!(
        outcome.expect_err("an id from another key resolves to nothing here").code(),
        &ErrorCode::NO_SUCH_UPLOAD
    );
    assert_eq!(asked, 1);
}

/// Negative — an id no record names is refused, and storage was asked, because a well-formed id
/// is exactly the value only storage can adjudicate.
#[test]
fn n_an_id_no_record_names_is_refused_after_the_lookup() {
    let store = Store::empty();
    let (outcome, asked) = resolve_in(&store, "conformance-upload-9999");

    assert_eq!(
        outcome.expect_err("an id nothing recorded resolves to nothing").code(),
        &ErrorCode::NO_SUCH_UPLOAD
    );
    assert_eq!(asked, 1);
}

/// Negative — the three refusals are one refusal.
///
/// A caller who can tell "wrong bucket" from "no such id" apart — by the code, by the message, by
/// anything — has been told the id it guessed is genuine, which is the whole of what the id was
/// protecting. So the refusals are compared field for field rather than merely both being errors.
#[test]
fn n_every_refusal_renders_the_same_document() {
    let wrong_bucket = resolve_in(&Store::holding("conf-mpu-other", "the-right-key"), "conformance-upload-0001").0;
    let wrong_key = resolve_in(&Store::holding("conf-mpu", "some-other-key"), "conformance-upload-0001").0;
    let absent = resolve_in(&Store::empty(), "conformance-upload-9999").0;
    let malformed = resolve_in(&Store::holding("conf-mpu", "the-right-key"), "../../etc/passwd").0;

    let rendered: Vec<(ErrorCode, &'static str)> = [wrong_bucket, wrong_key, absent, malformed]
        .into_iter()
        .map(|outcome| {
            let rejection = outcome.expect_err("all four are refusals");
            (rejection.code().clone(), rejection.reason())
        })
        .collect();

    let first = rendered.first().expect("four outcomes were collected").clone();
    for (code, reason) in &rendered {
        assert_eq!(
            (code.clone(), *reason),
            first,
            "two upload-id refusals are distinguishable, which tells a caller its guess was real"
        );
    }
}

/// Negative — a shape no upload can have never reaches storage.
///
/// Not a style rule. A backend that lays an upload out under its id — which is what a filesystem
/// backend does — turns `..` into an escape from the directory the upload lives in, and turns a
/// leading `/` into an absolute path that `Path::join` substitutes for the base wholesale. Refusing
/// the shape *before* the lookup is what makes "reaches nothing" true rather than incidental on the
/// store missing.
#[test]
fn n_a_shape_no_minted_id_can_have_is_refused_before_storage_is_asked() {
    for id in [
        "",
        "../../etc/passwd",
        "..",
        "uploads/../../etc/passwd",
        "/etc/passwd",
        "conformance-upload-0001\u{0}",
        "conformance-upload\n0001",
        "conformance-upload-0001\u{7f}",
    ] {
        let store = Store::holding("conf-mpu", "the-right-key");
        let (outcome, asked) = resolve_in(&store, id);

        assert_eq!(
            outcome
                .as_ref()
                .err()
                .unwrap_or_else(|| panic!("{id:?} names no upload this service could have minted"))
                .code(),
            &ErrorCode::NO_SUCH_UPLOAD,
            "{id:?}"
        );
        assert_eq!(asked, 0, "{id:?} was carried to storage before it was refused");
    }
}

/// Negative — the control for the floor above, in the other direction.
///
/// A floor that refused every id containing the two characters `..` would refuse ids AWS itself
/// mints: an upload id is opaque base64-ish text and dots inside a run of characters are ordinary.
/// Only a whole path *segment* of `..` is an escape. Each of these is admitted and reaches the
/// store, so the floor is a rule about path structure rather than a substring ban — and a floor
/// widened to a substring ban turns this test red.
#[test]
fn n_an_id_whose_dots_are_not_a_path_segment_reaches_storage() {
    for id in [
        "VXBsb2Fk..SUQ",
        "conformance..upload..0001",
        "a/..b/c",
        "..z",
        "z..",
        "VXBsb2FkIElEIGZvcgo+PS8rYWJj",
    ] {
        let store = Store::holding("conf-mpu", "the-right-key");
        let (outcome, asked) = resolve_in(&store, id);

        assert_eq!(asked, 1, "{id:?} is a shape an id may have and must reach the store");
        assert_eq!(
            outcome.expect("the record names this bucket and key"),
            id,
            "the handle carries the id that was resolved"
        );
    }
}

/// Positive — the one path that produces a handle, and it asks storage exactly once.
///
/// `asked == 1` rather than `asked >= 1`: a resolver that looked the id up twice would be a
/// time-of-check/time-of-use window, and the id it compared would not have to be the id it
/// returned.
#[test]
fn an_id_recorded_against_this_bucket_and_key_resolves_once() {
    let store = Store::holding("conf-mpu", "the-right-key");
    let claim = UploadIdClaim::from_wire("conformance-upload-0001");
    let (handle, record) = resolve_upload(&claim, &bucket("conf-mpu"), &key("the-right-key"), |raw| store.lookup(raw))
        .expect("an id recorded against this bucket and key resolves");

    assert_eq!(handle.id(), "conformance-upload-0001");
    assert_eq!(record.bucket(), "conf-mpu");
    assert_eq!(record.key(), "the-right-key");
    assert_eq!(store.asked.get(), 1, "the id was looked up more than once");
}

/// Negative — the comparison is over bytes, not over anything that folds them.
///
/// A bucket or key comparison that lowercased, trimmed or truncated would let a caller who owns
/// `the-right-key` reach `the-right-key ` or `The-Right-Key`. Object keys are case-sensitive and
/// may carry trailing whitespace, so each of these is a different object.
#[test]
fn n_the_ownership_comparison_folds_nothing() {
    for (recorded_bucket, recorded_key) in [
        ("conf-mpu", "The-Right-Key"),
        ("conf-mpu", "the-right-key "),
        ("conf-mpu", "the-right-ke"),
        ("conf-mpu", "the-right-keys"),
        ("conf-mpu-", "the-right-key"),
    ] {
        let store = Store::holding(recorded_bucket, recorded_key);
        let (outcome, _) = resolve_in(&store, "conformance-upload-0001");
        assert!(
            outcome.is_err(),
            "an upload recorded against {recorded_bucket}/{recorded_key} was accepted for conf-mpu/the-right-key"
        );
    }
}
