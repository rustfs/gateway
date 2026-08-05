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

//! The latency-parity cases `c-sig-0107`, `c-sig-0108` and `c-sig-0111`.
//!
//! Responsible for: showing that where a signature first differs does not change how long the
//! comparison takes, and that the unknown-access-key path and the wrong-signature path do the same
//! amount of work and land on the same failure floor.
//! NOT responsible for: proving constant time. No statistical test can — this is a regression net
//! that catches the *large* differences an early return produces, which is the class of defect
//! that actually ships. Nor is it responsible for the functional half of `c-sig-0111`
//! (`tests/verification_proof.rs`) or for the rate limiting that bounds what a measurement is
//! worth (`Governor`, P6-08).
//! Upstream: the `s3gate-sig` public API. Downstream: none (test target).
//!
//! # Run it in release
//!
//! `cargo test -p s3gate-sig --release --test timing`. In a debug build `subtle`'s `debug_assert!`s
//! add secret-dependent branches of their own, and nothing here is meaningful — which is also why
//! a debug build must never serve production traffic. The thresholds below are therefore
//! deliberately loose in debug and tighter in release, and the test never fails for being slow, only
//! for being *asymmetric*.

use std::hint::black_box;
use std::time::{Duration, Instant};

use s3gate_sig::timing::{CredentialLookup, FailureFloor, placeholder_secret};
use s3gate_sig::{CtBytes, SecretBytes, Signature};

/// Comparisons per timed sample. Large enough that one sample is far above clock resolution.
const BATCH: usize = 2_000;
/// Samples per side. The two sides are interleaved, so drift affects both equally.
const SAMPLES: usize = 201;
/// Rounds; the best (most symmetric) round wins, which absorbs a scheduler hiccup without
/// weakening the assertion — a real early return is asymmetric in every round.
const ROUNDS: usize = 3;

fn tolerance() -> f64 {
    if cfg!(debug_assertions) { 0.35 } else { 0.20 }
}

fn signature_with(first: u8, last: u8) -> Signature {
    let mut bytes = [0x5a; 32];
    bytes[0] = first;
    bytes[31] = last;
    Signature::HmacSha256(CtBytes::from_array(bytes))
}

fn time_batch(presented: &Signature, expected: &Signature) -> Duration {
    let start = Instant::now();
    for _ in 0..BATCH {
        let outcome = black_box(presented).ct_verify(black_box(expected));
        black_box(outcome.is_ok());
    }
    start.elapsed()
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

/// Interleaved A/B measurement. Returns the relative difference of the two medians.
fn relative_difference(a: &(Signature, Signature), b: &(Signature, Signature)) -> f64 {
    // Warm up: first-touch page faults and branch predictor state belong to neither side.
    for _ in 0..8 {
        time_batch(&a.0, &a.1);
        time_batch(&b.0, &b.1);
    }

    let mut a_samples = Vec::with_capacity(SAMPLES);
    let mut b_samples = Vec::with_capacity(SAMPLES);
    for index in 0..SAMPLES {
        // Alternate which side goes first, so a systematic per-pair warm-up cost cannot land on
        // the same side every time.
        if index % 2 == 0 {
            a_samples.push(time_batch(&a.0, &a.1));
            b_samples.push(time_batch(&b.0, &b.1));
        } else {
            b_samples.push(time_batch(&b.0, &b.1));
            a_samples.push(time_batch(&a.0, &a.1));
        }
    }

    let a_median = median(a_samples).as_secs_f64();
    let b_median = median(b_samples).as_secs_f64();
    let smaller = a_median.min(b_median);
    assert!(smaller > 0.0, "the clock produced a zero-length batch; raise BATCH");
    (a_median - b_median).abs() / smaller
}

fn best_relative_difference(a: &(Signature, Signature), b: &(Signature, Signature)) -> f64 {
    (0..ROUNDS).map(|_| relative_difference(a, b)).fold(f64::INFINITY, f64::min)
}

/// Negative — c-sig-0107 / c-sig-0108: where the first differing byte sits does not change how
/// long the comparison takes.
///
/// A byte-wise `PartialEq` returns as soon as it finds a difference, so a signature that differs in
/// byte 0 is rejected in a fraction of the time of one that differs only in byte 31 — and an
/// attacker who can measure that recovers the expected signature one byte at a time without ever
/// knowing the secret. `Signature::ct_verify` reads all 32 bytes either way.
#[test]
fn c_sig_0107_and_0108_the_position_of_the_difference_does_not_change_the_latency() {
    let expected = signature_with(0x5a, 0x5a);
    let differs_first = (signature_with(0x00, 0x5a), signature_with(0x5a, 0x5a));
    let differs_last = (signature_with(0x5a, 0x00), signature_with(0x5a, 0x5a));

    // Sanity: both really are rejections, and neither yields a proof.
    assert!(differs_first.0.ct_verify(&expected).is_err());
    assert!(differs_last.0.ct_verify(&expected).is_err());

    let difference = best_relative_difference(&differs_first, &differs_last);
    println!("timing parity (first-byte vs last-byte difference): {:.4} relative", difference);
    assert!(
        difference < tolerance(),
        "comparison latency depends on where the signatures diverge ({difference:.4} relative, \
         tolerance {:.2}); that is a byte-at-a-time signature oracle",
        tolerance()
    );
}

/// Negative — an equal pair and an unequal pair cost the same.
///
/// The complement of the case above: if a match were cheaper or dearer than a mismatch, an
/// attacker would not need to localise the differing byte to learn something.
#[test]
fn a_match_and_a_mismatch_cost_the_same() {
    let equal = (signature_with(0x5a, 0x5a), signature_with(0x5a, 0x5a));
    let unequal = (signature_with(0x5a, 0x00), signature_with(0x5a, 0x5a));
    assert!(equal.0.ct_verify(&equal.1).is_ok());

    let difference = best_relative_difference(&equal, &unequal);
    println!("timing parity (match vs mismatch): {:.4} relative", difference);
    assert!(
        difference < tolerance(),
        "a matching comparison is distinguishable from a failing one ({difference:.4} relative)"
    );
}

/// Negative — c-sig-0111 (latency half): the unknown-access-key path and the wrong-signature path
/// do the same work and are held to the same floor.
///
/// The two paths differ only in which secret they sign with — a real one or
/// `placeholder_secret()` — so an unknown key is not answered faster than a known one, and an
/// attacker cannot enumerate valid access keys from latency alone. The error codes still differ,
/// because S3 clients branch on them; see the `T1` row of the side-channel register.
#[test]
fn c_sig_0111_an_unknown_key_costs_the_same_as_a_bad_signature() {
    let real = SecretBytes::new(b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    assert!(CredentialLookup::Unknown.requires_parity_work());

    let presented = signature_with(0x01, 0x02);
    let known_path = (presented.clone(), stub_sign(&real));
    let unknown_path = (presented.clone(), stub_sign(&placeholder_secret()));

    let difference = best_relative_difference(&known_path, &unknown_path);
    println!("timing parity (unknown key vs bad signature): {:.4} relative", difference);
    assert!(
        difference < tolerance(),
        "the unknown-access-key path is distinguishable from the bad-signature path \
         ({difference:.4} relative); that enumerates valid access keys without a secret"
    );

    // And whatever the two cost, both are held to the same floor before the answer goes out.
    let floor = FailureFloor::default();
    let cheap = floor.remaining(Duration::from_micros(1));
    let dear = floor.remaining(Duration::from_micros(900));
    assert!(cheap.is_some() && dear.is_some());
    assert!(
        cheap.unwrap_or_default() + Duration::from_micros(1) == dear.unwrap_or_default() + Duration::from_micros(900),
        "the floor must make both rejections land at the same wall-clock time"
    );
}

/// A stand-in for P2-03's derivation: secret-dependent, fixed width, no HMAC.
fn stub_sign(secret: &SecretBytes) -> Signature {
    let bytes = secret.expose();
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        let byte = bytes[index % bytes.len()];
        *slot = byte ^ u8::try_from(index).unwrap_or(0);
    }
    Signature::HmacSha256(CtBytes::from_array(out))
}
