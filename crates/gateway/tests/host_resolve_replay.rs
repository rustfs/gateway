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

//! Fixed-seed replay of the `host_resolve` fuzz property inside the ordinary test gate.
//!
//! Responsible for: running every committed seed under `fuzz/seeds/host_resolve/` through the same
//! property file the fuzz target runs, pinning the exact outcome of the ten hand-written seeds, and
//! driving one hundred thousand deterministic samples through that property on stable.
//! NOT responsible for: fuzzing — `ci.yml` defers libFuzzer runs to a schedule — or the hand-picked
//! resolution cases in `tests/vhost_resolution.rs`, which name one shape each.
//! Upstream: `fuzz/support/host_resolve.rs` and the committed seeds. Downstream: Cargo's harness.

use std::path::{Path, PathBuf};

use rustfs_gateway::{Addressing, TargetKind, TargetOrigin, VhostHint};

#[path = "../../../fuzz/support/host_resolve.rs"]
mod host_resolve;

use host_resolve::{DOMAINS, Outcome, Resolution, check, encode};

/// The seeds the property's two directions rest on. Each must exist; none may be skipped.
const REQUIRED_SEEDS: [&str; 10] = [
    "vhost-path-first-segment",
    "vhost-case-root-dot-port",
    "vhost-region",
    "longest-match",
    "suffix-without-boundary",
    "domain-mid-host",
    "ipv4-under-numeric-domain",
    "unserved-hint",
    "served-endpoint-no-hint",
    "not-a-header-value",
];

fn seed_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/host_resolve")
}

fn replay(name: &str) -> Outcome {
    let path = seed_dir().join(name);
    let input = std::fs::read(&path).unwrap_or_else(|error| panic!("required seed {} is missing: {error}", path.display()));
    check(&input).unwrap_or_else(|| panic!("seed {name} is shorter than the case header"))
}

fn resolved(name: &str) -> Resolution {
    match replay(name) {
        Outcome::Resolved(resolution) => resolution,
        Outcome::NotAccepted => panic!("seed {name} was not accepted"),
    }
}

fn meta(bucket: &str, key: Option<&str>) -> Result<(Option<String>, Option<String>), ()> {
    Ok((Some(bucket.to_owned()), key.map(str::to_owned)))
}

// ---------------------------------------------------------------------------------------------
// Positive — a host that names a bucket.
// ---------------------------------------------------------------------------------------------

/// The cross-tenant shape: the host names `owner-bucket`, the path starts with `victim-bucket`.
/// The bucket acted on is the host's and `victim-bucket/key` is one key. Reading the first segment
/// as a bucket would act on somebody else's bucket under a request signed for this one.
#[test]
fn the_host_bucket_wins_and_the_first_path_segment_is_part_of_the_key() {
    let resolution = resolved("vhost-path-first-segment");
    assert_eq!(resolution.resolved.bucket().map(|bucket| bucket.as_str()), Some("owner-bucket"));
    assert_eq!(resolution.resolved.origin(), TargetOrigin::Host);
    assert_eq!(resolution.resolved.target, TargetKind::Object);
    assert_eq!(resolution.meta, meta("owner-bucket", Some("victim-bucket/key")));
}

/// Case, a root dot and a port are matched away; the property has already checked that the
/// signed bytes kept all three.
#[test]
fn a_mixed_case_host_with_root_dot_and_port_still_names_its_bucket() {
    let resolution = resolved("vhost-case-root-dot-port");
    assert_eq!(resolution.resolved.bucket().map(|bucket| bucket.as_str()), Some("conf-host"));
    assert_eq!(resolution.meta, meta("conf-host", Some("key")));
}

/// The region form carries its region, and `/` on a virtual host is the bucket itself.
#[test]
fn the_region_form_carries_its_region_and_the_root_is_the_bucket() {
    let resolution = resolved("vhost-region");
    assert_eq!(resolution.resolved.region(), Some("us-west-2"));
    assert_eq!(resolution.resolved.target, TargetKind::Bucket);
    assert_eq!(resolution.meta, meta("conf-host", None));
}

/// Under `s3.example.com` the prefix is `conf-host.s3`; under the shorter `example.com` it would
/// be `conf-host.s3.s3` and `s3` would become a region. The longest domain decides.
#[test]
fn the_longest_configured_domain_decides_the_prefix() {
    let resolution = resolved("longest-match");
    assert_eq!(resolution.resolved.bucket().map(|bucket| bucket.as_str()), Some("conf-host"));
    assert_eq!(resolution.resolved.region(), None);
}

// ---------------------------------------------------------------------------------------------
// Negative — a host that must not name a bucket, and a host that must not be read at all.
// ---------------------------------------------------------------------------------------------

/// s3s#648: `evil-notmys3.com` ends with `mys3.com` and is not under it. Path style reads `key`
/// as the bucket — a bucket the path named, not one the host invented.
#[test]
fn a_suffix_without_a_label_boundary_names_no_bucket() {
    let resolution = resolved("suffix-without-boundary");
    assert_eq!(resolution.resolved.addressing, Addressing::Path);
    assert_eq!(resolution.meta, meta("key", None));
}

/// A configured domain as whole labels in the middle of a foreign host is not a suffix.
#[test]
fn a_configured_domain_in_the_middle_of_the_host_names_no_bucket() {
    let resolution = resolved("domain-mid-host");
    assert_eq!(resolution.resolved.addressing, Addressing::Path);
    assert_eq!(resolution.meta, meta("key", None));
}

/// `192.168.1.1` ends with the configured `168.1.1` on a label boundary and is still an address;
/// its path-style request keeps working (s3s#147/#150, s3s#643).
#[test]
fn an_address_under_a_numeric_domain_stays_a_working_path_style_request() {
    let resolution = resolved("ipv4-under-numeric-domain");
    assert_eq!(resolution.resolved.addressing, Addressing::Path);
    assert_eq!(resolution.resolved.target, TargetKind::Object);
    assert_eq!(resolution.meta, meta("conf-host", Some("key")));
}

/// s3s#259: a bucket write at the root of an unserved vhost-shaped host earns the hint, and the
/// hint does not turn it into a virtual-hosted request.
#[test]
fn an_unserved_vhost_shaped_write_earns_the_hint_and_stays_path_style() {
    let resolution = resolved("unserved-hint");
    assert_eq!(resolution.resolved.diagnostic, Some(VhostHint::LooksLikeVhostButNotConfigured));
    assert_eq!(resolution.resolved.addressing, Addressing::Path);
    assert_eq!(resolution.resolved.target, TargetKind::Service);
}

/// The other direction of the hint: the same write to a served endpoint is not a misconfiguration.
#[test]
fn the_same_write_to_a_served_endpoint_earns_no_hint() {
    let resolution = resolved("served-endpoint-no-hint");
    assert_eq!(resolution.resolved.diagnostic, None);
    assert_eq!(resolution.resolved.target, TargetKind::Service);
}

/// A byte no `Host` header can carry is refused before any resolver runs.
#[test]
fn a_host_no_header_can_carry_is_never_resolved() {
    assert!(matches!(replay("not-a-header-value"), Outcome::NotAccepted));
}

/// Every committed seed — the ten above and any minimised regression added later — replays under
/// the property's own assertions. A missing directory or required seed fails, not skips.
#[test]
fn every_committed_seed_replays_under_the_fuzz_property() {
    let dir = seed_dir();
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("seed directory {} is missing: {error}", dir.display()))
        .map(|entry| {
            entry
                .expect("a readable directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    for required in REQUIRED_SEEDS {
        assert!(names.iter().any(|name| name == required), "required seed {required} is missing");
    }
    for name in &names {
        replay(name);
    }
}

// ---------------------------------------------------------------------------------------------
// One hundred thousand deterministic samples.
// ---------------------------------------------------------------------------------------------

/// Labels a host is built from: every configured domain's labels, the near-misses of them, the
/// prefix-shape vocabulary, and names no bucket can have.
const LABELS: [&str; 20] = [
    "mys3",
    "com",
    "s3",
    "example",
    "168",
    "1",
    "192",
    "localhost",
    "evil",
    "notmys3",
    "conf-host",
    "victim-bucket",
    "us-west-2",
    "xn--80ak6aa92e",
    "",
    "ab",
    "_bad_",
    "UPPER",
    "net",
    "io",
];

/// Paths after the leading `/`, each a different split for a path-style reading.
const PATHS: [&str; 9] = [
    "",
    "key",
    "victim-bucket/key",
    "/",
    "a/b/c",
    "victim-bucket/",
    "%41b",
    "k%2Fey",
    "a//b",
];

/// A xorshift sequence: a failed sample is reproducible from its index alone.
struct Sampler(u64);

impl Sampler {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound).expect("a small bound")).expect("below a usize bound")
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }

    fn label(&mut self) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";
        (0..self.below(66))
            .map(|_| char::from(ALPHABET[self.below(ALPHABET.len())]))
            .collect()
    }

    fn decorate(&mut self, mut host: String) -> Vec<u8> {
        if self.below(4) == 0 {
            host = host.to_ascii_uppercase();
        }
        if self.below(4) == 0 {
            host.push('.');
        }
        if self.below(4) == 0 {
            host.push_str(":9000");
        }
        host.into_bytes()
    }

    /// One input: a method, a host drawn from one of seven shapes, and a path.
    fn sample(&mut self) -> Vec<u8> {
        let method = u8::try_from(self.below(5)).expect("five methods");
        let host = match self.below(8) {
            // Arbitrary bytes, most of which acceptance refuses.
            0 => (0..self.below(256)).map(|_| self.next().to_le_bytes()[0]).collect(),
            // A configured domain glued to a label with no dot: s3s#648's shape.
            1 => {
                let host = format!("{}{}", self.label(), self.pick(&DOMAINS));
                self.decorate(host)
            }
            // A configured domain followed by a foreign one.
            2 => {
                let host = format!("{}.{}.{}.net", self.label(), self.pick(&DOMAINS), self.label());
                self.decorate(host)
            }
            // One label in front of a configured domain.
            3 => {
                let host = format!("{}.{}", self.label(), self.pick(&DOMAINS));
                self.decorate(host)
            }
            // The `s3` and region forms, with plausible and implausible regions.
            4 => {
                let region = if self.below(2) == 0 {
                    self.pick(&["us-west-2", "r1", "-lead", "UP", "a_b", "s3"]).to_owned()
                } else {
                    self.label()
                };
                let host = format!("{}.s3.{region}.{}", self.label(), self.pick(&DOMAINS));
                self.decorate(host)
            }
            // Address literals.
            5 => self
                .pick(&[
                    "192.168.1.1",
                    "192.168.1.1:8014",
                    "[2001:db8::1]:9000",
                    "[::1]",
                    "10.0.0.1.mys3.com",
                ])
                .as_bytes()
                .to_vec(),
            // Label soup over the vocabulary above.
            _ => {
                let labels: Vec<String> = (0..=self.below(6))
                    .map(|_| {
                        if self.below(3) == 0 {
                            self.label()
                        } else {
                            self.pick(&LABELS).to_owned()
                        }
                    })
                    .collect();
                self.decorate(labels.join("."))
            }
        };
        let path = if self.below(4) == 0 {
            (0..self.below(20))
                .map(|_| 0x21 + self.next().to_le_bytes()[0] % 0x5e)
                .collect()
        } else {
            self.pick(&PATHS).as_bytes().to_vec()
        };
        encode(method, &host, &path)
    }
}

/// The label-boundary property, one hundred thousand times: every sample runs under every assertion
/// in `fuzz/support/host_resolve.rs`. The counts at the end are the other half — a sampler that
/// drifted into producing only refusals, or only path-style hosts, would pass every assertion
/// above while testing nothing.
#[test]
fn one_hundred_thousand_fixed_seed_samples_hold_the_host_property() {
    let mut sampler = Sampler(0x686f_7374_2d72_6573);
    let (mut refused, mut path_style, mut virtual_hosted, mut hinted, mut split) = (0u32, 0u32, 0u32, 0u32, 0u32);
    for _ in 0..100_000 {
        let input = sampler.sample();
        match check(&input).expect("every sample carries the case header") {
            Outcome::NotAccepted => refused += 1,
            Outcome::Resolved(resolution) => {
                if resolution.resolved.diagnostic.is_some() {
                    hinted += 1;
                }
                if resolution.resolved.bucket().is_some() {
                    virtual_hosted += 1;
                    if resolution.meta.as_ref().is_ok_and(|(_, key)| key.is_some()) {
                        split += 1;
                    }
                } else {
                    path_style += 1;
                }
            }
        }
    }
    assert!(refused >= 5_000, "only {refused} samples exercised the acceptance boundary");
    assert!(path_style >= 30_000, "only {path_style} samples resolved path style");
    assert!(virtual_hosted >= 10_000, "only {virtual_hosted} samples named a bucket");
    assert!(hinted >= 200, "only {hinted} samples earned the hint");
    assert!(split >= 5_000, "only {split} virtual-hosted samples compared a key");
}
