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

//! Every capability domain in the corpus, gated on having *run* rather than on having loaded.
//!
//! Responsible for: one table with one row per `conformance/cases/<domain>/` directory, and the
//! assertion that each domain reached a verdict on the assembled service — a domain may only skip
//! the cases its row names, and a domain nothing can execute yet has to say so in the row with the
//! capability it is waiting on. The table is checked against the corpus in both directions, so a
//! new domain arrives without a gate exactly once.
//! NOT responsible for: what any individual case asserts (that is the case file), the corpus-wide
//! schema and convention invariants (`tests/corpus.rs`), or which cases are green — the
//! `--baseline` ratchet owns that, and the per-family ledgers own their own families' sizes,
//! polarity and known-red sets. See `crates/conformance/MAP.md`.
//! Upstream: the published API of `rustfs_gateway_conformance`. Downstream: nothing.
//!
//! # The hole this closes
//!
//! `conformance/baseline.json` records a verdict per case, and a run fails on a *regression*
//! against it. A skip is not a regression, so the ratchet cannot tell "this family ran and passed"
//! from "this family never ran": unregister one operation and a whole family turns into skips
//! underneath a green ratchet. That is not hypothetical — rustfs/gateway#203 found the `object/`
//! domain had been running against `Unwired` in `cargo test`, so every one of its cases was a skip
//! and its verdicts existed only in a manual `cargo xtask conformance run`.
//!
//! `tests/wired.rs` answers the same question for the corpus as a whole, and deliberately: it asks
//! that at least half of a filtered slice executed, and that the corpus is not back to reporting a
//! hundred and fifty-seven skips. A corpus-wide floor cannot notice one domain out of twenty-five
//! going quiet, and a domain is the granularity at which operations are registered — so it is the
//! granularity at which they get unregistered.
//!
//! # Why one table and not one file per family
//!
//! Seven hand-written ledgers already cover eight domains, each hard-coding its own counts.
//! Seventeen more of those would cost seventeen new Cargo test sources, each of which must be
//! registered in `scripts/check_test_target_consolidation.sh` **and** `tests/integration.rs`;
//! #207 and #208 both edited that frozen tuple within the same hour, and #209 added
//! `range_cond_family.rs` to it while this file was in flight. Every additional source is another
//! branch conflict at the same three lines. The per-domain fact this file needs is one short list,
//! and one short list per domain belongs in a table. The existing ledgers stay exactly as they are:
//! they assert far more than wiring — family size, polarity, baseline membership, which case is red
//! and for which reason — and this file deliberately asserts none of that.
//!
//! # Why the skip lists are subsets and not equalities
//!
//! A row names the cases that are *allowed* to skip, and a domain is red when it skips something
//! the row does not name. Skips may therefore only go down: a branch that recovers a skipped case
//! never turns this red, which is the direction rustfs/gateway#207 chose for
//! `multipart_family.rs`'s `KNOWN_SKIPS` and for the same reason — a guard that argues against its
//! own fix gets weakened, not obeyed. The opposite direction is the one that has to stop a build,
//! and it does: a case that quietly *starts* skipping is named, with its domain, in the failure.

use rustfs_gateway_conformance::corpus::Corpus;
use rustfs_gateway_conformance::inprocess::InProcess;
use rustfs_gateway_conformance::report::{CaseOutcome, Verdict};
use rustfs_gateway_conformance::runner::{self, RunOptions};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

/// What the repository claims about one domain's wiring.
#[derive(Clone, Copy, Debug)]
enum Wiring {
    /// The domain executes. Only the cases named here may skip; every other case in it must reach
    /// a verdict.
    Runs(&'static [&'static str]),
    /// Nothing in the domain executes on the in-process target, and this names its missing capability.
    ///
    /// A domain in this state cannot be gated on wiring — there is nothing wired to gate — so the
    /// row carries the reason instead, and
    /// [`a_deferred_domain_is_still_skipped_everywhere_it_claims_to_be`] checks the claim in both
    /// directions so the row cannot outlive it.
    Deferred(&'static str),
}

/// One row per `conformance/cases/<domain>/` directory.
///
/// The named skips are the six the in-process facade reports today, and every one of them is a case
/// that names the transport capability it needs and is recorded as `skipped` in
/// `conformance/baseline.json`. They are not a licence to skip: adding an identifier here is a
/// decision, and this is where somebody writes it down.
const GATES: &[(&str, Wiring)] = &[
    ("acl", Wiring::Runs(&[])),
    ("authz", Wiring::Runs(&[])),
    ("bkt", Wiring::Runs(&[])),
    ("bucketconfig", Wiring::Runs(&[])),
    ("checksum", Wiring::Runs(&[])),
    // This domain has no executing target yet. Its single case asks to be signed with
    // `sign.mode = "sigv4_streaming_trailer"` and then to half-close the connection mid-body. No
    // target in this repository can do either: in process the case is turned away for the
    // `half_close` control chunk, and over a socket it is turned away for the signing mode. Both
    // refusals name their capability and the baseline records the case as `skipped`, so this is a
    // deferral rather than an unwiring — but it is the one domain whose verdicts nobody has ever
    // seen on any transport, and the row is here so that stays visible instead of reading as a
    // domain like any other.
    (
        "chunked",
        Wiring::Deferred("no target signs `sigv4_streaming_trailer` or half-closes a request body"),
    ),
    // `c-cond-0013` wants two requests in flight at once so one loses the race. Neither target can
    // stage it: the in-process facade performs one call at a time, and the socket transport can put
    // both on the wire but cannot make them contend. `range_cond_family.rs` pins the same skip as an
    // equality; this row is the subset form, so the two disagree only in the direction that lets a
    // recovery land without touching this file.
    ("cond", Wiring::Runs(&["c-cond-0013"])),
    ("copy", Wiring::Runs(&[])),
    ("cors", Wiring::Runs(&[])),
    ("cred", Wiring::Runs(&[])),
    ("encryption", Wiring::Runs(&[])),
    ("etag", Wiring::Runs(&[])),
    // InProcess receives parsed HTTP requests and cannot execute literal HTTP/2 frame scripts.
    // The production Hyper gate in `src/conn/h2/tests/h2_corpus_tests.rs` executes every named
    // case and requires a pass; this row records only the in-process transport limitation.
    (
        "h2",
        Wiring::Deferred("the in-process target has no wire for authored HTTP/2 frames; production Hyper executes them"),
    ),
    ("host", Wiring::Runs(&[])),
    ("lifecycle", Wiring::Runs(&[])),
    ("list", Wiring::Runs(&[])),
    ("location", Wiring::Runs(&[])),
    ("lock", Wiring::Runs(&[])),
    // The five in `multipart_family.rs`'s `KNOWN_SKIPS`: three want a fresh connection per exchange
    // (`c-mpu-0053` for the connection verdict after a refusal left the body unread), one a stalled
    // chunk, one a malformed request head. All five execute over a socket.
    (
        "mpu",
        Wiring::Runs(&["c-mpu-0027", "c-mpu-0039", "c-mpu-0043", "c-mpu-0045", "c-mpu-0053"]),
    ),
    // The default CI run claims AWS. These MinIO-only cases (the slash-collapse trio and
    // c-naming-0032's dot-dot DeleteObject refusal, rustfs/gateway#772) are executed by the
    // dedicated profile command and are the deliberate profile-gated skips here.
    (
        "naming",
        Wiring::Runs(&["c-naming-0025", "c-naming-0026", "c-naming-0027", "c-naming-0032"]),
    ),
    // `c-object-0030` writes a raw request head, `c-object-0054` half-closes a declared-length
    // body, `c-object-0055` closes it outright, and `c-object-0056` stalls between body frames.
    // `c-object-0060` writes a raw chunked head with no length (rustfs/gateway#774).
    // Only a transport that puts bytes on a socket can express them; the in-process target is
    // handed a parsed `http::Request`. `tests/object.rs` reads the skips from the other side.
    (
        "object",
        Wiring::Runs(&[
            "c-object-0030",
            "c-object-0054",
            "c-object-0055",
            "c-object-0056",
            "c-object-0060",
        ]),
    ),
    ("post", Wiring::Runs(&[])),
    ("range", Wiring::Runs(&[])),
    ("replication", Wiring::Runs(&[])),
    ("select-restore", Wiring::Runs(&[])),
    ("sig", Wiring::Runs(&[])),
    ("ssec", Wiring::Runs(&[])),
    ("tagging", Wiring::Runs(&[])),
];

/// The whole corpus, run once against the assembled in-process service and grouped by domain.
///
/// One run for the whole file: the run is the expensive part, and repeating it per test would buy
/// nothing, because every test here reads the same set of outcomes.
fn measured() -> &'static BTreeMap<String, Vec<CaseOutcome>> {
    static MEASURED: OnceLock<BTreeMap<String, Vec<CaseOutcome>>> = OnceLock::new();
    MEASURED.get_or_init(|| {
        let root = Corpus::discover_root().expect("a corpus sits next to this crate");
        let corpus = runner::prepare_corpus(&root).expect("the corpus loads");
        let mut sut = InProcess::new(root);
        let report = runner::run(&corpus, &mut sut, &RunOptions::default());
        let mut grouped: BTreeMap<String, Vec<CaseOutcome>> = BTreeMap::new();
        for outcome in report.outcomes {
            grouped.entry(outcome.domain.clone()).or_default().push(outcome);
        }
        grouped
    })
}

/// The identifiers the corpus holds, per domain, read from the loaded cases rather than from the
/// filesystem so this agrees with whatever the loader decided a domain is.
///
/// Deliberately a second load rather than a projection of [`measured`]. The run is what is on
/// trial here; deriving the expected set from the run would make
/// [`every_gate_measures_every_case_the_domain_holds`] compare the run against itself, which is a
/// check that cannot fail.
fn corpus_domains() -> &'static BTreeMap<String, BTreeSet<String>> {
    static DOMAINS: OnceLock<BTreeMap<String, BTreeSet<String>>> = OnceLock::new();
    DOMAINS.get_or_init(|| {
        let root = Corpus::discover_root().expect("a corpus sits next to this crate");
        let corpus = runner::prepare_corpus(&root).expect("the corpus loads");
        let mut grouped: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for case in corpus.cases() {
            grouped.entry(case.domain.clone()).or_default().insert(case.id.clone());
        }
        grouped
    })
}

fn outcomes_of(domain: &str) -> &'static [CaseOutcome] {
    measured().get(domain).map(Vec::as_slice).unwrap_or_default()
}

/// The first few of a list, with the total, for a failure message.
///
/// An unwiring turns whole domains into skips at once, so an assertion that prints every affected
/// identifier prints hundreds of them. A failure nobody can read is a failure nobody acts on, and
/// the identifiers after the first few add nothing the count does not already say.
fn few(ids: &[&str]) -> String {
    let head: Vec<&str> = ids.iter().copied().take(4).collect();
    if ids.len() > head.len() {
        format!("{head:?} and {} more", ids.len() - head.len())
    } else {
        format!("{head:?}")
    }
}

/// Negative — the table and the corpus name the same domains, in both directions.
///
/// The direction that is easy to forget is the one that matters most: a domain added with no row
/// would be gated by nothing at all, and would read from the summary line exactly like a gated one.
/// The other direction matters too — a row naming a domain that no longer exists is a row whose
/// assertions can never run, which is the shape this repository has caught eight times.
#[test]
fn every_corpus_domain_is_gated_and_every_gate_names_a_corpus_domain() {
    let declared: Vec<&str> = GATES.iter().map(|(domain, _)| *domain).collect();
    let gated: BTreeSet<&str> = declared.iter().copied().collect();
    assert_eq!(gated.len(), declared.len(), "a domain is gated twice: {declared:?}");

    let present = corpus_domains();
    let ungated: Vec<&String> = present.keys().filter(|domain| !gated.contains(domain.as_str())).collect();
    assert!(
        ungated.is_empty(),
        "corpus domain(s) with no wiring gate: {ungated:?} — add a row to GATES"
    );
    let stale: Vec<&&str> = gated.iter().filter(|domain| !present.contains_key(**domain)).collect();
    assert!(
        stale.is_empty(),
        "GATES names domain(s) the corpus no longer holds: {stale:?} — drop the row"
    );
}

/// Negative — an allowance that cannot bind is not a gate, and an allowance that names nothing is
/// not a reason.
///
/// A row allowing every case it holds would let the whole domain go quiet and stay green, which is
/// precisely the defect this file exists to stop; a domain in that position must be recorded as
/// [`Wiring::Deferred`], where the two-directional check applies. An identifier that names no case
/// in the domain is the other half: it has outlived its case, so it can never be matched and the
/// row is quietly one entry weaker than it reads.
#[test]
fn no_gate_allows_a_skip_it_cannot_bind_or_an_identifier_it_cannot_match() {
    for (domain, wiring) in GATES {
        let held = corpus_domains().get(*domain).cloned().unwrap_or_default();
        match wiring {
            Wiring::Runs(allowed) => {
                let unique: BTreeSet<&str> = allowed.iter().copied().collect();
                assert_eq!(unique.len(), allowed.len(), "the `{domain}` gate names a case twice: {allowed:?}");
                let unknown: Vec<&&str> = allowed.iter().filter(|id| !held.contains(**id)).collect();
                assert!(
                    unknown.is_empty(),
                    "the `{domain}` gate allows {unknown:?} to skip, but the domain holds no such case"
                );
                assert!(
                    allowed.len() < held.len(),
                    "the `{domain}` gate allows all {} of its cases to skip, so the whole domain \
                     could stop running and this file would stay green — record it as Deferred instead",
                    held.len()
                );
            }
            Wiring::Deferred(reason) => {
                assert!(!reason.trim().is_empty(), "the `{domain}` deferral names no missing capability");
                assert!(!held.is_empty(), "the `{domain}` deferral names a domain that holds no cases");
            }
        }
    }
}

/// Negative — every gate sees every case its domain holds.
///
/// Between the corpus and the report sit a filter, a profile gate and an `applies_to` check, any of
/// which can quietly shrink what a run looks at. An allowance checked over half a domain is an
/// allowance over the half that happened to be selected, and the other half is ungoverned.
#[test]
fn every_gate_measures_every_case_the_domain_holds() {
    for (domain, held) in corpus_domains() {
        let observed: BTreeSet<&str> = outcomes_of(domain).iter().map(|outcome| outcome.id.as_str()).collect();
        let missing: Vec<&str> = held.iter().map(String::as_str).filter(|id| !observed.contains(id)).collect();
        assert!(
            missing.is_empty(),
            "the `{domain}` domain holds {}, which never reached the run",
            few(&missing)
        );
        assert_eq!(
            observed.len(),
            held.len(),
            "the `{domain}` domain reached the run with {} outcomes for {} cases",
            observed.len(),
            held.len()
        );
    }
}

/// **The assertion this file exists for.** Negative — no domain skips a case its row does not name.
///
/// Unregister one operation from the in-process facade and whole families stop producing verdicts.
/// Nothing else in `cargo test --workspace` need notice: `tests/corpus.rs` runs against `Unwired`,
/// where every case is a skip by design, and the baseline ratchet compares failures, of which an
/// unwired family has none. This is the line that goes red, and it names the domain.
#[test]
fn no_domain_skips_a_case_its_gate_does_not_name() {
    let mut unexpected: Vec<String> = Vec::new();
    for (domain, wiring) in GATES {
        let Wiring::Runs(allowed) = wiring else { continue };
        let outcomes = outcomes_of(domain);
        let offenders: Vec<&CaseOutcome> = outcomes
            .iter()
            .filter(|outcome| outcome.verdict == Verdict::Skipped)
            .filter(|outcome| !allowed.contains(&outcome.id.as_str()))
            .collect();
        let Some(first) = offenders.first() else { continue };
        // One line per domain rather than one per case: an unwiring turns hundreds of cases into
        // skips for a single reason, and a failure nobody can read is a failure nobody acts on.
        let named: Vec<&str> = offenders.iter().map(|outcome| outcome.id.as_str()).collect();
        unexpected.push(format!(
            "{domain}: {} of {} case(s) skipped, none of them allowed — {}; first reason: {}",
            offenders.len(),
            outcomes.len(),
            few(&named),
            first.skip_reason.as_deref().unwrap_or("no reason given")
        ));
    }
    assert!(
        unexpected.is_empty(),
        "domain(s) that stopped running — is every operation they need still registered?\n{}",
        unexpected.join("\n")
    );
}

/// Negative — a skip states the capability the target lacks.
///
/// This is what keeps "skipped deliberately, reason recorded" apart from "skipped because nothing
/// was wired". `tests/corpus.rs` makes the same demand of the `Unwired` target, where every case is
/// a skip and the reason is the whole point; here it is made of the *real* run, which is the one
/// whose green line anybody reads.
#[test]
fn every_skip_in_the_real_run_states_a_reason() {
    let mut mute: Vec<&str> = Vec::new();
    for outcomes in measured().values() {
        for outcome in outcomes {
            if outcome.verdict != Verdict::Skipped {
                continue;
            }
            if outcome.skip_reason.as_deref().unwrap_or_default().trim().is_empty() {
                mute.push(outcome.id.as_str());
            }
        }
    }
    assert!(
        mute.is_empty(),
        "case(s) skipped with no reason on the assembled service: {mute:?} — \
         `did not run` and `ran and was red` must stay distinguishable"
    );
}

/// Negative — a deferred domain is still wholly skipped.
///
/// Two directions, for the reason `tests/object.rs` gives about its own exemption list: an
/// exemption nobody re-reads is the same defect as no list at all. If a deferred domain starts
/// producing verdicts, the row has outlived its reason and is now hiding a domain that could be
/// gated properly — so that turns this red, and the fix is to give the domain a `Runs` row.
#[test]
fn a_deferred_domain_is_still_skipped_everywhere_it_claims_to_be() {
    for (domain, wiring) in GATES {
        let Wiring::Deferred(reason) = wiring else { continue };
        let outcomes = outcomes_of(domain);
        assert!(!outcomes.is_empty(), "the `{domain}` domain reached the run with no cases at all");
        let executed: Vec<&str> = outcomes
            .iter()
            .filter(|outcome| outcome.verdict != Verdict::Skipped)
            .map(|outcome| outcome.id.as_str())
            .collect();
        assert!(
            executed.is_empty(),
            "the `{domain}` domain is recorded as deferred on `{reason}`, but {} of its cases \
             produced a verdict ({}) — replace the deferral with a Runs row that names the rest",
            executed.len(),
            few(&executed)
        );
    }
}
