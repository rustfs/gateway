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

//! POST Object case assembly and observations that require the bundled fixture.
//!
//! Responsible for: assembling that case under the RustFS profile's form grammar, which is the
//! grammar that fixes a file's length from a declared `Content-Length`; recording, at the
//! handler's entry, `PostObjectInput::content_length` and the body's own remaining length; failing
//! the case when either is not the file's exact length; and declaring that reading unavailable on
//! an external endpoint, which reports nothing to the hook (rustfs/gateway#1406); selecting the
//! legacy grammar for c-post-0022; and declaring c-post-0026 unavailable externally, since its
//! refusal depends on the bundled fixture's lack of KMS (rustfs/gateway#1399).
//! NOT responsible for: judging the response (`crate::expect`), the fixture's storage capability,
//! or skipping the case (the external target returns the declared reason and the runner skips).
//! Upstream: the selected case id. Downstream: `super::InProcess` service assembly and `finish`,
//! and `crate::conn::external_fixture` through [`unavailable_externally`].

use std::sync::{Arc, Mutex};

use rustfs_gateway::{BoxFuture, HandlerResult, Next, Req, ServiceBuilder, dto, op_layer};

use crate::sut::SutError;

/// The case whose handler entry is observed.
const OBSERVED_CASE: &str = "c-post-0020";

/// The exact length of that case's file part, `twenty-four-byte-payload`.
const OBSERVED_FILE_BYTES: u64 = 24;

/// What one handler entry saw: the input's `content_length`, and the body's remaining length.
pub(super) type Observed = Arc<Mutex<Vec<(Option<u64>, Option<u64>)>>>;

pub(super) fn configure_case(builder: ServiceBuilder, case_id: &str, observed: Observed) -> ServiceBuilder {
    if case_id == "c-post-0022" {
        return builder.legacy_rustfs_post_forms();
    }
    if case_id != OBSERVED_CASE {
        return builder;
    }
    builder.legacy_rustfs_post_forms().op_layer::<dto::PostObject, _>(op_layer(
        move |request: Req<dto::PostObject>, next: Next<'_, dto::PostObject>| {
            let observed = Arc::clone(&observed);
            Box::pin(async move {
                let input = request.input();
                let seen = (input.content_length, input.body.remaining_length().get());
                if let Ok(mut observed) = observed.lock() {
                    observed.push(seen);
                }
                next.run(request).await
            }) as BoxFuture<'_, HandlerResult<dto::PostObject>>
        },
    ))
}

/// Why an external endpoint cannot answer for `case_id`, when its verdict requires the handler
/// observation or the bundled fixture's lack of KMS; `None` for every other case.
///
/// The hook is a layer on the service this target assembles, so only a request that passes through
/// that service can reach it. An external endpoint is assembled by someone else: nothing it does
/// is reported to the hook, `finish` would read an empty list, and the case would fail for lack of
/// an observation rather than for anything the endpoint did. The external target asks this before
/// it sends anything and skips the case with the reason returned here.
pub(crate) fn unavailable_externally(case_id: &str) -> Option<String> {
    if case_id == "c-post-0026" {
        return Some(
            "c-post-0026: the reference fixture cannot provide KMS; an external host's managed encryption \
             capability is not controlled by this case, so it is unavailable on an external endpoint"
                .to_owned(),
        );
    }
    (case_id == OBSERVED_CASE).then(|| {
        format!(
            "{OBSERVED_CASE} observes PostObjectInput::content_length at the handler's entry, a reading only the \
             in-process target's handler hook can supply; it is unavailable on an external endpoint, so the case \
             is not run there"
        )
    })
}

/// The observation's verdict: exactly one handler entry, handed the file's exact length both as
/// `content_length` and as the body's remaining length.
pub(super) fn finish(case_id: &str, observed: &Observed) -> Result<(), SutError> {
    if case_id != OBSERVED_CASE {
        return Ok(());
    }
    let seen = observed
        .lock()
        .map(|observed| observed.clone())
        .map_err(|_| SutError::Environment(format!("{OBSERVED_CASE}: the observation lock was poisoned")))?;
    let expected = vec![(Some(OBSERVED_FILE_BYTES), Some(OBSERVED_FILE_BYTES))];
    if seen != expected {
        return Err(SutError::Environment(format!(
            "{OBSERVED_CASE}: the handler saw {seen:?} as (content_length, body remaining length); expected {expected:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Negative — a missing entry, a `None` on either side, a second entry and another case's
    /// id each decide as they must: the first three fail the observed case, the last is not
    /// observed at all.
    #[test]
    fn n_the_verdict_fails_every_reading_but_the_exact_one() {
        let exact = (Some(OBSERVED_FILE_BYTES), Some(OBSERVED_FILE_BYTES));
        for seen in [
            vec![],
            vec![(None, Some(OBSERVED_FILE_BYTES))],
            vec![(Some(OBSERVED_FILE_BYTES), None)],
            vec![(Some(OBSERVED_FILE_BYTES - 1), Some(OBSERVED_FILE_BYTES - 1))],
            vec![exact, exact],
        ] {
            let observed: Observed = Arc::new(Mutex::new(seen.clone()));
            assert!(finish(OBSERVED_CASE, &observed).is_err(), "{seen:?}");
            assert!(finish("c-post-0001", &observed).is_ok(), "{seen:?}");
        }
    }

    /// Positive — the exact reading, once, passes.
    #[test]
    fn the_exact_reading_passes() {
        let observed: Observed = Arc::new(Mutex::new(vec![(Some(OBSERVED_FILE_BYTES), Some(OBSERVED_FILE_BYTES))]));
        assert!(finish(OBSERVED_CASE, &observed).is_ok());
    }

    /// Negative — portable cases, neighbouring ids, near misses and the empty id stay answerable
    /// on an external endpoint. A gate that skipped every PostObject case would hide measurements.
    #[test]
    fn n_only_fixture_dependent_cases_are_unavailable_externally() {
        for other in [
            "c-post-0019",
            "c-post-0021",
            "c-post-0022",
            "c-post-0023",
            "c-post-0024",
            "c-post-0025",
            "c-post-0027",
            "c-post-0001",
            "c-post-00200",
            "c-post-00260",
            "C-POST-0020",
            "C-POST-0026",
            "",
        ] {
            assert_eq!(unavailable_externally(other), None, "{other:?}");
        }
    }

    /// Positive — the observed case is unavailable, and its reason names the case, the reading and
    /// the hook, which is all a reader of the skip line has to go on.
    #[test]
    fn the_observed_case_names_what_an_external_endpoint_cannot_supply() {
        let reason = unavailable_externally(OBSERVED_CASE).expect("the observed case is unavailable externally");
        for needle in [OBSERVED_CASE, "PostObjectInput::content_length", "in-process", "external"] {
            assert!(reason.contains(needle), "{needle:?} missing from {reason:?}");
        }
    }

    /// The unsupported-KMS fixture case cannot declare that capability on an external host.
    #[test]
    fn the_unsupported_managed_fixture_case_is_unavailable_externally() {
        let reason = unavailable_externally("c-post-0026").expect("the fixture capability is unavailable externally");
        assert!(reason.contains("reference fixture cannot provide KMS"), "{reason}");
    }

    /// The real `c-post-0020` file, with `replace` applied to its text, in a corpus of its own.
    struct Isolated(std::path::PathBuf);

    impl Isolated {
        fn with(replace: Option<(&str, &str)>) -> Isolated {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "rustfs-gateway-post-object-hook-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(root.join("cases/post")).expect("create the cases directory");
            let repository = crate::corpus::Corpus::discover_root().expect("the repository corpus");
            std::fs::copy(repository.join("case.schema.json"), root.join("case.schema.json")).expect("copy the frozen schema");
            let mut text = std::fs::read_to_string(repository.join("cases/post/c-post-0020.toml")).expect("the real case");
            if let Some((from, to)) = replace {
                assert!(text.contains(from), "the control no longer matches the case text: {from:?}");
                text = text.replace(from, to);
            }
            std::fs::write(root.join("cases/post/c-post-0020.toml"), text).expect("write the case");
            Isolated(root)
        }

        /// The case's outcome from a full in-process run.
        fn run(&self) -> crate::report::CaseOutcome {
            let corpus = crate::corpus::Corpus::load(&self.0).expect("the isolated corpus loads");
            let options = crate::runner::RunOptions {
                filter: Some(OBSERVED_CASE.to_owned()),
                ..crate::runner::RunOptions::default()
            };
            let report = crate::runner::run(&corpus, &mut super::super::InProcess::new(self.0.clone()), &options);
            assert_eq!(report.outcomes.len(), 1, "exactly the observed case ran");
            report.outcomes.into_iter().next().expect("one outcome")
        }
    }

    impl Drop for Isolated {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Positive control — in process, where the hook exists, the real case passes: the handler is
    /// handed 24 and 24, and the gate that skips it externally does not touch this target.
    #[test]
    fn in_process_the_real_case_passes() {
        let outcome = Isolated::with(None).run();
        assert_eq!(outcome.verdict, crate::report::Verdict::Passed, "{:?}", outcome.diagnostics);
    }

    /// Negative control — the same case, in process, still FAILS when the hook sees another value:
    /// a 25-byte file reaches the handler as `(Some(25), Some(25))`, and the cleanup verdict names
    /// it. Without this the external skip could be a skip of a check that never fails.
    #[test]
    fn n_in_process_the_same_case_fails_when_the_hook_sees_another_length() {
        let outcome = Isolated::with(Some((
            "twenty-four-byte-payload\\r\\n--confpost--",
            "twenty-four-byte-payloads\\r\\n--confpost--",
        )))
        .run();
        assert_eq!(outcome.verdict, crate::report::Verdict::Failed, "{:?}", outcome.diagnostics);
        let cleanup = outcome
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.rule == "runner/cleanup")
            .expect("the hook's verdict is reported at cleanup");
        assert!(cleanup.message.contains("(Some(25), Some(25))"), "{}", cleanup.message);
    }
}
