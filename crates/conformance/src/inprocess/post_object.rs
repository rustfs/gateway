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

//! The in-process observation of what a POST Object handler is handed for the file's length
//! (c-post-0020, rustfs/gateway#1167).
//!
//! Responsible for: assembling that case under the RustFS profile's form grammar, which is the
//! grammar that fixes a file's length from a declared `Content-Length`; recording, at the
//! handler's entry, `PostObjectInput::content_length` and the body's own remaining length; and
//! failing the case when either is not the file's exact length.
//! NOT responsible for: judging the response (`crate::expect`), or any other case's assembly.
//! Upstream: the selected case id. Downstream: `super::InProcess` service assembly and `finish`.

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
}
