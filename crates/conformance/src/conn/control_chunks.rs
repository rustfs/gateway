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

//! Control chunks on a socket exchange: catching the body up, stalls, and teardowns.
//!
//! Responsible for: carrying out `[[request.chunks]]` control actions on a live connection and
//! charging what they wait to the exchange's harness account.
//! NOT responsible for: writing data frames or reading the response, which `super` owns.
//! Upstream: `super::write_body`. Downstream: the socket and the pacer.

use std::sync::Arc;
use std::time::Duration;

use super::{ChunkStep, Connection, ExchangeClock, Pacer, SutError, Wire};

/// Writes the data frames the case declared and the pacing had not released yet.
///
/// The pacing is an *instrument*: it exists so that "how much of the body had gone out when the
/// answer arrived" is a fact about the server rather than about a kernel buffer, and that question
/// is settled the moment the answer exists. Leaving the rest unwritten after that point would make
/// this client permanently truncate every request the service refused early — which is not what any
/// client does, and which would make the connection unusable for reasons the case never described.
/// `c-object-0013` is the case that shows it: eleven bytes, refused on the head, and
/// `connection_after = "open"` — which the service grants only on condition that the remainder is
/// drained, and there is nothing to drain if the client never sent it.
///
/// Only the frames the *case* wrote, never up to a declared `Content-Length`: `c-mpu-0027`
/// announces five gigabytes and means to send ten bytes. Errors are dropped, because a server that
/// is already closing is the ordinary outcome here and is not a failure of the exchange.
pub(super) fn catch_up(connection: &mut Connection, wire: &Wire, from: usize) {
    for step in wire.steps.iter().skip(from) {
        match step {
            ChunkStep::Data(bytes, _) => {
                if connection.write_body(bytes).is_err() {
                    return;
                }
            }
            // A declared teardown is not performed here. It was scripted relative to a request in
            // flight, and the request is over.
            ChunkStep::Control { .. } => return,
        }
    }
}

/// Carries out one control chunk, returning a note when the act makes an assertion unfalsifiable.
pub(super) fn control(
    connection: &mut Connection,
    pacer: &Arc<Pacer>,
    satisfied: &mut u64,
    action: &str,
    delay_ms: u64,
    duration_ms: u64,
    clock: &mut ExchangeClock,
) -> Result<Option<String>, SutError> {
    match action {
        // A stall is "hold the connection open and send nothing", and it is the one place a
        // duration is the instruction rather than an approximation of one. It is still cut short
        // the moment there is an answer to read, so a server that refuses on the head does not cost
        // the case its own `terminate_within_ms`.
        "stall" => {
            let budget = Duration::from_millis(duration_ms).min(clock.remaining()?);
            let _ = clock.charged(|| pacer.stall_until_answered(budget));
            Ok(None)
        }
        // Both teardowns wait for the server to have taken what was already written, so that
        // "close after the body" is not a race with the server's first read. That wait is on the
        // peer; the `delay_ms` that follows is the case's own instruction about *when* to tear the
        // connection down relative to the work it started, and there is no acknowledgement that
        // could stand in for it.
        "half_close" => {
            wait_for_teardown(pacer, satisfied, action, delay_ms, clock)?;
            connection.half_close()?;
            Ok(None)
        }
        "close" => {
            wait_for_teardown(pacer, satisfied, action, delay_ms, clock)?;
            connection.close()?;
            Ok(Some(
                "this client closed the connection itself, so `kind = \"connection_reset\"` and \
                 `connection_after = \"closed\"` on this exchange are facts about a socket nobody \
                 was going to answer on, and cannot fail. The case's own comment says as much — \
                 what it actually asserts is in its later exchanges"
                    .to_owned(),
            ))
        }
        other => Err(SutError::Environment(format!(
            "a `{other}` control chunk is not carried out by this transport, and is refused rather \
             than dropped: a case that scripts a connection-level act and is answered from a \
             connection that never performed it is a false green"
        ))),
    }
}

fn wait_for_teardown(
    pacer: &Arc<Pacer>,
    satisfied: &mut u64,
    action: &str,
    delay_ms: u64,
    clock: &mut ExchangeClock,
) -> Result<(), SutError> {
    let handover_budget = teardown_handover_budget(action, delay_ms, clock.remaining()?)?;
    clock.charged(|| {
        let _ = pacer.await_handover(satisfied, handover_budget);
        sleep(delay_ms);
    });
    let _ = clock.remaining()?;
    Ok(())
}

pub(super) fn teardown_handover_budget(action: &str, delay_ms: u64, budget: Duration) -> Result<Duration, SutError> {
    budget.checked_sub(Duration::from_millis(delay_ms)).ok_or_else(|| {
        SutError::Environment(format!(
            "{action} control chunk declares a {delay_ms}ms delay beyond the remaining exchange timeout"
        ))
    })
}

fn sleep(millis: u64) {
    if millis > 0 {
        std::thread::sleep(Duration::from_millis(millis));
    }
}
