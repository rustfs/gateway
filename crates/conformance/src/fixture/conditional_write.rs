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

//! Responsible for: optimistic conditional-write commit and the deterministic fixture rendezvous
//! that makes overlapping checks executable.
//! Not responsible for: evaluating preconditions or selecting concurrent cases.
//! Upstream: object handlers and the socket batch.
//! Downstream: fixture storage and the existing 409 error renderer.

use std::sync::Condvar;
use std::time::Duration;

use tokio::sync::Notify;

use super::*;

impl Fixture {
    /// Shares this fixture's test-only rendezvous with its socket transport.
    pub(crate) fn conditional_race_coordinator(&self) -> Arc<ConditionalRaceCoordinator> {
        Arc::clone(&self.conditional_races)
    }

    /// Captures the storage generation a conditional write checked.
    fn object_generation(&self, bucket: &str, key: &str) -> u64 {
        self.object_generations
            .get(&(bucket.to_owned(), key.to_owned()))
            .copied()
            .unwrap_or(0)
    }

    /// Commits only if no write reached this key after the caller checked its conditions.
    fn put_object_if_generation(&mut self, bucket: &str, key: &str, expected: u64, object: StoredObject) -> Result<String, ()> {
        if self.object_generation(bucket, key) != expected {
            return Err(());
        }
        Ok(self.put_object(bucket, key, object))
    }
}

/// Coordinates successful conditional checks without deciding either condition or response.
#[derive(Debug, Default)]
pub(crate) struct ConditionalRaceCoordinator {
    state: Mutex<ConditionalRaceState>,
    checked: Condvar,
    changed: Notify,
}

#[derive(Debug, Default)]
struct ConditionalRaceState {
    active: Option<ActiveConditionalRace>,
}

#[derive(Debug)]
struct ActiveConditionalRace {
    participants: usize,
    checked: usize,
    aborted: bool,
    leader_committed: bool,
}

#[derive(Clone, Copy)]
struct ConditionalRacePermit {
    leader: bool,
}

impl ConditionalRaceCoordinator {
    pub(crate) fn begin(&self, participants: usize) -> Result<(), &'static str> {
        if participants < 2 {
            return Err("a conditional-race rendezvous requires at least two participants");
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "the conditional-race rendezvous was left poisoned")?;
        if state.active.is_some() {
            return Err("a conditional-race rendezvous is already active");
        }
        state.active = Some(ActiveConditionalRace {
            participants,
            checked: 0,
            aborted: false,
            leader_committed: false,
        });
        Ok(())
    }

    pub(crate) fn end(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.active = None;
        }
        self.checked.notify_all();
        self.changed.notify_waiters();
    }

    pub(crate) fn wait_until_checked(&self, minimum: usize, timeout: Duration) -> Result<(), &'static str> {
        let state = self
            .state
            .lock()
            .map_err(|_| "the conditional-race rendezvous was left poisoned")?;
        let (state, wait) = self
            .checked
            .wait_timeout_while(state, timeout, |state| {
                state.active.as_ref().is_some_and(|active| active.checked < minimum)
            })
            .map_err(|_| "the conditional-race rendezvous was left poisoned")?;
        let Some(active) = state.active.as_ref() else {
            return Err("the conditional-race rendezvous ended before every check arrived");
        };
        if wait.timed_out() && active.checked < minimum {
            return Err("a conditional write did not reach the rendezvous before its timeout");
        }
        Ok(())
    }

    async fn after_check(&self, condition_satisfied: bool) -> Result<Option<ConditionalRacePermit>, HandlerError> {
        let permit = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| HandlerError::internal_error("the conditional-race rendezvous was left poisoned"))?;
            let Some(active) = state.active.as_mut() else { return Ok(None) };
            if active.checked >= active.participants {
                return Err(HandlerError::internal_error(
                    "more conditional writes arrived than the concurrent batch declared",
                ));
            }
            let permit = ConditionalRacePermit {
                leader: active.checked == 0,
            };
            active.checked += 1;
            active.aborted |= !condition_satisfied;
            permit
        };
        self.checked.notify_all();
        self.changed.notify_waiters();

        loop {
            let changed = self.changed.notified();
            let ready = {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| HandlerError::internal_error("the conditional-race rendezvous was left poisoned"))?;
                let active = state
                    .active
                    .as_ref()
                    .ok_or_else(|| HandlerError::internal_error("the conditional-race rendezvous ended before commit"))?;
                if active.aborted {
                    true
                } else if permit.leader {
                    active.checked == active.participants
                } else {
                    active.leader_committed
                }
            };
            if ready {
                return Ok(Some(permit));
            }
            changed.await;
        }
    }

    fn after_commit(&self, permit: Option<ConditionalRacePermit>) -> Result<(), HandlerError> {
        if !permit.is_some_and(|permit| permit.leader) {
            return Ok(());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| HandlerError::internal_error("the conditional-race rendezvous was left poisoned"))?;
        let active = state
            .active
            .as_mut()
            .ok_or_else(|| HandlerError::internal_error("the conditional-race rendezvous ended before commit"))?;
        active.leader_committed = true;
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }
}

/// `blocked` is the bucket's `BlockedEncryptionTypes` verdict for this request, decided by the
/// handler from the framework's SSE proof. It is applied after the body is drained, like every
/// other refusal here, so a refused write still consumes exactly the body it framed.
///
/// The three `x-amz-object-lock-*` headers set the new version's retention and legal hold, so
/// they are held to the rules their document twins are: the bucket must have object lock on
/// (`q-lock-0015` — a lock on an unlocked bucket is a promise no enforcement path reads), and the
/// values must pass `validate_object_write_lock` against this case's clock. Both refusals come
/// before anything is stored. Ignoring the headers instead would answer `200` for a write the
/// client believes is protected, which is the one wrong answer this family exists to prevent.
pub(super) async fn put_object(
    state: &Arc<Mutex<Fixture>>,
    input: dto::PutObjectInput,
    blocked: Result<(), HandlerError>,
) -> HandlerResult<dto::PutObject> {
    let bytes = drain(input.body).await?;
    require_content_md5(input.content_md5.as_deref(), &bytes)?;
    blocked?;
    let lock_mode = input.object_lock_mode.as_ref().map(|mode| mode.as_str());
    let lock_until = input.object_lock_retain_until_date.as_ref();
    let lock_hold = input.object_lock_legal_hold_status.as_ref().map(|status| status.as_str());
    let (now, existing, generation, conditional_races) = {
        let fixture = state
            .lock()
            .map_err(|_| HandlerError::internal_error("the fixture state was left poisoned by an earlier exchange"))?;
        require_bucket(&fixture, &input.bucket)?;
        if lock_mode.is_some() || lock_until.is_some() || lock_hold.is_some() {
            require_object_lock(&fixture, input.bucket.as_str())?;
            validate_object_write_lock(lock_mode, lock_until, lock_hold, fixture.now)
                .map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        }
        (
            fixture.now,
            fixture.object(input.bucket.as_str(), input.key.as_str()).cloned(),
            fixture.object_generation(input.bucket.as_str(), input.key.as_str()),
            fixture.conditional_race_coordinator(),
        )
    };
    let guard_before_mutation = conditional_write_guards_before_mutation();
    let conditional = input.if_match.is_some() || input.if_none_match.is_some();
    let guard = guard_write(existing.as_ref(), input.if_match.as_deref(), input.if_none_match.as_deref(), now);
    let mut object = StoredObject::new(bytes, input.content_type.clone(), now);
    if let Some(checksum) = input.checksum_spec {
        object.checksum = Some(checksum);
    }
    object.cache_control = input.cache_control.clone();
    object.content_disposition = input.content_disposition.clone();
    object.content_encoding = input.content_encoding.clone();
    object.content_language = input.content_language.clone();
    object.expires = input.expires.as_ref().map(|value| value.as_str().to_owned());
    object.metadata = input.metadata.clone();
    object.tags = read_tagging_header(input.tagging.as_deref())?;
    if let Some(class) = input.storage_class.as_ref() {
        object.storage_class = class.to_string();
    }
    // Validated above: a mode and an instant arrive together or not at all.
    if let (Some(mode), Some(until)) = (lock_mode, lock_until) {
        object.retention = Some(dto::ObjectLockRetention {
            mode: Some(dto::Mode::custom(mode.to_owned())),
            retain_until_date: Some(*until),
        });
    }
    object.legal_hold = lock_hold.map(|status| dto::ObjectLockLegalHold {
        status: Some(dto::Status::custom(status.to_owned())),
    });
    let size = object.body.len() as i64;
    let etag = object.etag.clone();
    let written = if guard_before_mutation {
        let permit = if conditional {
            conditional_races.after_check(guard.is_ok()).await?
        } else {
            None
        };
        guard?;
        let result = {
            let mut fixture = state
                .lock()
                .map_err(|_| HandlerError::internal_error("the fixture state was left poisoned by an earlier exchange"))?;
            if conditional {
                fixture.put_object_if_generation(input.bucket.as_str(), input.key.as_str(), generation, object)
            } else {
                Ok(fixture.put_object(input.bucket.as_str(), input.key.as_str(), object))
            }
        };
        conditional_races.after_commit(permit)?;
        result.map_err(|()| conflict())?
    } else {
        let written = state
            .lock()
            .map_err(|_| HandlerError::internal_error("the fixture state was left poisoned by an earlier exchange"))?
            .put_object(input.bucket.as_str(), input.key.as_str(), object);
        guard?;
        written
    };
    Ok(Resp::new(dto::PutObjectOutput {
        size: Some(size),
        checksum_spec: input.checksum_spec,
        checksum_type: input.checksum_spec.and_then(reported_checksum_type),
        e_tag: entity_tag(&etag)?,
        version_id: (written != UNVERSIONED).then_some(written),
        ..dto::PutObjectOutput::default()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(byte: u8) -> StoredObject {
        StoredObject::new(vec![byte], None, 1_773_014_400)
    }

    #[test]
    fn a_current_generation_commits() {
        let mut fixture = Fixture::at(1_773_014_400);
        fixture.declare_bucket("bucket", false);
        let generation = fixture.object_generation("bucket", "key");

        assert!(
            fixture
                .put_object_if_generation("bucket", "key", generation, object(1))
                .is_ok()
        );
    }

    #[test]
    fn a_stale_generation_cannot_overwrite_the_winner() {
        let mut fixture = Fixture::at(1_773_014_400);
        fixture.declare_bucket("bucket", false);
        let stale = fixture.object_generation("bucket", "key");
        fixture.put_object("bucket", "key", object(1));

        assert!(fixture.put_object_if_generation("bucket", "key", stale, object(2)).is_err());
        assert_eq!(fixture.object("bucket", "key").map(|stored| stored.body.as_slice()), Some(&[1][..]));
    }

    #[test]
    fn a_generation_from_one_key_does_not_authorize_another_key() {
        let mut fixture = Fixture::at(1_773_014_400);
        fixture.declare_bucket("bucket", false);
        let key_b_generation = fixture.object_generation("bucket", "key-b");
        fixture.put_object("bucket", "key-a", object(1));

        assert!(
            fixture
                .put_object_if_generation("bucket", "key-b", key_b_generation, object(2))
                .is_ok()
        );
        assert_eq!(fixture.object_generation("bucket", "key-a"), 1);
        assert_eq!(fixture.object_generation("bucket", "key-b"), 1);
    }

    #[test]
    fn a_rendezvous_rejects_invalid_or_overlapping_batches() {
        let coordinator = ConditionalRaceCoordinator::default();

        assert_eq!(
            coordinator.begin(1),
            Err("a conditional-race rendezvous requires at least two participants")
        );
        assert!(coordinator.begin(2).is_ok());
        assert_eq!(coordinator.begin(2), Err("a conditional-race rendezvous is already active"));
        assert_eq!(
            coordinator.wait_until_checked(1, Duration::from_millis(1)),
            Err("a conditional write did not reach the rendezvous before its timeout")
        );
        coordinator.end();
    }
}
