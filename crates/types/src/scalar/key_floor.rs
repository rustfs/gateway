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

//! The rule a client-chosen object key is held to before the deployment's validator: the
//! unconditional floor, or legacy RustFS's (rustfs/gateway#1107).
//!
//! Responsible for: [`KeyFloor`] and the legacy RustFS rule it selects.
//! NOT responsible for: the unconditional floor itself (`super::naming::floor_check_key`, the one
//! definition `scripts/check_single_normalization.sh` allows), decoding, the slash rule, or
//! choosing the floor at request time — `super::naming` reads the policy and calls one of the two.
//! Upstream: `super::naming::NamePolicy`. Downstream: `super::naming`'s key checks.

use super::naming::{MAX_KEY_BYTES, NameRejection};

#[cfg(doc)]
use super::naming::floor_check_key;

/// Which rule a client-chosen object key is held to before the deployment's validator.
///
/// The default is the unconditional safety floor. The only other value is the rule legacy RustFS
/// applies, for a deployment that fronts RustFS: it lowers the floor, so it is named for what it
/// does and a start-up posture line reports it.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum KeyFloor {
    /// [`floor_check_key`], after the refusal of an encoded separator that survived the decode.
    #[default]
    Unconditional,
    /// Legacy RustFS's rule (rustfs/gateway#1107): a key is refused only when it cannot be an
    /// [`crate::ObjectKey`] at all — empty, longer than 1024 bytes, or holding a NUL — and every
    /// other key reaches the handler as the bytes the single decode produced.
    ///
    /// Legacy RustFS's protocol front checks nothing else (`check_key` in the legacy path parser,
    /// reached from `rustfs/src/server/http.rs:166-172` on rustfs/rustfs `e870a6d25b`): a
    /// traversal, a control character, a backslash, a drive letter or a literal `%2F` is handed to
    /// RustFS, whose storage layer then refuses what it refuses (`crates/ecstore/src/bucket/utils.rs`
    /// `is_valid_object_prefix`, `check_object_name_for_length_and_slash`) after authorization.
    /// Only a backend that validates every key itself may be put behind it; RustFS's storage does.
    RustfsLegacy,
}

impl KeyFloor {
    /// Whether this rule admits a key the default floor refuses.
    #[must_use]
    pub fn lowers_the_default(self) -> bool {
        match self {
            Self::Unconditional => false,
            Self::RustfsLegacy => true,
        }
    }

    /// The identifier a posture report prints.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unconditional => "unconditional",
            Self::RustfsLegacy => "rustfs-legacy",
        }
    }

    /// Whether an encoded separator that survived the one decode (`%2F`, `%5C`, `%2e%2e` in the
    /// decoded value) is refused. Exhaustive, so a floor added later has to answer it.
    #[must_use]
    pub fn refuses_residual_escapes(self) -> bool {
        match self {
            Self::Unconditional => true,
            // Legacy-compat (rustfs/backlog#2684): legacy RustFS stores a literal `%2F`, `%5C` or
            // `%2e%2e` that survived the one decode as key text (`PUT /b/a%252Fb` stores `a%2Fb`),
            // which a consumer that decodes once more reads as a separator. Kept so those objects
            // stay reachable; the intended future behaviour is the refusal, for every deployment.
            Self::RustfsLegacy => false,
        }
    }
}

/// [`KeyFloor::RustfsLegacy`]: refuses only the keys an [`crate::ObjectKey`] cannot represent.
///
/// Legacy-compat (rustfs/backlog#2684): legacy RustFS's protocol front hands every other key to
/// its storage, which stores a control character, a backslash, a UNC or drive-letter shape and a
/// literal encoded separator (`a%01b`, `\x`, `C:\x`, `a%2Fb`, measured on a legacy build), and
/// refuses a `.` or `..` segment, CR, LF or an interior `//` only after authorization, with
/// `400 InvalidArgument`. Each of those shapes is either a byte no log line or shell carries
/// unambiguously or a spelling a filesystem reads as a path, which is why the default floor
/// refuses them before authentication. Kept so that every object a RustFS client stored stays
/// reachable under the key it was stored under, and RustFS answers the rest as it does today; the
/// intended future behaviour is the unconditional floor ([`floor_check_key`]), once the stored
/// keys it refuses have been found and renamed.
///
/// NUL stays refused here, before authorization: an `ObjectKey` cannot hold one, and legacy
/// RustFS refuses it too, with the same `400 InvalidArgument`, after authorization.
pub(super) fn legacy_rustfs_key_floor(key: &str) -> Result<(), NameRejection> {
    if key.is_empty() {
        return Err(NameRejection::Empty);
    }
    if key.len() > MAX_KEY_BYTES {
        return Err(NameRejection::TooLong);
    }
    if key.contains('\0') {
        return Err(NameRejection::Nul);
    }
    Ok(())
}
