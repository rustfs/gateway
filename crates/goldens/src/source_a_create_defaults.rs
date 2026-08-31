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

//! Source-(a) RustFS bucket-creation default configuration bindings.
//!
//! Responsible for: binding g-d2-008/009 to the exact RustFS default constants.
//! NOT responsible for: creating buckets, owning persistence codecs, or adding duplicate samples.
//! Upstream: RustFS ecstore bucket creation. Downstream: Versioning and Object Lock provenance.

#[cfg(test)]
use rustfs_gateway_types::compat::{serialize_s3s_object_lock, serialize_s3s_versioning};
#[cfg(test)]
use rustfs_gateway_types::persistence::{
    PersistedObjectLockConfiguration, PersistedVersioningConfiguration, serialize_object_lock, serialize_versioning,
};
use sha2::{Digest, Sha256};

use crate::ConfigKind;
use crate::source_a_census::SourceARow;

const RUSTFS_COMMIT: &str = "c876df53f5097618b1817568a471cbb8b4f26ee8";
const CONSTANTS_FILE_SHA256: &str = "ac3966d7b1da55987199602ffbe66d5d506b874dbfd2c041627e9ebfedf407b8";
const CALLSITE_FILE_SHA256: &str = "6cefb8c35a98a6292a7d4c88a38f0293f3e7ab5de6a1a44cdeb37b9e849f57c1";
const VERSIONING_SOURCE_REF: &str = "crates/ecstore/src/store/mod.rs::ENABLED_VERSIONING_CONFIG";
const OBJECT_LOCK_SOURCE_REF: &str = "crates/ecstore/src/store/mod.rs::ENABLED_OBJECT_LOCK_CONFIG";
const VERSIONING_CALLSITE_REF: &str = "crates/ecstore/src/store/bucket.rs::handle_make_bucket::versioning_config_xml";
const OBJECT_LOCK_CALLSITE_REF: &str = "crates/ecstore/src/store/bucket.rs::handle_make_bucket::object_lock_config_xml";

#[derive(Clone, Copy, Debug)]
struct SourceBinding {
    case_id: &'static str,
    kind: ConfigKind,
    source_ref: &'static str,
    callsite_ref: &'static str,
    sha256: &'static str,
    bytes: &'static [u8],
}

fn bindings() -> [SourceBinding; 2] {
    [
        SourceBinding {
            case_id: "g-d2-008",
            kind: ConfigKind::Versioning,
            source_ref: VERSIONING_SOURCE_REF,
            callsite_ref: VERSIONING_CALLSITE_REF,
            sha256: "dd6f6f21cc8680cc5c32bba98d4297e37552279d7e326a35df847ed2713f2d6a",
            bytes: crate::versioning::BODY_LITERAL_PERSISTED,
        },
        SourceBinding {
            case_id: "g-d2-009",
            kind: ConfigKind::ObjectLock,
            source_ref: OBJECT_LOCK_SOURCE_REF,
            callsite_ref: OBJECT_LOCK_CALLSITE_REF,
            sha256: "9cf16b957c9f7a738af95d6962500ebaae0e23d0138c811a8b6f39bcc941bbb2",
            bytes: crate::object_lock::ENABLED_WITHOUT_RULE,
        },
    ]
}

pub(crate) fn source_a_rows() -> Vec<SourceARow> {
    bindings()
        .into_iter()
        .flat_map(|binding| {
            [
                SourceARow::accepted_alias(binding.kind, binding.source_ref, binding.sha256),
                SourceARow::accepted_alias(binding.kind, binding.callsite_ref, binding.sha256),
            ]
        })
        .collect()
}

fn validate_bindings(candidates: &[SourceBinding]) -> Result<(), String> {
    let expected = [
        ("g-d2-008", ConfigKind::Versioning, VERSIONING_SOURCE_REF, VERSIONING_CALLSITE_REF),
        ("g-d2-009", ConfigKind::ObjectLock, OBJECT_LOCK_SOURCE_REF, OBJECT_LOCK_CALLSITE_REF),
    ];
    if candidates.len() != expected.len() {
        return Err(format!(
            "expected {} bucket-creation default bindings, found {}",
            expected.len(),
            candidates.len()
        ));
    }
    for (binding, (case_id, kind, source_ref, callsite_ref)) in candidates.iter().zip(expected) {
        if (binding.case_id, binding.kind, binding.source_ref, binding.callsite_ref) != (case_id, kind, source_ref, callsite_ref)
        {
            return Err(format!("unexpected or duplicate bucket-creation binding: {}", binding.case_id));
        }
        let observed = hex::encode(Sha256::digest(binding.bytes));
        if observed != binding.sha256 {
            return Err(format!("SHA-256 mismatch for {} from {}", binding.case_id, binding.source_ref));
        }
    }
    if CONSTANTS_FILE_SHA256.len() != 64
        || CALLSITE_FILE_SHA256.len() != 64
        || !CONSTANTS_FILE_SHA256
            .bytes()
            .chain(CALLSITE_FILE_SHA256.bytes())
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("RustFS source file SHA-256 provenance is malformed".to_owned());
    }
    Ok(())
}

pub(crate) fn versioning_alias_note() -> String {
    alias_note(validated_binding(0))
}

pub(crate) fn object_lock_alias_note() -> String {
    alias_note(validated_binding(1))
}

fn validated_binding(index: usize) -> SourceBinding {
    let registered = bindings();
    validate_bindings(&registered).expect("the static RustFS default binding table is valid"); // The local closed table has no external input.
    registered[index]
}

fn alias_note(binding: SourceBinding) -> String {
    format!(
        "{} source-(a) alias binds RustFS {RUSTFS_COMMIT} {} at {} (constants file SHA-256 {CONSTANTS_FILE_SHA256}; callsite file SHA-256 {CALLSITE_FILE_SHA256})",
        binding.case_id, binding.source_ref, binding.callsite_ref
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g_d2_008_default_versioning_constant_keeps_old_and_new_bytes() {
        let binding = bindings()[0];
        validate_bindings(&bindings()).expect("both default configuration bindings must remain exact");
        let value = PersistedVersioningConfiguration {
            status: Some("Enabled".to_owned()),
            ..PersistedVersioningConfiguration::default()
        };
        assert_eq!(
            serialize_s3s_versioning(&value).expect("the pinned old serializer accepts the RustFS default"),
            binding.bytes
        );
        assert_eq!(serialize_versioning(&value), binding.bytes);
    }

    #[test]
    fn g_d2_009_default_object_lock_constant_keeps_old_and_new_bytes() {
        let binding = bindings()[1];
        validate_bindings(&bindings()).expect("both default configuration bindings must remain exact");
        let value = PersistedObjectLockConfiguration {
            object_lock_enabled: Some("Enabled".to_owned()),
            ..PersistedObjectLockConfiguration::default()
        };
        assert_eq!(
            serialize_s3s_object_lock(&value).expect("the pinned old serializer accepts the RustFS default"),
            binding.bytes
        );
        assert_eq!(serialize_object_lock(&value), binding.bytes);
    }

    #[test]
    fn census_rejects_a_stale_default_digest() {
        let mut stale = bindings();
        stale[0].sha256 = "ed6f6f21cc8680cc5c32bba98d4297e37552279d7e326a35df847ed2713f2d6a";
        let error = validate_bindings(&stale).expect_err("a stale RustFS constant digest must fail closed");
        assert!(error.contains("g-d2-008"));
        assert!(error.contains("SHA-256 mismatch"));
    }

    #[test]
    fn census_rejects_a_duplicate_case_identifier() {
        let mut duplicated = bindings();
        duplicated[1].case_id = "g-d2-008";
        let error = validate_bindings(&duplicated).expect_err("a duplicate acceptance identifier must fail closed");
        assert!(error.contains("g-d2-008"));
        assert!(error.contains("unexpected or duplicate"));
    }

    #[test]
    fn census_rejects_a_swapped_constant_reference() {
        let mut swapped = bindings();
        swapped[0].source_ref = OBJECT_LOCK_SOURCE_REF;
        let error = validate_bindings(&swapped).expect_err("a source reference assigned to the wrong case must fail closed");
        assert!(error.contains("g-d2-008"));
        assert!(error.contains("unexpected or duplicate"));
    }
}
