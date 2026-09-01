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

//! Concrete lifecycle-extension round-trip and persistence safety.
//!
//! Responsible for: binding the existing c-lifecycle-0018 pressure to a registered typed field,
//! exact sibling placement, property coverage over valid values, and fail-closed RMW. NOT responsible for: literal bodies, error
//! rendering, or any other vendor extension. Upstream: ADR-0007 and public protocol evidence.
//! Downstream: the P6 dialect integration surface.

use proptest::prelude::*;
use rustfs_gateway_dialect_minio::{DelMarkerExpiration, MinioLifecycleDialect};
use rustfs_gateway_types::ext::ExtError;

const CANONICAL: &[u8] = b"<LifecycleConfiguration><Rule><Expiration><Days>7</Days></Expiration><DelMarkerExpiration><Days>7</Days></DelMarkerExpiration><Filter><Prefix>del/</Prefix></Filter><ID>dialect</ID><Status>Enabled</Status></Rule></LifecycleConfiguration>";
const CHANGED: &[u8] = b"<LifecycleConfiguration><Rule><Expiration><Days>7</Days></Expiration><DelMarkerExpiration><Days>7</Days></DelMarkerExpiration><Filter><Prefix>del/</Prefix></Filter><ID>changed</ID><Status>Enabled</Status></Rule></LifecycleConfiguration>";

#[test]
fn c_dial_0001_to_0002_registered_lifecycle_field_survives_real_rmw_in_its_exact_slot() {
    let dialect = MinioLifecycleDialect::new().expect("one concrete registration is unique");
    let mut persisted = dialect.decode_persisted(CANONICAL);
    let decoded = persisted.value_mut().expect("the registered document decodes completely");
    assert_eq!(
        decoded.rule_extensions[0].get::<DelMarkerExpiration>(),
        Some(&DelMarkerExpiration { days: 7 })
    );
    decoded.configuration.rules[0].id = Some("changed".to_owned());

    assert_eq!(dialect.rewrite(&persisted).expect("a complete read may be replaced"), CHANGED);
}

proptest! {
    /// Every valid positive day count survives a real persisted mutation in the registered slot.
    #[test]
    fn registered_lifecycle_days_survive_arbitrary_real_rmw(
        days in 1i32..=i32::MAX,
        suffix in "[a-zA-Z0-9_-]{1,24}",
    ) {
        let source = format!(
            "<LifecycleConfiguration><Rule><Expiration><Days>7</Days></Expiration>\
             <DelMarkerExpiration><Days>{days}</Days></DelMarkerExpiration>\
             <Filter><Prefix>del/</Prefix></Filter><ID>before</ID><Status>Enabled</Status>\
             </Rule></LifecycleConfiguration>"
        );
        let dialect = MinioLifecycleDialect::new().expect("one concrete registration is unique");
        let mut persisted = dialect.decode_persisted(source.as_bytes());
        let decoded = persisted.value_mut().expect("the registered document decodes completely");
        prop_assert_eq!(
            decoded.rule_extensions[0].get::<DelMarkerExpiration>(),
            Some(&DelMarkerExpiration { days })
        );
        let changed = format!("changed-{suffix}");
        decoded.configuration.rules[0].id = Some(changed.clone());

        let encoded = String::from_utf8(dialect.rewrite(&persisted).expect("a complete read may be replaced"))
            .expect("the XML writer emits UTF-8");
        let expiration = encoded.find("</Expiration>").expect("the known sibling is present");
        let extension = encoded.find("<DelMarkerExpiration>").expect("the registered field is present");
        let filter = encoded.find("<Filter>").expect("the following known sibling is present");
        prop_assert!(expiration < extension && extension < filter, "extension left its declared slot: {encoded}");
        let days_fragment = format!("<Days>{days}</Days></DelMarkerExpiration>");
        let id_fragment = format!("<ID>{changed}</ID>");
        prop_assert!(encoded.contains(&days_fragment));
        prop_assert!(encoded.contains(&id_fragment));
    }
}

#[test]
fn c_lifecycle_0018_without_the_registration_preserves_bytes_and_blocks_rmw() {
    let dialect = MinioLifecycleDialect::without_extensions();
    let persisted = dialect.decode_persisted(CANONICAL);

    assert_eq!(persisted.original_bytes(), CANONICAL);
    assert_eq!(dialect.rewrite(&persisted), Err(ExtError::PersistedRewriteBlocked));
}

#[test]
fn c_dial_0022_an_unregistered_persisted_sibling_preserves_bytes_and_blocks_rmw() {
    let dialect = MinioLifecycleDialect::new().expect("one concrete registration is unique");
    let raw =
        b"<LifecycleConfiguration><Rule><Status>Enabled</Status><FutureKnob>on</FutureKnob></Rule></LifecycleConfiguration>";
    let persisted = dialect.decode_persisted(raw);

    assert_eq!(persisted.original_bytes(), raw);
    assert_eq!(dialect.rewrite(&persisted), Err(ExtError::PersistedRewriteBlocked));
}

#[test]
fn n_a_malformed_persisted_lifecycle_document_is_never_absent_or_rewritten() {
    let dialect = MinioLifecycleDialect::new().expect("one concrete registration is unique");
    let raw = b"<LifecycleConfiguration><Rule><Status>Enabled";
    let persisted = dialect.decode_persisted(raw);

    assert!(persisted.value().is_err());
    assert_eq!(persisted.original_bytes(), raw);
    assert_eq!(dialect.rewrite(&persisted), Err(ExtError::PersistedRewriteBlocked));
}
