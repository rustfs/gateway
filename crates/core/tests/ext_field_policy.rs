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

//! Production contracts for runtime XML extension fields.
//!
//! Responsible for: proving a borrowed codec policy can dispatch one typed field and emit it at
//! its declared known-sibling slot. NOT responsible for: a concrete vendor dialect, literal-body
//! codecs, or error rendering. Upstream: ADR-0007 and the production types/XML crates. Downstream:
//! generated parent codecs that consume the same policy.

use rustfs_gateway_types::ext::{CodecPolicy, ExtError, ExtField, Extensions, PersistedXml, UnknownElementPolicy};
use rustfs_gateway_xml::{XmlNode, XmlWriter, parse};

#[derive(Debug, Eq, PartialEq)]
struct DelMarkerExpiration {
    days: u32,
}

impl ExtField for DelMarkerExpiration {
    const PARENT: &'static str = "LifecycleRule";
    const LOCAL_NAME: &'static str = "DelMarkerExpiration";
    const INSERT_AFTER: &'static str = "Expiration";

    fn decode_xml(node: &XmlNode) -> Result<Self, ExtError> {
        let days = node
            .children
            .iter()
            .find(|child| child.name == "Days")
            .ok_or(ExtError::MissingRequired("DelMarkerExpiration.Days"))?
            .text
            .parse()
            .map_err(|_| ExtError::InvalidValue("DelMarkerExpiration.Days"))?;
        Ok(Self { days })
    }

    fn encode_xml(&self, writer: &mut XmlWriter) -> Result<(), ExtError> {
        writer.open(Self::LOCAL_NAME, None);
        writer.element_i64("Days", i64::from(self.days));
        writer.close();
        Ok(())
    }
}

fn extension_node(xml: &[u8]) -> XmlNode {
    parse(xml).expect("the fixture is bounded well-formed XML")
}

#[test]
fn c_dial_0001_registered_field_uses_a_borrowed_policy_and_exact_slot() {
    let mut policy = CodecPolicy::security_relevant();
    policy.register::<DelMarkerExpiration>().expect("one registration is unique");
    let mut extensions = Extensions::default();

    policy
        .decode_unknown(
            DelMarkerExpiration::PARENT,
            &extension_node(b"<DelMarkerExpiration><Days>7</Days></DelMarkerExpiration>"),
            &mut extensions,
        )
        .expect("the registered field decodes");

    assert_eq!(extensions.get::<DelMarkerExpiration>(), Some(&DelMarkerExpiration { days: 7 }));
    let mut writer = XmlWriter::fragment();
    policy
        .encode_after(DelMarkerExpiration::PARENT, "Expiration", &extensions, &mut writer)
        .expect("the declared insertion slot encodes");
    assert_eq!(writer.finish(), "<DelMarkerExpiration><Days>7</Days></DelMarkerExpiration>");
}

#[test]
fn c_dial_0025_security_default_rejects_an_unregistered_sibling() {
    let policy = CodecPolicy::security_relevant();
    let mut extensions = Extensions::default();
    let error = policy
        .decode_unknown("LifecycleRule", &extension_node(b"<Unregistered></Unregistered>"), &mut extensions)
        .expect_err("security-relevant XML defaults to allow only registered fields");
    assert_eq!(policy.unknown_elements(), UnknownElementPolicy::AllowRegistered);
    assert_eq!(error, ExtError::UnknownElement("Unregistered".to_owned()));
}

#[test]
fn c_ext_n014_an_unimplemented_insertion_slot_fails_closed() {
    let mut policy = CodecPolicy::security_relevant();
    policy.register::<DelMarkerExpiration>().expect("one registration is unique");
    let mut extensions = Extensions::default();
    extensions.insert(DelMarkerExpiration { days: 7 });
    let error = policy
        .validate_slots(DelMarkerExpiration::PARENT, &["ID", "Status"])
        .expect_err("the parent codec does not implement the declared slot");
    assert_eq!(
        error,
        ExtError::UnsupportedInsertionSlot {
            parent: "LifecycleRule",
            local_name: "DelMarkerExpiration",
            insert_after: "Expiration",
        }
    );
}

#[test]
fn c_dial_0022_an_unregistered_persisted_field_preserves_the_original_bytes_and_blocks_rewrite() {
    let original = b"<Rule><Unregistered>keep me</Unregistered></Rule>";
    let document = PersistedXml::<()>::decode(original.to_vec(), |_| Err(ExtError::UnknownElement("Unregistered".to_owned())));

    assert_eq!(document.original_bytes(), original);
    assert_eq!(document.replacement(b"<Rule></Rule>".to_vec()), Err(ExtError::PersistedRewriteBlocked));
}

#[test]
fn n_a_persisted_parse_failure_is_not_translated_to_absent_configuration() {
    let original = b"<Rule><Status>Enabled";
    let document = PersistedXml::<()>::decode(original.to_vec(), |_| Err(ExtError::InvalidXml));

    assert!(matches!(document.value(), Err(ExtError::InvalidXml)));
    assert_eq!(document.original_bytes(), original);
    assert_eq!(document.replacement(Vec::new()), Err(ExtError::PersistedRewriteBlocked));
}
