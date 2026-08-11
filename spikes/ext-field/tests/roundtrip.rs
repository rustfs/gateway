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

//! Q1 round-trip, registration, ordering, and loss-boundary cases.

use ext_field_spike::{
    CodecPolicy, DelMarkerExpiration, ExtField, LifecycleRule, UnknownPolicy, XmlError, XmlReader, XmlWriter, write_text_element,
};
use rustfs_gateway_core::Req as FrameworkReq;
use rustfs_gateway_types::dto::PutBucketLifecycleConfiguration;

// Measured from origin/main@f4d90745b0ebe20349338638442d230426c7ca2c.
const MAIN_REQ_SIZE_64: usize = 136;

const STANDARD_XML: &str = "<Rule><Expiration><Days>30</Days></Expiration><ID>rule-1</ID><Status>Enabled</Status></Rule>";
const DIALECT_XML: &str = "<Rule><Expiration><Days>30</Days></Expiration><DelMarkerExpiration><Days>7</Days></DelMarkerExpiration><ID>rule-1</ID><Status>Enabled</Status></Rule>";

fn registered_policy(mode: UnknownPolicy) -> CodecPolicy {
    let mut policy = CodecPolicy::new(mode);
    policy.register::<DelMarkerExpiration>().expect("one registration");
    policy
}

#[test]
fn c_ext_0001_registered_extension_decodes_to_typed_slot() {
    let rule = LifecycleRule::decode_xml(DIALECT_XML.as_bytes(), &registered_policy(UnknownPolicy::AllowRegistered))
        .expect("registered dialect field decodes");

    assert_eq!(rule.ext.get::<DelMarkerExpiration>().map(|value| value.days), Some(7));
}

#[test]
fn c_ext_0002_registered_extension_encodes_through_vtable() {
    let mut rule = LifecycleRule::new("Enabled");
    rule.id = Some("rule-1".to_owned());
    rule.expiration_days = Some(30);
    rule.ext.insert(DelMarkerExpiration { days: 7 });

    let output = rule
        .encode_xml(&registered_policy(UnknownPolicy::AllowRegistered))
        .expect("registered dialect field encodes");
    assert!(
        String::from_utf8(output)
            .expect("XML is UTF-8")
            .contains("<DelMarkerExpiration><Days>7</Days>")
    );
}

#[test]
fn c_ext_0003_byte_identical_roundtrip() {
    let policy = registered_policy(UnknownPolicy::AllowRegistered);
    let rule = LifecycleRule::decode_xml(DIALECT_XML.as_bytes(), &policy).expect("decode");

    assert_eq!(rule.encode_xml(&policy).expect("encode"), DIALECT_XML.as_bytes());
}

#[test]
fn c_ext_0004_static_codec_does_not_name_dialect_type() {
    let source = include_str!("../src/lifecycle_rule.rs");
    assert!(!source.contains("DelMarkerExpiration"));
}

#[test]
fn c_ext_0005_no_extension_is_identical_to_baseline() {
    let policy = CodecPolicy::new(UnknownPolicy::Lenient);
    let rule = LifecycleRule::decode_xml(STANDARD_XML.as_bytes(), &policy).expect("standard XML decodes");

    assert_eq!(rule.encode_xml(&policy).expect("standard XML encodes"), STANDARD_XML.as_bytes());

    let measurement_policy = registered_policy(UnknownPolicy::Lenient);
    let iterations = 2_000_000_u32;
    let started = std::time::Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(measurement_policy.ext_fields_for(std::hint::black_box("LifecycleRule")));
    }
    let elapsed = started.elapsed();
    let candidate_req_size = std::mem::size_of::<FrameworkReq<PutBucketLifecycleConfiguration>>();
    #[cfg(target_pointer_width = "64")]
    assert_eq!(
        candidate_req_size, MAIN_REQ_SIZE_64,
        "the candidate must not enlarge the real framework request"
    );
    println!(
        "Q3 lookup: {iterations} iterations in {elapsed:?}, {:.2} ns/lookup; policy ref: {} bytes; main Req snapshot: {MAIN_REQ_SIZE_64} bytes; candidate Req: {candidate_req_size} bytes",
        elapsed.as_nanos() as f64 / f64::from(iterations),
        std::mem::size_of::<&CodecPolicy>()
    );
}

struct DuplicateField;

impl ExtField for DuplicateField {
    const PARENT: &'static str = "LifecycleRule";
    const LOCAL_NAME: &'static str = "DelMarkerExpiration";
    const INSERT_AFTER: &'static str = "Expiration";

    fn encode_xml(&self, writer: &mut XmlWriter) -> Result<(), XmlError> {
        write_text_element(writer, Self::LOCAL_NAME, "duplicate")
    }

    fn decode_xml(_reader: &mut XmlReader<'_>) -> Result<Self, XmlError> {
        Ok(Self)
    }
}

#[test]
fn c_ext_n011_duplicate_parent_and_local_name_is_rejected() {
    let mut policy = registered_policy(UnknownPolicy::AllowRegistered);
    let error = policy
        .register::<DuplicateField>()
        .expect_err("duplicate registration must fail");

    assert!(matches!(error, XmlError::DuplicateRegistration { .. }));
}

#[test]
fn c_ext_n012_unset_typed_slot_returns_none() {
    let rule = LifecycleRule::new("Enabled");
    assert!(rule.ext.get::<DelMarkerExpiration>().is_none());
}

#[test]
fn c_ext_n014_extension_before_known_fields_is_not_canonical() {
    let input = "<Rule><DelMarkerExpiration><Days>7</Days></DelMarkerExpiration><Expiration><Days>30</Days></Expiration><ID>rule-1</ID><Status>Enabled</Status></Rule>";
    let policy = registered_policy(UnknownPolicy::AllowRegistered);
    let rule = LifecycleRule::decode_xml(input.as_bytes(), &policy).expect("input order is readable");
    let output = String::from_utf8(rule.encode_xml(&policy).expect("canonical encode")).expect("XML is UTF-8");

    assert_ne!(output, input);
    assert!(output.find("</Expiration>").expect("known field") < output.find("<DelMarkerExpiration>").expect("ext field"));
    assert!(output.find("<DelMarkerExpiration>").expect("ext field") < output.find("<ID>").expect("following known field"));

    let mut unsupported_policy = CodecPolicy::new(UnknownPolicy::AllowRegistered);
    unsupported_policy
        .register::<UnsupportedSlotField>()
        .expect("one registration");
    let mut unsupported_rule = LifecycleRule::new("Enabled");
    unsupported_rule.ext.insert(UnsupportedSlotField);
    let error = unsupported_rule
        .encode_xml(&unsupported_policy)
        .expect_err("an unsupported insertion slot must fail closed");
    assert!(matches!(error, XmlError::Extension(_)));
}

struct UnsupportedSlotField;

impl ExtField for UnsupportedSlotField {
    const PARENT: &'static str = "LifecycleRule";
    const LOCAL_NAME: &'static str = "UnsupportedSlot";
    const INSERT_AFTER: &'static str = "Filter";

    fn encode_xml(&self, writer: &mut XmlWriter) -> Result<(), XmlError> {
        write_text_element(writer, Self::LOCAL_NAME, "unsupported")
    }

    fn decode_xml(_reader: &mut XmlReader<'_>) -> Result<Self, XmlError> {
        Ok(Self)
    }
}

struct FailingField;

impl ExtField for FailingField {
    const PARENT: &'static str = "LifecycleRule";
    const LOCAL_NAME: &'static str = "DelMarkerExpiration";
    const INSERT_AFTER: &'static str = "Expiration";

    fn encode_xml(&self, _writer: &mut XmlWriter) -> Result<(), XmlError> {
        Err(XmlError::Extension("injected encode failure".to_owned()))
    }

    fn decode_xml(_reader: &mut XmlReader<'_>) -> Result<Self, XmlError> {
        Ok(Self)
    }
}

#[test]
fn c_ext_n015_extension_encode_error_exposes_no_partial_xml() {
    let mut policy = CodecPolicy::new(UnknownPolicy::AllowRegistered);
    policy.register::<FailingField>().expect("one registration");
    let mut rule = LifecycleRule::new("Enabled");
    rule.ext.insert(FailingField);

    let error = rule
        .encode_xml(&policy)
        .expect_err("extension failure aborts the whole encode");
    assert!(matches!(error, XmlError::Extension(_)));
}

#[test]
fn c_ext_n016_lenient_unregistered_roundtrip_loses_extension() {
    let policy = CodecPolicy::new(UnknownPolicy::Lenient);
    let rule = LifecycleRule::decode_xml(DIALECT_XML.as_bytes(), &policy).expect("lenient decode skips unregistered ext");
    let output = rule.encode_xml(&policy).expect("remaining known fields encode");

    assert_eq!(output, STANDARD_XML.as_bytes());
    assert_ne!(output, DIALECT_XML.as_bytes());
}
