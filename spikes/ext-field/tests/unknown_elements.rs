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

//! Three-state unknown-element policy cases.

use ext_field_spike::{CodecPolicy, DelMarkerExpiration, LifecycleRule, UnknownPolicy, XmlError};

fn registered_policy(mode: UnknownPolicy) -> CodecPolicy {
    let mut policy = CodecPolicy::new(mode);
    policy.register::<DelMarkerExpiration>().expect("one registration");
    policy
}

#[test]
fn c_ext_n001_lenient_skips_unregistered_element() {
    let input = b"<Rule><ID>rule-1</ID><FutureField>ignored</FutureField><Status>Enabled</Status></Rule>";
    let rule = LifecycleRule::decode_xml(input, &CodecPolicy::new(UnknownPolicy::Lenient)).expect("unknown is skipped");

    assert_eq!(rule.id.as_deref(), Some("rule-1"));
    assert_eq!(rule.status, "Enabled");
}

#[test]
fn c_ext_n002_lenient_skips_entire_nested_subtree() {
    let input = b"<Rule><FutureField><Nested><Leaf>ignored</Leaf></Nested></FutureField><Status>Enabled</Status></Rule>";
    let rule = LifecycleRule::decode_xml(input, &CodecPolicy::new(UnknownPolicy::Lenient))
        .expect("nested unknown subtree is skipped without cursor drift");

    assert_eq!(rule.status, "Enabled");
}

#[test]
fn c_ext_n003_allow_registered_rejects_unregistered_element() {
    let input = b"<Rule><FutureField>ignored</FutureField><Status>Enabled</Status></Rule>";
    let error = LifecycleRule::decode_xml(input, &registered_policy(UnknownPolicy::AllowRegistered))
        .expect_err("unregistered unknown must fail");

    assert!(matches!(error, XmlError::UnknownElement(name) if name == "FutureField"));
}

#[test]
fn c_ext_n004_deny_rejects_even_registered_element() {
    let input = b"<Rule><Status>Enabled</Status><DelMarkerExpiration><Days>7</Days></DelMarkerExpiration></Rule>";
    let error =
        LifecycleRule::decode_xml(input, &registered_policy(UnknownPolicy::Deny)).expect_err("deny rejects registered extension");

    assert!(matches!(error, XmlError::UnknownElement(name) if name == "DelMarkerExpiration"));
}

#[test]
fn c_ext_n013_persisted_configuration_cannot_default_to_deny() {
    let persisted = b"<Rule><Status>Enabled</Status><FutureRetention><Days>7</Days></FutureRetention></Rule>";
    let error = LifecycleRule::decode_xml(persisted, &CodecPolicy::new(UnknownPolicy::Deny))
        .expect_err("deny would make a previously readable persisted document unavailable");

    assert!(matches!(error, XmlError::UnknownElement(name) if name == "FutureRetention"));
}
