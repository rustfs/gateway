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

//! The replication invariants the round-trip identity cannot see, over every generated legal
//! configuration.
//!
//! Responsible for: what must follow when a sender does what this encoder never does — plants
//! elements this build does not know (`q-repl-0005`), orders the members of a rule or of its
//! destination differently, or mixes the V1 and V2 schemas in one rule (`q-repl-0006`).
//! NOT responsible for: the `decode ∘ encode` identity, the wire shape it is checked against, the
//! generators and the boundary tests, which `replication_roundtrip.rs` owns and this module
//! reuses; and the semantic rules themselves, which `ops::shared::replication` owns.
//! Upstream: `replication_roundtrip.rs` (the generator, the codec fixtures and the projection) and
//! `ops::shared::replication`. Downstream: nothing.
//!
//! Moved out of `replication_roundtrip.rs` unchanged, so that file stays inside its
//! `allowances/file_size.txt` limit.
//!
// The crate denies these so that no request path can panic on a caller's bytes. A test asserts
// against a fixture it wrote itself, where a panic is the failure report; AGENTS.md exempts test
// code from the rule, and this is where that exemption is spelled.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use proptest::prelude::*;
use rustfs_gateway_core::ops::shared::replication::{ReplicationRejection, validate_replication};
use rustfs_gateway_types::dto;

use crate::replication_roundtrip::{ROOT, decode_write, encode_read, projection, replication_configuration};

// ── the invariants the identity cannot see ───────────────────────────────────────────────────
//
// The identity walks documents this codec wrote, so it is blind to everything a *sender* is free
// to do that this encoder never does: interleave elements this build has never heard of, put the
// members of a rule in another order, or mix the two schema versions in one rule. Each of the three
// properties below takes a generated legal configuration, perturbs its document in exactly one of
// those ways, and states what must follow. The corpus pins one fixed sample of each; these pin the
// same rule over every rule position and every member set the generator reaches.

/// Elements no replication schema this build knows declares, in the three forms a future AWS
/// member or another vendor's dialect would take: a leaf, a subtree, and an empty element whose
/// name begins with a real member's name.
const UNKNOWN_ELEMENTS: &[&str] = &[
    "<FutureKnob>opaque</FutureKnob>",
    "<VendorExtension><Nested>x</Nested><Nested/></VendorExtension>",
    "<RuleSet/>",
];

/// Plants `element` as the first child of the root, the first child of every `<Rule>` and the last
/// child of every `<Destination>`. Never inside a `<Filter>`: an empty filter holding only an unknown
/// child is `q-repl-0015`'s refusal, not a skip.
fn plant_unknown(document: &str, element: &str) -> String {
    let root_open_end = document
        .find(ROOT)
        .and_then(|at| document[at..].find('>').map(|end| at + end + 1))
        .expect("the document names its root");
    let (head, body) = document.split_at(root_open_end);
    let body = body
        .replace("<Rule>", &format!("<Rule>{element}"))
        .replace("</Destination>", &format!("{element}</Destination>"));
    format!("{head}{element}{body}")
}

/// The top-level child elements of an element's inner text, each as its full source text. The
/// encoder escapes every `<` in text and writes no attribute inside a rule, so a `<` always starts
/// a tag here.
fn top_level_children(inner: &str) -> Vec<&str> {
    let mut children = Vec::new();
    let (mut depth, mut start, mut cursor) = (0usize, 0usize, 0usize);
    while let Some(offset) = inner[cursor..].find('<') {
        let open = cursor + offset;
        let close = open + inner[open..].find('>').expect("every tag the encoder writes is closed");
        let tag = &inner[open..=close];
        if tag.starts_with("</") {
            depth -= 1;
            if depth == 0 {
                children.push(&inner[start..=close]);
            }
        } else if tag.ends_with("/>") {
            if depth == 0 {
                children.push(tag);
            }
        } else {
            if depth == 0 {
                start = open;
            }
            depth += 1;
        }
        cursor = close + 1;
    }
    children
}

/// A deterministic Fisher–Yates over `items`, driven by splitmix64 from `seed`. When the shuffle
/// happens to be the identity the order is reversed instead, so every element with two or more
/// distinct children really arrives in another order.
fn permute<'a>(items: &[&'a str], seed: u64) -> Vec<&'a str> {
    let mut state = seed;
    let mut next = || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    };
    let mut permuted = items.to_vec();
    for index in (1..permuted.len()).rev() {
        let pick = usize::try_from(next() % (index as u64 + 1)).expect("an index below the length fits");
        permuted.swap(index, pick);
    }
    if permuted == items {
        permuted.reverse();
    }
    permuted
}

/// Permutes the direct children of every `<{element}>` in `document`. Neither element this is used
/// for nests inside itself, so the first close after an open is its own.
fn permute_children_of(document: &str, element: &str, seed: u64) -> String {
    let (open, close) = (format!("<{element}>"), format!("</{element}>"));
    let mut out = String::with_capacity(document.len());
    let mut rest = document;
    let mut occurrence = 0u64;
    while let Some(at) = rest.find(&open) {
        let inner_start = at + open.len();
        let inner_end = inner_start
            + rest[inner_start..]
                .find(&close)
                .expect("every element the encoder opens it closes");
        let children = top_level_children(&rest[inner_start..inner_end]);
        out.push_str(&rest[..inner_start]);
        out.push_str(&permute(&children, seed ^ occurrence.wrapping_mul(0xA24B_AED4_963E_E407)).concat());
        out.push_str(&close);
        rest = &rest[inner_end + close.len()..];
        occurrence += 1;
    }
    out.push_str(rest);
    out
}

/// The document a sender that ordered nothing the way this encoder does would send: the members of
/// every rule and of every destination permuted, and the role moved behind the rules. The rules
/// themselves keep their relative order, because that order is the configuration's meaning.
fn shuffle_members(document: &str, seed: u64) -> String {
    let role_start = document.find("<Role>").expect("the encoder writes the role");
    let role_end = role_start + document[role_start..].find("</Role>").expect("and closes it") + "</Role>".len();
    let role = &document[role_start..role_end];
    let without_role = format!("{}{}", &document[..role_start], &document[role_end..]);
    let root_close = without_role.rfind("</ReplicationConfiguration>").expect("the root closes");
    let moved = format!("{}{role}{}", &without_role[..root_close], &without_role[root_close..]);
    let rules = permute_children_of(&moved, "Rule", seed);
    permute_children_of(&rules, "Destination", seed.rotate_left(17))
}

/// The one schema-version mixture injected into one rule, with the refusal it must draw.
fn mix_schema_versions(rule: &mut dto::ReplicationRule, choice: u8) -> ReplicationRejection {
    if rule.filter.is_some() {
        match choice % 3 {
            0 => {
                rule.prefix = Some("legacy/".to_owned());
                ReplicationRejection::FilterBesideLegacyPrefix
            }
            1 => {
                rule.priority = None;
                ReplicationRejection::PriorityMissingWithFilter
            }
            _ => {
                rule.delete_marker_replication = None;
                ReplicationRejection::DeleteMarkerReplicationMissingWithFilter
            }
        }
    } else if choice.is_multiple_of(2) {
        rule.priority = Some(1);
        ReplicationRejection::PriorityOnLegacyRule
    } else {
        rule.delete_marker_replication = Some(dto::DeleteMarkerReplication {
            status: Some(dto::Status::DISABLED),
        });
        ReplicationRejection::DeleteMarkerReplicationOnLegacyRule
    }
}

proptest! {
    /// `q-repl-0005`: an element this build does not know is skipped wherever a sender puts it,
    /// and skipping it changes nothing about the rules. A decoder that grew stricter here would
    /// not switch replication off — RustFS reads the stored document fail-closed, so it would make
    /// the bucket unusable on the next read.
    #[test]
    fn an_unknown_element_anywhere_a_sender_puts_it_changes_nothing(
        configuration in replication_configuration(),
        element in prop::sample::select(UNKNOWN_ELEMENTS),
    ) {
        let planted = plant_unknown(&encode_read(configuration.clone()), element);
        prop_assert_eq!(
            planted.matches(element).count(),
            1 + 2 * configuration.rules.len(),
            "the plant reached the root, every rule and every destination: {}", planted
        );

        let decoded = decode_write(&planted).map_err(|error| {
            TestCaseError::fail(format!("an unknown element must be skipped, not refused: {error:?}: {planted}"))
        })?;

        prop_assert_eq!(validate_replication(&decoded), Ok(()), "document: {}", planted);
        prop_assert_eq!(projection(&decoded), projection(&configuration), "document: {}", planted);
    }

    /// The reader is order-insensitive for every member of a rule and of its destination, and for
    /// the role against the rules — over every member set the generator reaches, not the single
    /// hand-written shuffle the fixed test below pins.
    #[test]
    fn a_rule_is_the_same_rule_whatever_order_its_members_arrive_in(
        configuration in replication_configuration(),
        seed in any::<u64>(),
    ) {
        let document = encode_read(configuration.clone());
        let shuffled = shuffle_members(&document, seed);
        prop_assert_ne!(&shuffled, &document, "the shuffle moved nothing");
        prop_assert_eq!(shuffled.len(), document.len(), "the shuffle only moved elements: {}", shuffled);

        let decoded = decode_write(&shuffled).map_err(|error| {
            TestCaseError::fail(format!("a reordered document is the same document: {error:?}: {shuffled}"))
        })?;

        prop_assert_eq!(projection(&decoded), projection(&configuration), "document: {}", shuffled);
    }

    /// `q-repl-0006`: one rule mixing the V1 and V2 schemas, at any position among otherwise legal
    /// rules, is refused with the coupling it broke — both as written and after the trip through
    /// the wire, because the stored document is what the next read judges, and an encoder that
    /// dropped the stray member would silently install a rule its writer never sent.
    #[test]
    fn a_schema_version_mixture_in_any_rule_is_refused_by_its_coupling(
        mut configuration in replication_configuration(),
        position in any::<prop::sample::Index>(),
        choice in any::<u8>(),
    ) {
        let index = position.index(configuration.rules.len());
        let expected = mix_schema_versions(&mut configuration.rules[index], choice);

        prop_assert_eq!(validate_replication(&configuration), Err(expected.clone()), "mixed rule #{}", index);

        let document = encode_read(configuration);
        let decoded = decode_write(&document).map_err(|error| {
            TestCaseError::fail(format!("a mixture is a semantic refusal, not a parse failure: {error:?}: {document}"))
        })?;
        prop_assert_eq!(validate_replication(&decoded), Err(expected), "mixed rule #{}: {}", index, document);
    }
}
