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

//! The schema-bound reading against a small hand-written document: a negative-majority matrix of
//! what it refuses, why, and what the tree it returns holds.
//!
//! Responsible for: every refusal [`super::Reason`] names and every rule the module docs state,
//! over a document that exercises each shape form once.
//! NOT responsible for: any operation's real document (the generated schemas and the differential
//! against the legacy stack in `rustfs-gateway-goldens` cover those).
//! Upstream: [`super::read`]. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::{
    Arity, Attribute, BoundRefusal, Content, Document, EmptyBody, Member, Reason, Scalar, ScalarRefusal, Shape, Unknown, Value,
    read,
};
use crate::error::XmlError;
use crate::read::{XmlLimits, XmlNode};

const fn member(element: &'static str, arity: Arity, value: Value, required: bool) -> Member {
    Member {
        element,
        arity,
        value,
        required,
        kept: true,
    }
}

/// `Config` (a document root: unknown elements skipped) holding a required `Status`, an optional
/// integer `Days`, a repeated `Rule`, a wrapped `TagSet` of `Tag`, a union `Filter`, a `Grantee`
/// with its literal `xsi:type`, an empty structure `Simple`, and `Legacy`, validated and dropped.
static SHAPES: [Shape; 6] = [
    Shape {
        name: "Config",
        content: Content::Members {
            members: &[
                member("Status", Arity::One, Value::Text(Scalar::Text), true),
                member("Days", Arity::One, Value::Text(Scalar::Integer), false),
                member("Rule", Arity::Repeated, Value::Shape(1), false),
                member("TagSet", Arity::Wrapped("Tag"), Value::Shape(1), false),
                member("Filter", Arity::One, Value::Shape(2), false),
                member("Grantee", Arity::One, Value::Shape(3), false),
                member("Simple", Arity::One, Value::Shape(4), false),
                Member {
                    element: "Legacy",
                    arity: Arity::One,
                    value: Value::Shape(5),
                    required: false,
                    kept: false,
                },
            ],
            unknown: Unknown::Skip,
        },
        attribute: None,
    },
    Shape {
        name: "Rule",
        content: Content::Members {
            members: &[
                member("ID", Arity::One, Value::Text(Scalar::Text), true),
                member("Note", Arity::One, Value::Text(Scalar::Text), false),
            ],
            unknown: Unknown::Refuse,
        },
        attribute: None,
    },
    Shape {
        name: "Filter",
        content: Content::Choice(&[
            member("Prefix", Arity::One, Value::Text(Scalar::Text), false),
            member("Size", Arity::One, Value::Text(Scalar::Long), false),
        ]),
        attribute: None,
    },
    Shape {
        name: "Grantee",
        content: Content::Members {
            members: &[member("ID", Arity::One, Value::Text(Scalar::Text), false)],
            unknown: Unknown::Refuse,
        },
        attribute: Some(Attribute {
            key: "xsi:type",
            name: "type",
            namespace: "http://www.w3.org/2001/XMLSchema-instance",
            required: true,
        }),
    },
    Shape {
        name: "Simple",
        content: Content::Members {
            members: &[],
            unknown: Unknown::Refuse,
        },
        attribute: None,
    },
    Shape {
        name: "Legacy",
        content: Content::Members {
            members: &[member("Name", Arity::One, Value::Text(Scalar::Text), false)],
            unknown: Unknown::Refuse,
        },
        attribute: None,
    },
];

static DOCUMENT: Document = Document {
    roots: &["Config", "Alias"],
    shapes: &SHAPES,
    empty: EmptyBody::Missing,
};

/// The same shapes, with an empty body refused as a document.
static PLAIN: Document = Document {
    roots: &["Config"],
    shapes: &SHAPES,
    empty: EmptyBody::Refused,
};

/// The scalar reading these tests use: integers must be digits and are spelled back without
/// leading zeros, `bad` is unreadable, `wide` is uncarriable, and every other value is unchanged.
fn scalar(kind: Scalar, raw: &str) -> Result<String, ScalarRefusal> {
    match (kind, raw) {
        (_, "bad") => Err(ScalarRefusal::Unreadable),
        (_, "wide") => Err(ScalarRefusal::Uncarriable),
        (Scalar::Integer | Scalar::Long, digits) => digits
            .parse::<i64>()
            .map(|value| value.to_string())
            .map_err(|_| ScalarRefusal::Unreadable),
        (_, text) => Ok(text.to_owned()),
    }
}

fn read_with(body: &str, limits: XmlLimits) -> Result<XmlNode, BoundRefusal> {
    read(body.as_bytes(), &DOCUMENT, limits, &scalar)
}

fn bound(body: &str) -> Result<XmlNode, BoundRefusal> {
    read_with(body, XmlLimits::S3)
}

fn refused(body: &str, reason: Reason) {
    assert_eq!(bound(body), Err(BoundRefusal::Document(reason)), "{body}");
}

fn names(node: &XmlNode) -> Vec<&str> {
    node.children.iter().map(|child| child.name.as_str()).collect()
}

// ── what is read ───────────────────────────────────────────────────────────────────────────────

/// Positive — every shape form, read into the tree the decoders read: members in document order,
/// scalars in the scalar reading's spelling, the repeated member twice, the wrapped list's entries
/// under its wrapper, the union's one member, and the attribute under its namespace.
#[test]
fn a_document_of_every_form_reads_into_its_tree() {
    let tree = bound(concat!(
        "<Config><Days>007</Days><Status>on</Status>",
        "<Rule><ID>a</ID></Rule><Rule><ID>b</ID><Note>n</Note></Rule>",
        "<TagSet><Tag><ID>t</ID></Tag></TagSet><Filter><Size>5</Size></Filter>",
        "<Grantee xsi:type=\"Group\"><ID>g</ID></Grantee><Simple/></Config>",
    ))
    .expect("the document reads");
    assert_eq!(tree.name, "Config");
    assert_eq!(names(&tree), ["Days", "Status", "Rule", "Rule", "TagSet", "Filter", "Grantee", "Simple"]);
    assert_eq!(tree.child_text("Days"), Some("7"), "the scalar reading's spelling");
    assert_eq!(tree.children_named("Rule").count(), 2);
    let tags = tree.child("TagSet").expect("the wrapper");
    assert_eq!(names(tags), ["Tag"]);
    assert_eq!(tree.child("Filter").and_then(|filter| filter.child_text("Size")), Some("5"));
    let grantee = tree.child("Grantee").expect("the grantee");
    assert_eq!(grantee.attribute_ns("http://www.w3.org/2001/XMLSchema-instance", "type"), Some("Group"));
}

/// Positive — an alias root reads under its own name, and a self-closing element is the same
/// element as its paired spelling.
#[test]
fn an_alias_root_and_a_self_closing_element_read() {
    let tree = bound("<Alias><Status/></Alias>").expect("the alias root reads");
    assert_eq!(tree.name, "Alias");
    assert_eq!(tree.child_text("Status"), Some(""));
    assert_eq!(bound("<Alias><Status></Status></Alias>"), Ok(tree));
}

/// Positive — at the document root an unknown element is skipped with everything inside it,
/// and a member validated for the legacy stack but carried by no decoder is left out.
#[test]
fn an_unknown_element_at_the_root_is_skipped_and_a_dropped_member_is_left_out() {
    let tree =
        bound("<Config><Future><Deep a=b>x<Deeper/></Deep></Future><Status>s</Status><Legacy><Name>n</Name></Legacy></Config>")
            .expect("the unknown element is skipped");
    assert_eq!(names(&tree), ["Status"]);
}

/// Positive — scalar text is the character data exactly as written: references resolved, CDATA
/// sections and comments left out, a carriage return kept.
#[test]
fn a_scalar_is_its_character_data_as_written() {
    let tree = bound("<Config><Status>a&amp;b&#x41;&#66;<![CDATA[gone]]><!-- no -->c\r\nd</Status></Config>")
        .expect("the document reads");
    assert_eq!(tree.child_text("Status"), Some("a&bABc\r\nd"));
}

/// Positive — text between members, before the root and after it is ignored.
#[test]
fn text_outside_scalars_is_ignored() {
    let tree = bound("junk <Config> x <Status>s</Status> y </Config> z").expect("the document reads");
    assert_eq!(names(&tree), ["Status"]);
}

/// Positive — inside a wrapped list an element other than the entry is skipped.
#[test]
fn an_unknown_element_inside_a_wrapped_list_is_skipped() {
    let tree = bound("<Config><Status>s</Status><TagSet><Other><ID>x</ID></Other><Tag><ID>t</ID></Tag></TagSet></Config>")
        .expect("the document reads");
    assert_eq!(names(tree.child("TagSet").expect("the wrapper")), ["Tag"]);
}

// ── what is refused ────────────────────────────────────────────────────────────────────────────

/// Negative — an unknown element inside a structure that is not a document root.
#[test]
fn n_an_unknown_element_inside_a_nested_structure_is_refused() {
    refused(
        "<Config><Status>s</Status><Rule><ID>a</ID><Future/></Rule></Config>",
        Reason::UnknownElement,
    );
    refused(
        "<Config><Status>s</Status><Grantee xsi:type=\"Group\"><Email/></Grantee></Config>",
        Reason::UnknownElement,
    );
}

/// Negative — a second occurrence of a member that may appear once, at the root, nested, and of a
/// wrapped list's wrapper.
#[test]
fn n_a_repeated_member_is_refused() {
    refused("<Config><Status>a</Status><Status>b</Status></Config>", Reason::Repeated);
    refused("<Config><Status>s</Status><Rule><ID>a</ID><ID>b</ID></Rule></Config>", Reason::Repeated);
    refused("<Config><Status>s</Status><TagSet></TagSet><TagSet></TagSet></Config>", Reason::Repeated);
}

/// Negative — a required member or a required attribute that is absent.
#[test]
fn n_a_missing_required_member_or_attribute_is_refused() {
    refused("<Config></Config>", Reason::Missing);
    refused("<Config><Status>s</Status><Rule><Note>n</Note></Rule></Config>", Reason::Missing);
    refused("<Config><Status>s</Status><Grantee><ID>g</ID></Grantee></Config>", Reason::Missing);
}

/// Negative — the attribute is matched by its spelling: a prefix bound to the same namespace is
/// not it, and an attribute that does not parse refuses the document.
#[test]
fn n_the_attribute_is_matched_literally_and_must_parse() {
    refused(
        "<Config><Status>s</Status><Grantee xmlns:x=\"http://www.w3.org/2001/XMLSchema-instance\" x:type=\"Group\"/></Config>",
        Reason::Missing,
    );
    refused(
        "<Config><Status>s</Status><Grantee xsi:type=\"Group\" xsi:type=\"User\"/></Config>",
        Reason::Attribute,
    );
    refused("<Config><Status>s</Status><Grantee xsi:type=Group/></Config>", Reason::Attribute);
}

/// Negative — an element name is compared as spelled: a prefixed member is unknown, refused where
/// unknown elements are, and a prefixed root is not the root.
#[test]
fn n_a_prefixed_name_is_not_the_member_it_ends_with() {
    refused("<Config><Status>s</Status><Rule><s3:ID>a</s3:ID></Rule></Config>", Reason::UnknownElement);
    refused("<s3:Config xmlns:s3=\"urn:s3\"><Status>s</Status></s3:Config>", Reason::Root);
    let tree = bound("<Config><s3:Status>skipped</s3:Status><Status>s</Status></Config>").expect("skipped at the root");
    assert_eq!(tree.child_text("Status"), Some("s"));
}

/// Negative — an element inside a scalar member, before or after its text.
#[test]
fn n_an_element_inside_a_scalar_is_refused() {
    refused("<Config><Status><b/></Status></Config>", Reason::UnexpectedElement);
    refused("<Config><Status>s<b/></Status></Config>", Reason::UnexpectedElement);
}

/// Negative — a union with no member, with two, or with one it does not declare.
#[test]
fn n_a_union_takes_exactly_one_declared_member() {
    refused("<Config><Status>s</Status><Filter></Filter></Config>", Reason::EmptyChoice);
    refused(
        "<Config><Status>s</Status><Filter><Prefix>p</Prefix><Size>1</Size></Filter></Config>",
        Reason::UnexpectedElement,
    );
    refused("<Config><Status>s</Status><Filter><Tag>t</Tag></Filter></Config>", Reason::UnknownElement);
}

/// Negative — a structure with no members holds no element.
#[test]
fn n_an_empty_structure_holds_no_element() {
    refused("<Config><Status>s</Status><Simple><Child/></Simple></Config>", Reason::UnknownElement);
    assert!(bound("<Config><Status>s</Status><Simple>text</Simple></Config>").is_ok());
}

/// Negative — a root the document does not declare, content after the root, and a document that
/// ends before its root does.
#[test]
fn n_the_root_and_its_end_are_the_documents_bounds() {
    refused("<Other><Status>s</Status></Other>", Reason::Root);
    refused("<Config><Status>s</Status></Config><Config/>", Reason::Trailing);
    refused("   ", Reason::Truncated);
}

/// Negative — a reference that names neither a predefined entity nor a character XML admits.
#[test]
fn n_an_unresolvable_reference_is_refused() {
    for body in [
        "<Config><Status>&nbsp;</Status></Config>",
        "<Config><Status>&#X41;</Status></Config>",
        "<Config><Status>&#1;</Status></Config>",
        "<Config><Status>&#;</Status></Config>",
    ] {
        refused(body, Reason::Reference);
    }
}

/// Negative — the scalar reading decides: an unreadable value refuses the document, and an
/// uncarriable one is refused as that.
#[test]
fn n_the_scalar_reading_refuses_by_its_own_verdict() {
    refused("<Config><Status>bad</Status></Config>", Reason::Unreadable);
    refused("<Config><Status>s</Status><Days>x1</Days></Config>", Reason::Unreadable);
    assert_eq!(bound("<Config><Status>wide</Status></Config>"), Err(BoundRefusal::Uncarriable));
}

/// Negative — the refusals this reading keeps from the tree reader: a `DOCTYPE`, a character XML
/// cannot represent, a document that is not UTF-8, and a malformed one.
#[test]
fn n_the_tree_readers_lexical_refusals_are_kept() {
    assert_eq!(
        bound("<!DOCTYPE Config><Config><Status>s</Status></Config>"),
        Err(BoundRefusal::Xml(XmlError::DocTypeDeclaration))
    );
    assert_eq!(
        bound("<Config><Status>\u{1}</Status></Config>"),
        Err(BoundRefusal::Xml(XmlError::ForbiddenCharacter))
    );
    assert_eq!(
        read(b"<Config><Status>\xff</Status></Config>", &DOCUMENT, XmlLimits::S3, &scalar),
        Err(BoundRefusal::Xml(XmlError::NotUtf8))
    );
    assert_eq!(bound("<Config><Status>s</Rule></Config>"), Err(BoundRefusal::Xml(XmlError::Malformed)));
}

/// Negative — the depth and element ceilings hold, skipped content included.
#[test]
fn n_the_depth_and_element_ceilings_hold_inside_skipped_content() {
    let shallow = XmlLimits::new(1 << 20, 3, 100, 8, 64).expect("non-zero limits");
    assert_eq!(
        read_with("<Config><Status>s</Status><Future><a><b/></a></Future></Config>", shallow),
        Err(BoundRefusal::Xml(XmlError::TooDeep))
    );
    let few = XmlLimits::new(1 << 20, 32, 3, 8, 64).expect("non-zero limits");
    assert_eq!(
        read_with("<Config><Status>s</Status><Future/><Future/></Config>", few),
        Err(BoundRefusal::Xml(XmlError::TooManyElements))
    );
    assert!(read_with("<Config><Status>s</Status><Future/></Config>", few).is_ok());
}

// ── the body as a whole ────────────────────────────────────────────────────────────────────────

/// Negative — a bare body is not a document, MinIO's `Enabled` included: the RustFS profile reads
/// that literal before this reader sees the body (the core's `body_literal`), never here.
#[test]
fn n_a_bare_body_is_not_a_document() {
    for body in ["Enabled", "  Enabled\n", "enabled", "Suspended", "\u{a0}Enabled"] {
        for document in [&DOCUMENT, &PLAIN] {
            let answer = read(body.as_bytes(), document, XmlLimits::S3, &scalar);
            assert!(
                matches!(answer, Err(BoundRefusal::Document(_) | BoundRefusal::Xml(_))),
                "{body:?}: {answer:?}"
            );
        }
    }
}

/// The same shapes, with an empty body read as no document at all.
static OPTIONAL: Document = Document {
    roots: &["Config"],
    shapes: &SHAPES,
    empty: EmptyBody::Absent,
};

/// Negative — an empty body is missing, refused or absent, as the document says; white space is
/// none of them, and a document that is present is read whatever the empty body would be.
#[test]
fn n_an_empty_body_is_what_the_document_calls_it() {
    assert_eq!(bound(""), Err(BoundRefusal::Missing));
    assert_eq!(read(b"", &PLAIN, XmlLimits::S3, &scalar), Err(BoundRefusal::Document(Reason::Truncated)));
    assert_eq!(read(b"", &OPTIONAL, XmlLimits::S3, &scalar), Err(BoundRefusal::Absent));
    assert_eq!(bound(" \n "), Err(BoundRefusal::Document(Reason::Truncated)));
    assert_eq!(
        read(b" \n ", &OPTIONAL, XmlLimits::S3, &scalar),
        Err(BoundRefusal::Document(Reason::Truncated))
    );
    assert!(read(b"<Config><Status>s</Status></Config>", &OPTIONAL, XmlLimits::S3, &scalar).is_ok());
}

/// Negative — an uncarriable value is reported only once the rest of the document reads: a later
/// refusal wins, as it does on the legacy stack, whose answer the uncarriable one would replace.
#[test]
fn n_an_uncarriable_value_yields_to_a_later_refusal() {
    assert_eq!(
        bound("<Config><Status>wide</Status><Status>x</Status></Config>"),
        Err(BoundRefusal::Document(Reason::Repeated))
    );
    assert_eq!(
        bound("<Config><Status>wide</Status><Rule><Future/></Rule></Config>"),
        Err(BoundRefusal::Document(Reason::UnknownElement))
    );
    assert_eq!(
        bound("<Config><Status>wide</Status><Days>1</Days></Config>"),
        Err(BoundRefusal::Uncarriable)
    );
}

/// Positive — an optional wrapped list's empty wrapper is read as a present empty list, as legacy
/// RustFS reads it, whether it held nothing or only skipped entries: the caller carries a list's
/// presence apart from its entries (rustfs/gateway#1078). No wrapper is no list.
#[test]
fn an_empty_optional_wrapper_is_read_as_a_present_empty_list() {
    for body in [
        "<Config><Status>s</Status><TagSet></TagSet></Config>",
        "<Config><Status>s</Status><TagSet/></Config>",
        "<Config><Status>s</Status><TagSet><Other/></TagSet></Config>",
    ] {
        let tree = bound(body).unwrap_or_else(|refusal| panic!("{body}: {refusal:?}"));
        let wrapper = tree.child("TagSet").unwrap_or_else(|| panic!("{body}: no TagSet"));
        assert!(wrapper.children.is_empty(), "{body}");
    }
    let listed = bound("<Config><Status>s</Status><TagSet><Tag><ID>t</ID></Tag></TagSet></Config>");
    assert!(listed.is_ok_and(|tree| tree.child("TagSet").is_some_and(|wrapper| wrapper.children.len() == 1)));
    assert!(bound("<Config><Status>s</Status></Config>").is_ok_and(|tree| tree.child("TagSet").is_none()));
}
