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

//! Reader validation tests for bare `xmlns`, undeclared-prefix attributes, and outside-root events.
//!
//! Responsible for: proving that `crate::read` validates bare `xmlns` values and undeclared-prefix
//! attribute values before ignoring/dropping them, and refuses non-whitespace text, CDATA, and
//! general references outside the root element while still admitting XML 1.0 prolog/epilog
//! whitespace.
//! NOT responsible for: bound-reader (`crate::bound`) parity or XML limit ceilings (`tests.rs`).
//! Upstream: `crate::parse`, `crate::XmlWriter::append_fragment`.
//! Downstream: Cargo's unit test harness.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use crate::{XmlError, XmlLimits, XmlWriter, parse, parse_legacy_persistence_with_limits};

/// Negative — bare `xmlns="..."` attributes must be validated for forbidden characters and
/// unsupported entities even though they are not surfaced as data attributes.
#[test]
fn n_refuses_invalid_bare_xmlns_values() {
    for body in [
        "<Root xmlns=\"&#x1;\"/>",
        "<Root xmlns=\"&#x1;\"></Root>",
        "<Root xmlns=\"urn:\u{1}x\"/>",
    ] {
        assert_eq!(parse(body.as_bytes()), Err(XmlError::ForbiddenCharacter), "{body:?}");
    }
    for body in ["<Root xmlns=\"&bogus;\"/>", "<Root xmlns=\"&bogus;\"></Root>"] {
        assert_eq!(parse(body.as_bytes()), Err(XmlError::UnsupportedEntity), "{body:?}");
    }
}

/// Negative — attributes carrying an undeclared prefix must have their values validated before
/// they are dropped.
#[test]
fn n_refuses_invalid_undeclared_prefix_attribute_values() {
    for body in [
        "<Root u:a=\"&#x1;\"/>",
        "<Root u:a=\"&#x1;\"></Root>",
        "<Root u:a=\"v\u{1}\"/>",
    ] {
        assert_eq!(parse(body.as_bytes()), Err(XmlError::ForbiddenCharacter), "{body:?}");
    }
    for body in ["<Root u:a=\"&bogus;\"/>", "<Root u:a=\"&bogus;\"></Root>"] {
        assert_eq!(parse(body.as_bytes()), Err(XmlError::UnsupportedEntity), "{body:?}");
    }
}

/// Negative — non-whitespace character data outside the root element is not well-formed XML 1.0
/// and must be refused (including non-ASCII whitespace outside XML 1.0 `S` and control chars).
#[test]
fn n_refuses_non_whitespace_text_outside_root() {
    for body in [
        "junk<Root/>",
        "<Root/>junk",
        "<?xml version=\"1.0\"?>junk<Root/>",
        "\u{00a0}<Root/>",
        "\u{1}<Root/>",
        "\u{feff}\u{feff}<Root/>",
        "<Root/>\u{feff}",
        "junk",
    ] {
        assert_eq!(parse(body.as_bytes()), Err(XmlError::Malformed), "{body:?}");
    }
}

/// Negative — CDATA sections outside the root element are illegal in XML 1.0 even when their
/// contents are whitespace.
#[test]
fn n_refuses_cdata_outside_root() {
    for body in ["<![CDATA[x]]><Root/>", "<Root/><![CDATA[x]]>", "<![CDATA[ ]]><Root/>"] {
        assert_eq!(parse(body.as_bytes()), Err(XmlError::Malformed), "{body:?}");
    }
}

/// Negative — entity and character references outside the root element are illegal in XML 1.0,
/// whether predefined, numeric, or custom.
#[test]
fn n_refuses_general_references_outside_root() {
    for body in [
        "<Root/>&xxe;",
        "&xxe;<Root/>",
        "&amp;<Root/>",
        "<Root/>&#x20;",
        "&#x1;<Root/>",
    ] {
        assert_eq!(parse(body.as_bytes()), Err(XmlError::Malformed), "{body:?}");
    }
}

/// Negative — `XmlWriter::append_fragment` rejects fragments carrying outside-root text, CDATA,
/// or references without mutating the parent writer.
#[test]
fn n_append_fragment_refuses_outside_root_content() {
    for fragment in ["junk<Child/>", "<Child/>&xxe;", "<![CDATA[x]]><Child/>"] {
        let mut writer = XmlWriter::fragment();
        writer.open("Root", None);
        let before = writer.len();
        assert_eq!(writer.append_fragment(fragment), Err(XmlError::Malformed), "{fragment:?}");
        assert_eq!(writer.len(), before, "{fragment:?}");
    }
}

/// Positive — XML 1.0 whitespace (`S`), declarations, comments, valid bare `xmlns`, and valid
/// undeclared-prefix attributes continue to parse cleanly, and whitespace-only bodies remain
/// `XmlError::Empty`.
#[test]
fn admits_prolog_epilog_whitespace_and_valid_default_or_undeclared_attributes() {
    let body = " \t\r\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<!-- ok -->\n \
                <Root xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\" u:ignored=\"ok&amp;fine\">hi</Root> \t\r\n";
    let root = parse(body.as_bytes()).expect("well-formed XML with prolog/epilog whitespace must parse");
    assert_eq!(root.name, "Root");
    assert_eq!(root.text, "hi");
    assert!(root.attributes.is_empty());
    assert_eq!(parse(b" \t\r\n"), Err(XmlError::Empty));

    // One leading UTF-8 BOM is valid XML 1.0 §4.3.3 before either the root or the XML declaration.
    let bom_root = parse("\u{feff}<Root>ok</Root>".as_bytes()).expect("single leading UTF-8 BOM");
    assert_eq!((bom_root.name.as_str(), bom_root.text.as_str()), ("Root", "ok"));
    let bom_decl = parse("\u{feff}<?xml version=\"1.0\"?><Root/>".as_bytes()).expect("leading BOM before declaration");
    assert_eq!(bom_decl.name, "Root");
}

/// Negative & positive — legacy persistence parsing retains historical root-trailing text
/// tolerance (P9 D4NotStricter) while still refusing outside-root CDATA, outside-root references,
/// and invalid bare `xmlns` or undeclared-prefix attributes.
#[test]
fn n_legacy_persistence_keeps_trailing_text_but_refuses_invalid_attributes_and_non_text_outside_root() {
    let trailing = parse_legacy_persistence_with_limits(b"<Root/>trailing", XmlLimits::S3)
        .expect("legacy persistence keeps old-readable trailing text");
    assert_eq!(trailing.name, "Root");

    for body in ["<![CDATA[x]]><Root/>", "<Root/>&xxe;"] {
        assert_eq!(
            parse_legacy_persistence_with_limits(body.as_bytes(), XmlLimits::S3),
            Err(XmlError::Malformed),
            "{body:?}"
        );
    }
    for body in ["<Root xmlns=\"&#x1;\"/>", "<Root u:a=\"&#x1;\"/>"] {
        assert_eq!(
            parse_legacy_persistence_with_limits(body.as_bytes(), XmlLimits::S3),
            Err(XmlError::ForbiddenCharacter),
            "{body:?}"
        );
    }
    for body in ["<Root xmlns=\"&bogus;\"/>", "<Root u:a=\"&bogus;\"/>"] {
        assert_eq!(
            parse_legacy_persistence_with_limits(body.as_bytes(), XmlLimits::S3),
            Err(XmlError::UnsupportedEntity),
            "{body:?}"
        );
    }
}

#[test]
fn n_root_declares_namespace_inspects_only_root_start_tag() {
    use crate::root_declares_namespace;

    // Negative false-positive traps: xmlns= in text, SQL expression, comment, CDATA, or child element.
    for clean in [
        "<SelectObjectContentRequest><Expression>SELECT * FROM s3object WHERE a = 'xmlns='</Expression></SelectObjectContentRequest>",
        "<!-- xmlns=\"http://example.com\" --><RestoreRequest><Days>1</Days></RestoreRequest>",
        "<RestoreRequest><Description><![CDATA[xmlns:s3=\"http://s3.amazonaws.com/doc/2006-03-01/\"]]></Description></RestoreRequest>",
        "<RestoreRequest><Child xmlns=\"http://example.com\"/></RestoreRequest>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n  <RestoreRequest/>",
        "",
    ] {
        assert_eq!(
            root_declares_namespace(clean.as_bytes(), XmlLimits::S3),
            Ok(false),
            "must not report root namespace for {clean:?}"
        );
    }

    // Positive root namespace declarations, including whitespace around `=` and prefixed roots.
    for qualified in [
        "<RestoreRequest xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>",
        "<RestoreRequest xmlns = \"http://s3.amazonaws.com/doc/2006-03-01/\"><Days>1</Days></RestoreRequest>",
        "<RestoreRequest xmlns:s3=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>",
        "<s3:RestoreRequest xmlns:s3=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>",
        "<s3:RestoreRequest/>",
    ] {
        assert_eq!(
            root_declares_namespace(qualified.as_bytes(), XmlLimits::S3),
            Ok(true),
            "must detect root namespace for {qualified:?}"
        );
    }

    // Malformed, DOCTYPE, non-UTF-8, and over-limit inputs fail closed.
    assert_eq!(
        root_declares_namespace(b"<!DOCTYPE x><RestoreRequest/>", XmlLimits::S3),
        Err(XmlError::DocTypeDeclaration)
    );
    assert_eq!(root_declares_namespace(&[0xFF, 0xFE], XmlLimits::S3), Err(XmlError::NotUtf8));
    assert_eq!(
        root_declares_namespace(b"<RestoreRequest attr=\"unclosed>", XmlLimits::S3),
        Err(XmlError::Malformed)
    );
    let tiny = XmlLimits::new(8, 4, 4, 4, 4).expect("limits");
    assert_eq!(root_declares_namespace(b"<RestoreRequest/>", tiny), Err(XmlError::BodyTooLarge));
}
