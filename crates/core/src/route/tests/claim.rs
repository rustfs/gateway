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

//! The claim and template rules of the parent module, pinned by unit tests (ADR-0024, ADR-0030,
//! ADR-0036).
//!
//! Responsible for: what a claim covers and overlaps, the dot-segment spellings, what a template
//! matches and extracts, and how two templates overlap and refine each other — the trailing `/`
//! and the catch-all included.
//! NOT responsible for: the claimed table and the dialect rules (`crates/core/tests/dialect_claims*.rs`)
//! or the facade pipeline (`rustfs-gateway`'s tests).
//! Upstream: the parent module. Downstream: nothing; this is a leaf test module.

#![allow(clippy::expect_used, clippy::panic)]

use super::*;

const EVIDENCE: &[&str] = &["https://github.com/rustfs/backlog/issues/1744"];

fn claim(prefix: &'static str) -> PathClaim {
    PathClaim {
        prefix,
        reason: "fixture",
        evidence: EVIDENCE,
    }
}

#[test]
fn a_claim_covers_its_prefix_and_what_continues_it_with_a_separator() {
    let admin = claim("/rustfs/admin");
    for inside in ["/rustfs/admin", "/rustfs/admin/", "/rustfs/admin/v3/info"] {
        assert!(admin.covers(inside), "{inside}");
    }
    for outside in [
        "/rustfs",
        "/rustfs/",
        "/rustfs/adminx",
        "/rustfs/admi",
        "/x/rustfs/admin",
        "rustfs/admin",
    ] {
        assert!(!admin.covers(outside), "{outside}");
    }
}

#[test]
fn nested_and_equal_claims_overlap_and_siblings_do_not() {
    let admin = claim("/rustfs/admin");
    assert!(admin.overlaps(&claim("/rustfs/admin/v3")));
    assert!(claim("/rustfs/admin/v3").overlaps(&admin));
    assert!(admin.overlaps(&admin));
    assert!(!admin.overlaps(&claim("/rustfs/adminx")));
    assert!(!admin.overlaps(&claim("/minio/admin")));
}

#[test]
fn dot_segments_are_recognised_in_every_spelling() {
    for dot in [".", "..", "%2e", "%2E", ".%2e", "%2E%2e"] {
        assert!(is_dot_segment(dot), "{dot}");
    }
    for other in ["...", "a.", ".a", "%2e%2e%2e", "%2f", ""] {
        assert!(!is_dot_segment(other), "{other}");
    }
}

#[test]
fn a_literal_refines_a_parameter_and_not_the_other_way_round() {
    let literal = PathTemplate::parse("/a/b/stats").expect("a template");
    let parameter = PathTemplate::parse("/a/b/{name}").expect("a template");
    assert!(literal.refines(&parameter));
    assert!(!parameter.refines(&literal));
    assert_eq!(literal.overlap_path(&parameter).as_deref(), Some("/a/b/stats"));
    let other = PathTemplate::parse("/a/c/{name}").expect("a template");
    assert_eq!(literal.overlap_path(&other), None);
}

/// Positive — a template written with a trailing `/` ends in an empty literal and matches a
/// request path with that trailing `/` and nothing else (ADR-0030).
#[test]
fn a_trailing_slash_is_an_empty_last_literal_matched_exactly() {
    let heal = PathTemplate::parse("/rustfs/admin/v3/heal/").expect("a template");
    assert_eq!(heal.as_str(), "/rustfs/admin/v3/heal/");
    assert_eq!(heal.parameters().count(), 0);
    assert!(heal.matches("/rustfs/admin/v3/heal/"));
    for other in [
        "/rustfs/admin/v3/heal",
        "/rustfs/admin/v3/heal//",
        "/rustfs/admin/v3/heal/photos",
        "/rustfs/admin/v3/heal/%2f",
        "/rustfs/admin/v3/heal/ ",
    ] {
        assert!(!heal.matches(other), "{other}");
        assert_eq!(heal.extract(other).err(), Some(PathParamError::Mismatch), "{other}");
    }
    assert!(heal.extract("/rustfs/admin/v3/heal/").expect("a match").is_empty());
}

/// Negative — every other empty segment is still refused: two adjacent separators anywhere,
/// a trailing `//`, and a template that is only separators.
#[test]
fn n_an_empty_segment_that_is_not_a_trailing_slash_is_refused() {
    for template in ["/", "//", "/a//", "/a//b", "/a/b//", "//a"] {
        assert_eq!(PathTemplate::parse(template).err(), Some(TemplateRejection::EmptySegment), "{template}");
    }
}

/// Negative — a parameter never matches an empty segment, so a trailing `/` and a parameter
/// in the same position overlap nothing and neither refines the other (ADR-0030).
#[test]
fn n_a_trailing_slash_and_a_parameter_share_no_path() {
    let heal = PathTemplate::parse("/a/heal/").expect("a template");
    let by_bucket = PathTemplate::parse("/a/heal/{bucket}").expect("a template");
    assert_eq!(heal.overlap_path(&by_bucket), None);
    assert_eq!(by_bucket.overlap_path(&heal), None);
    assert!(!heal.refines(&by_bucket));
    assert!(!by_bucket.refines(&heal));
    assert!(!by_bucket.matches("/a/heal/"));
    let same = PathTemplate::parse("/a/heal/").expect("a template");
    assert_eq!(heal.overlap_path(&same).as_deref(), Some("/a/heal/"));
    assert!(heal.refines(&same));
}

// ── the catch-all (ADR-0036) ─────────────────────────────────────────────────────────────────

/// RustFS's heal route: a bound bucket, then everything after it (ADR-0036).
const HEAL: &str = "/a/admin/heal/{bucket}/{*prefix}";

/// Positive — a catch-all takes the rest of the raw path after the separator before it, one byte
/// or more, separators, empty and dot segments included: that is the value, as `matchit`'s
/// catch-all captures it for RustFS's router.
#[test]
fn a_catch_all_matches_the_rest_of_the_path_one_byte_or_more() {
    let heal = PathTemplate::parse(HEAL).expect("a template");
    assert_eq!(heal.as_str(), HEAL);
    assert_eq!(heal.parameters().collect::<Vec<_>>(), ["bucket", "prefix"]);
    assert_eq!(heal.catch_all(), Some("prefix"));
    assert_eq!(PathTemplate::parse("/a/admin/heal/{bucket}").expect("a template").catch_all(), None);
    for (path, rest) in [
        ("/a/admin/heal/b/x", "x"),
        ("/a/admin/heal/b/x/y/z", "x/y/z"),
        ("/a/admin/heal/b/x/", "x/"),
        ("/a/admin/heal/b//", "/"),
        ("/a/admin/heal/b//x", "/x"),
        ("/a/admin/heal/b/x//y", "x//y"),
        ("/a/admin/heal/b/..", ".."),
        ("/a/admin/heal/b/x/../y", "x/../y"),
        ("/a/admin/heal/b/%2e%2e", "%2e%2e"),
        ("/a/admin/heal/b/a%2Fb", "a%2Fb"),
        ("/a/admin/heal/b/a%5Cb\\c", "a%5Cb\\c"),
        ("/a/admin/heal/b/{x}", "{x}"),
    ] {
        assert!(heal.matches(path), "{path}");
        assert_eq!(heal.raw_value(path, "prefix"), Some(rest), "{path}");
        assert_eq!(heal.raw_value(path, "bucket"), Some("b"), "{path}");
    }
}

/// Negative — a catch-all never matches nothing: the path must continue past the separator before
/// it, and every segment before it still follows its own rule.
#[test]
fn n_a_catch_all_never_matches_an_empty_rest_or_a_short_path() {
    let heal = PathTemplate::parse(HEAL).expect("a template");
    for path in [
        "/a/admin/heal/b/",
        "/a/admin/heal/b",
        "/a/admin/heal/",
        "/a/admin/heal",
        "/a/admin/heal//x",
        "/a/admin/heal/%2e/x",
        "/a/admin/heal/..//x",
        "/a/admin/heal/b%2Fc/x",
        "/a/admin/healx/b/x",
        "/a/admin/Heal/b/x",
        "a/admin/heal/b/x",
        "",
    ] {
        assert!(!heal.matches(path), "{path}");
        assert_eq!(heal.extract(path).err(), Some(PathParamError::Mismatch), "{path}");
        assert_eq!(heal.raw_value(path, "prefix"), None, "{path}");
        assert_eq!(heal.raw_value(path, "bucket"), None, "{path}");
    }
}

/// Positive — the value is decoded once, as an object key is: every well-formed escape once, a
/// `%` without two hexadecimal digits kept as it is, and nothing else refused, because the value is
/// data the handler validates as RustFS's does (ADR-0036).
#[test]
fn a_catch_all_value_is_decoded_once_as_an_object_key_is() {
    let heal = PathTemplate::parse(HEAL).expect("a template");
    for (path, value) in [
        ("/a/admin/heal/b/x", "x"),
        ("/a/admin/heal/b/dir/sub/obj.txt", "dir/sub/obj.txt"),
        ("/a/admin/heal/b/x%2Fy/z%20w", "x/y/z w"),
        ("/a/admin/heal/b/%252e%252e", "%2e%2e"),
        ("/a/admin/heal/b/%2e%2e/x", "../x"),
        ("/a/admin/heal/b/100%zz", "100%zz"),
        ("/a/admin/heal/b/a%4", "a%4"),
        ("/a/admin/heal/b/%", "%"),
        ("/a/admin/heal/b/%%41", "%A"),
        ("/a/admin/heal/b//", "/"),
        ("/a/admin/heal/b/x%5Cy", "x\\y"),
        ("/a/admin/heal/b/%E4%BD%A0%E5%A5%BD", "\u{4f60}\u{597d}"),
        ("/a/admin/heal/b/tab%09and%01", "tab\tand\u{1}"),
    ] {
        let params = heal.extract(path).expect(path);
        assert_eq!(params.get("prefix"), Some(value), "{path}");
        assert_eq!(params.get("bucket"), Some("b"), "{path}");
        assert_eq!(params.iter().map(|(name, _)| name).collect::<Vec<_>>(), ["bucket", "prefix"], "{path}");
    }
}

/// Negative — a value that does not decode to UTF-8 is refused, naming the catch-all and never
/// echoing the value; the parameters before it keep their own refusals.
#[test]
fn n_a_catch_all_value_that_is_not_utf8_is_refused_without_echoing_it() {
    let heal = PathTemplate::parse(HEAL).expect("a template");
    for raw in ["%ff", "x/%C3", "%C3%28", "ok/%ED%A0%80"] {
        let path = format!("/a/admin/heal/b/{raw}");
        let error = heal.extract(&path).expect_err(raw);
        assert!(matches!(error, PathParamError::Invalid { name: "prefix", .. }), "{raw}: {error:?}");
        assert!(!error.to_string().contains(raw), "the refusal echoes the value: {error}");
    }
    let error = heal
        .extract("/a/admin/heal/b%00/x")
        .expect_err("a control byte in the bucket");
    assert!(matches!(error, PathParamError::Invalid { name: "bucket", .. }), "{error:?}");
}

/// Negative — a catch-all is the template's last segment, spelled `{*name}` with a lowercase
/// name, and its name is not repeated.
#[test]
fn n_a_misplaced_or_misspelled_catch_all_is_refused() {
    for (template, rejection) in [
        ("/a/admin/{*rest}/x", TemplateRejection::CatchAllNotLast),
        ("/a/admin/{*rest}/", TemplateRejection::CatchAllNotLast),
        ("/a/admin/{*rest}/{*more}", TemplateRejection::CatchAllNotLast),
        ("/a/admin/{*rest}/{id}", TemplateRejection::CatchAllNotLast),
        ("/a/admin/{*Rest}", TemplateRejection::MalformedParameter),
        ("/a/admin/{*}", TemplateRejection::MalformedParameter),
        ("/a/admin/{**rest}", TemplateRejection::MalformedParameter),
        ("/a/admin/{* rest}", TemplateRejection::MalformedParameter),
        ("/a/admin/x{*rest}", TemplateRejection::MalformedParameter),
        ("/a/admin/{*rest}.zip", TemplateRejection::MalformedParameter),
        ("/a/admin/{rest}/{*rest}", TemplateRejection::DuplicateParameter),
    ] {
        assert_eq!(PathTemplate::parse(template).err(), Some(rejection), "{template}");
    }
}

/// Positive and negative — a catch-all overlaps a template whose extra segments it can take, and is
/// refined by one whose every path it takes; it refines no fixed-length template, and every
/// overlap path it names is matched by both templates.
#[test]
fn a_catch_all_overlaps_and_refines_by_what_it_can_match() {
    let parse = |text: &'static str| PathTemplate::parse(text).expect(text);
    let rest = parse("/a/b/{*r}");
    for (other, overlap, other_refines_rest, rest_refines_other) in [
        ("/a/b/c", Some("/a/b/c"), true, false),
        ("/a/b/{x}", Some("/a/b/p"), true, false),
        ("/a/b/c/d/e", Some("/a/b/c/d/e"), true, false),
        ("/a/b/c/", Some("/a/b/c/"), true, false),
        ("/a/{x}/{y}", Some("/a/b/p"), false, false),
        ("/a/{x}/{*s}", Some("/a/b/p"), false, true),
        ("/a/b/c/{*s}", Some("/a/b/c/p"), true, false),
        ("/a/{*s}", Some("/a/b/p"), false, true),
        ("/a/b/{*s}", Some("/a/b/p"), true, true),
        ("/a/b", None, false, false),
        ("/a/b/", None, false, false),
        ("/a/c/{*s}", None, false, false),
        ("/a/c/d", None, false, false),
        ("/x/b/c", None, false, false),
        ("/a", None, false, false),
    ] {
        let other_template = parse(other);
        assert_eq!(rest.overlap_path(&other_template).as_deref(), overlap, "{other}");
        assert_eq!(other_template.overlap_path(&rest).as_deref(), overlap, "{other}, reversed");
        if let Some(path) = overlap {
            assert!(rest.matches(path) && other_template.matches(path), "{other}: {path}");
        }
        assert_eq!(other_template.refines(&rest), other_refines_rest, "{other} refines the catch-all");
        assert_eq!(rest.refines(&other_template), rest_refines_other, "the catch-all refines {other}");
    }
}

/// Negative — the heal routes as RustFS registers them share no path: the trailing `/`, the
/// bucket alone, and the bucket with a catch-all each take paths the others never do.
#[test]
fn n_the_heal_routes_share_no_path() {
    let parse = |text: &'static str| PathTemplate::parse(text).expect(text);
    let routes = [parse("/a/admin/heal/"), parse("/a/admin/heal/{bucket}"), parse(HEAL)];
    for (index, first) in routes.iter().enumerate() {
        for second in routes.iter().skip(index + 1) {
            assert_eq!(first.overlap_path(second), None, "{} {}", first.as_str(), second.as_str());
            assert_eq!(second.overlap_path(first), None, "{} {}", second.as_str(), first.as_str());
            assert!(!first.refines(second) && !second.refines(first), "{} {}", first.as_str(), second.as_str());
        }
    }
}
