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

//! The page-size ceiling a view applies for the RustFS profile, seen through the generated
//! listing decoders.
//!
//! Responsible for: an oversized `max-keys` decoding as the ceiling on every listing that reads
//! it, and everything else — absent, in range, negative, unparseable, another parameter, a view
//! without a ceiling — decoding exactly as it did before.
//! NOT responsible for: which operations an assembly clamps (`rustfs-gateway`'s builder) or the
//! default refusal, which `super`'s max-keys tests pin.
//! Upstream: `crate::codec::view::PageSizeCeiling`. Downstream: nothing.

use super::*;
use crate::codec::PageSizeCeiling;

const MAX_KEYS: PageSizeCeiling = PageSizeCeiling::new("max-keys", 1000);

fn list_v2(query: &str, ceiling: Option<PageSizeCeiling>) -> Result<Option<i32>, crate::codec::CodecError> {
    let request = accepted("GET", &format!("/photos?list-type=2&{query}"), &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let view = match ceiling {
        Some(ceiling) => view.with_page_size_ceiling(ceiling),
        None => view,
    };
    dto::ListObjectsV2::decode(&view, RequestBody::None).map(|input| input.max_keys)
}

#[test]
fn an_oversized_max_keys_decodes_as_the_ceiling() {
    for raw in ["1001", "5000", "100000", "2147483647", "%205000"] {
        assert_eq!(
            list_v2(&format!("max-keys={raw}"), Some(MAX_KEYS)).ok(),
            Some(Some(1000)),
            "max-keys={raw}"
        );
    }
}

#[test]
fn n_an_in_range_or_absent_max_keys_is_not_touched() {
    for (raw, expected) in [("0", 0), ("1", 1), ("999", 999), ("1000", 1000)] {
        assert_eq!(
            list_v2(&format!("max-keys={raw}"), Some(MAX_KEYS)).ok(),
            Some(Some(expected)),
            "max-keys={raw}"
        );
    }
    assert_eq!(list_v2("prefix=a", Some(MAX_KEYS)).ok(), Some(Some(1000)), "the model default");
}

#[test]
fn n_a_negative_max_keys_is_still_refused_under_the_ceiling() {
    for raw in ["-1", "-2147483648"] {
        let error = list_v2(&format!("max-keys={raw}"), Some(MAX_KEYS)).expect_err("a ceiling is not a floor");
        assert_eq!(error.code().as_str(), "InvalidArgument", "max-keys={raw}");
        assert_eq!(error.member(), Some("MaxKeys"), "max-keys={raw}");
    }
}

#[test]
fn n_an_unparseable_max_keys_is_still_refused_under_the_ceiling() {
    for raw in ["abc", "1e4", "", "2147483648", "99999999999", "5000abc"] {
        let error = list_v2(&format!("max-keys={raw}"), Some(MAX_KEYS)).expect_err("only an integer is clamped");
        assert_eq!(error.code().as_str(), "InvalidArgument", "max-keys={raw}");
        assert_eq!(error.member(), Some("MaxKeys"), "max-keys={raw}");
    }
}

#[test]
fn n_without_the_ceiling_an_oversized_max_keys_is_still_refused() {
    let error = list_v2("max-keys=1001", None).expect_err("the default view keeps the modelled range");
    assert_eq!(error.code().as_str(), "InvalidArgument");
    assert_eq!(error.member(), Some("MaxKeys"));
}

#[test]
fn the_unbounded_listings_read_the_ceiling_too() {
    let request = accepted("GET", "/photos?max-keys=5000", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket)
        .expect("view")
        .with_page_size_ceiling(MAX_KEYS);
    let input = dto::ListObjects::decode(&view, RequestBody::None).expect("ListObjects has no modelled ceiling");
    assert_eq!(input.max_keys, Some(1000));

    let request = accepted("GET", "/photos?versions&max-keys=5000", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket)
        .expect("view")
        .with_page_size_ceiling(MAX_KEYS);
    let input = dto::ListObjectVersions::decode(&view, RequestBody::None).expect("ListObjectVersions has no modelled ceiling");
    assert_eq!(input.max_keys, Some(1000));
}

#[test]
fn n_without_the_ceiling_the_unbounded_listings_read_the_wire_value() {
    let request = accepted("GET", "/photos?max-keys=5000", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let input = dto::ListObjects::decode(&view, RequestBody::None).expect("ListObjects has no modelled ceiling");
    assert_eq!(input.max_keys, Some(5000));
}

#[test]
fn n_the_ceiling_governs_only_its_own_parameter() {
    let request = accepted("GET", "/photos?uploads&max-uploads=5000&prefix=5000", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket)
        .expect("view")
        .with_page_size_ceiling(MAX_KEYS);
    let input = dto::ListMultipartUploads::decode(&view, RequestBody::None).expect("decodes");
    assert_eq!(input.max_uploads, Some(5000), "max-uploads is not max-keys");
    assert_eq!(input.prefix.as_deref(), Some("5000"), "another parameter reads as sent");

    let request = accepted("GET", "/photos/key?uploadId=u1&max-parts=5000", &[]);
    let view = MetaView::of(&request, TargetKind::Object)
        .expect("view")
        .with_page_size_ceiling(MAX_KEYS);
    let input = dto::ListParts::decode(&view, RequestBody::None).expect("decodes");
    assert_eq!(input.max_parts, Some(5000), "max-parts is not max-keys");
}
