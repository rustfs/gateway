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

//! Responsible for: schema-version ownership of computed Content-MD5.
//! NOT responsible for: digest calculation or transport execution.
//! Upstream: the frozen case schema. Downstream: request validation.

use super::*;

fn case(version: i64, request: &str) -> String {
    format!(
        r#"[case]
id = "c-test-0001"
schema_version = {version}
rationale = "A computed digest must be a versioned request instruction with no ambiguous wire representation."
polarity = "negative"
quirks = []
evidence = [{{ url = "https://github.com/rustfs/gateway/issues/436", summary = "A literal digest can become stale after the authored request body changes." }}]
[request]
{request}
[expect]
kind = "response"
status = 200
"#
    )
}

fn violations(source: &str) -> Vec<Violation> {
    Schema::compile(include_str!("../../../../conformance/case.schema.json"))
        .expect("the frozen schema compiles")
        .validate(&crate::toml::parse(source).expect("the synthetic case is valid TOML"))
}

const COMPUTED: &str = "method = \"PUT\"\ntarget = \"/bucket/key\"\ncontent_md5 = \"computed\"";

#[test]
fn version_three_accepts_computed_md5() {
    assert!(violations(&case(3, COMPUTED)).is_empty());
}

#[test]
fn earlier_versions_cannot_claim_computed_md5() {
    for version in [1, 2] {
        let errors = violations(&case(version, COMPUTED));
        assert!(errors.iter().any(|error| error.pointer.ends_with("content_md5")), "{errors:?}");
    }
}

#[test]
fn unknown_digest_modes_are_rejected_by_the_field_contract() {
    for value in ["\"sha256\"", "false", "1", "{}"] {
        let request = COMPUTED.replace("\"computed\"", value);
        let errors = violations(&case(3, &request));
        assert!(errors.iter().any(|error| error.pointer.ends_with("content_md5")), "{errors:?}");
    }
}

#[test]
fn computed_md5_cannot_rewrite_a_raw_head() {
    for raw in ["raw_head_utf8 = \"PUT /bucket/key HTTP/1.1\"", "raw_head_hex = \"505554\""] {
        let source = case(3, &format!("{raw}\ncontent_md5 = \"computed\""));
        let errors = violations(&source);
        assert!(errors.iter().any(|error| error.pointer == "/request/content_md5"), "{errors:?}");
    }
}

#[test]
fn computed_md5_version_applies_to_every_exchange() {
    for version in [1, 2, 3] {
        let single = case(version, COMPUTED);
        let exchange = single
            .replace("[request]", "[[exchanges]]\n[exchanges.request]")
            .replace("[expect]", "[exchanges.expect]");
        let errors = violations(&exchange);
        if version == 3 {
            assert!(errors.is_empty(), "{errors:?}");
        } else {
            assert!(
                errors.iter().any(|error| error.pointer == "/exchanges/0/request/content_md5"),
                "{errors:?}"
            );
        }
    }
}

#[test]
fn computed_md5_rejects_raw_http2_frames_including_an_empty_list() {
    for frames in ["[]", "[{ kind = \"data\", stream_id = 1, payload_hex = \"00\" }]"] {
        let errors = violations(&case(3, &format!("{COMPUTED}\nh2_frames = {frames}")));
        assert!(errors.iter().any(|error| error.pointer == "/request/content_md5"), "{errors:?}");
    }
}

#[test]
fn version_three_retains_concurrent_exchange_support() {
    let source = case(3, COMPUTED)
        .replace("[request]", "[connection]\nconcurrent = true\n[[exchanges]]\n[exchanges.request]")
        .replace("[expect]", "[exchanges.expect]");
    let errors = violations(&source);
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn computed_md5_rejects_raw_chunk_instructions_only() {
    for raw in ["raw_utf8 = \"abc\"", "raw_hex = \"616263\""] {
        let errors = violations(&case(3, &format!("{COMPUTED}\nchunks = [{{ {raw} }}]")));
        assert!(
            errors.iter().any(|error| error.pointer.starts_with("/request/chunks/0/raw_")),
            "{errors:?}"
        );
    }
    let errors = violations(&case(3, &format!("{COMPUTED}\nchunks = [{{ utf8 = \"abc\" }}]")));
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn raw_chunks_remain_valid_without_a_computed_digest() {
    for raw in ["raw_utf8 = \"abc\"", "raw_hex = \"616263\""] {
        let request = format!("method = \"PUT\"\ntarget = \"/bucket/key\"\nchunks = [{{ {raw} }}]");
        let errors = violations(&case(3, &request));
        assert!(errors.is_empty(), "{errors:?}");
    }
}
