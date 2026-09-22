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

//! Responsible for: computed Content-MD5 and conflicting wire declarations.
//! NOT responsible for: MD5 primitives, signing, or response matching.
//! Upstream: parsed request specifications. Downstream: the shared wire preparation path.

use super::super::*;

fn request(extra: &str) -> Value {
    crate::toml::parse(&format!(
        "method = \"PUT\"\ntarget = \"/bucket/key\"\ncontent_md5 = \"computed\"\n{extra}"
    ))
    .expect("the synthetic request is valid TOML")
}

#[test]
fn computed_md5_covers_the_final_payload_bytes() {
    let target = InProcess::new(PathBuf::from("."));
    for body in [
        "body = { utf8 = \"abc\" }",
        "body = { hex = \"616263\" }",
        "body = { size = 3, fill = \"616263\" }",
    ] {
        let wire = target.read_wire(&request(body)).expect("the payload is supported");
        assert_eq!(wire.body, b"abc", "{body}");
        assert_eq!(wire.headers, [("content-md5".to_owned(), "kAFQmDzST7DWlj99KOF/cg==".to_owned())]);
    }
    let empty = target.read_wire(&request("")).expect("the empty payload is supported");
    assert_eq!(empty.headers, [("content-md5".to_owned(), "1B2M2Y8AsgTpgAmY7PhCfg==".to_owned())]);
}

#[test]
fn computed_md5_refuses_an_existing_header_without_overwriting_it() {
    let target = InProcess::new(PathBuf::from("."));
    for headers in [
        "headers = { \"content-md5\" = \"literal\" }",
        "headers = { \"Content-MD5\" = [\"literal\"] }",
        "raw_headers = [[\"CONTENT-MD5\", \"literal\"]]",
    ] {
        let error = target
            .read_wire(&request(headers))
            .expect_err("conflicting header declarations must fail");
        assert!(error.to_string().contains("content_md5"), "{error}");
    }
}

#[test]
fn computed_md5_refuses_a_verbatim_head_or_frame_script() {
    let target = InProcess::new(PathBuf::from("."));
    for raw in [
        "raw_head_utf8 = \"PUT /bucket/key HTTP/1.1\\r\\n\\r\\n\"",
        "raw_head_hex = \"505554\"",
        "h2_frames = []",
    ] {
        let error = target
            .read_wire(&request(raw))
            .expect_err("a computed header cannot rewrite raw framing");
        assert!(error.to_string().contains("content_md5"), "{error}");
    }
}

#[test]
fn computed_md5_refuses_unknown_or_mistyped_modes() {
    let target = InProcess::new(PathBuf::from("."));
    for mode in ["\"sha256\"", "false", "3", "{}"] {
        let source = format!("method = \"PUT\"\ntarget = \"/bucket/key\"\ncontent_md5 = {mode}");
        let value = crate::toml::parse(&source).expect("valid TOML");
        let error = target.read_wire(&value).expect_err("an unknown computation must fail closed");
        assert!(error.to_string().contains("content_md5"), "{error}");
    }
}

#[test]
fn computed_md5_covers_concatenated_chunks_without_timing_bytes() {
    let target = InProcess::new(PathBuf::from("."));
    let wire = target
        .read_wire(&request("chunks = [{ utf8 = \"a\", delay_ms = 1 }, { hex = \"6263\", delay_ms = 2 }]"))
        .expect("structured chunks are supported");
    assert_eq!(wire.body, b"abc");
    assert_eq!(wire.headers, [("content-md5".to_owned(), "kAFQmDzST7DWlj99KOF/cg==".to_owned())]);
}

#[test]
fn computed_md5_does_not_interpret_raw_chunk_bytes_as_payload() {
    let target = InProcess::new(PathBuf::from("."));
    for chunks in [
        "chunks = [{ raw_utf8 = \"3\\r\\nabc\\r\\n0\\r\\n\\r\\n\" }]",
        "chunks = [{ raw_hex = \"330d0a6162630d0a300d0a0d0a\" }]",
        "chunks = [{ utf8 = \"abc\" }, { raw_utf8 = \"0\\r\\n\\r\\n\" }]",
    ] {
        let error = target
            .read_wire(&request(chunks))
            .expect_err("raw framing has no unambiguous payload digest");
        assert!(error.to_string().contains("content_md5"), "{error}");
    }
}

#[test]
fn computed_md5_uses_file_contents_instead_of_the_file_name() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance");
    let target = InProcess::new(root);
    let wire = target
        .read_wire(&request("body = { file = \"fixtures/cors/one-hundred-rules.xml\" }"))
        .expect("the corpus fixture exists");
    assert_eq!(wire.body.len(), 13539);
    assert_eq!(wire.headers, [("content-md5".to_owned(), "JYoSwYo6t9w8byT3F3Jgxg==".to_owned())]);
}
