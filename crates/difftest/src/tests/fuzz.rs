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

//! The stable replay of the two fuzz properties, and the input format they share.
//!
//! Responsible for: every committed `decode_diff` seed passing the decode property; a fixed-seed
//! sampler of mutated seeds and of encode inputs passing both properties on stable (so the
//! properties run in CI, where the nightly fuzzer does not); the reader's refusals and changes;
//! and each property failing on an injected gateway defect.
//! NOT responsible for: finding new inputs (the nightly fuzzer), or the properties themselves.
//! Upstream: `fuzz.rs`, `fuzz/seeds/decode_diff/`. Downstream: none.

use std::path::PathBuf;

use crate::decode::{Differ, Fault, Item};
use crate::fuzz::{check_decode, check_encode, encode_differences, outputs_of, render, request_of, route_differences};
use crate::fuzz_case::draft_with;
use crate::{OracleOutput, RawRequest};

fn seeds() -> Vec<(String, Vec<u8>)> {
    let dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fuzz/seeds/decode_diff"));
    let mut seeds: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
        .map(|entry| {
            let path = entry.expect("a seed entry").path();
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            (name, std::fs::read(&path).expect("a readable seed"))
        })
        .collect();
    seeds.sort();
    seeds
}

/// A small deterministic generator: the same inputs on every run and every host.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound.max(1)).unwrap_or(1)).unwrap_or(0)
    }
}

/// What a fuzzer splices in: the subresources and headers that decide a route.
const TOKENS: [&str; 16] = [
    "?uploads",
    "&uploadId=u",
    "?versions",
    "?versioning",
    "?location",
    "?list-type=2",
    "?delete",
    "&partNumber=1",
    "?tagging",
    "?acl",
    "?attributes",
    "\nx-amz-copy-source: /bkt/src",
    "\nrange: bytes=0-1",
    "/",
    "%2F",
    "?x-id=ListParts",
];

fn mutate(seed: &[u8], random: &mut XorShift) -> Vec<u8> {
    let mut input = seed.to_vec();
    let line_end = input.iter().position(|byte| *byte == b'\n').unwrap_or(input.len());
    for _ in 0..=random.below(3) {
        match random.below(3) {
            0 => {
                let token = TOKENS[random.below(TOKENS.len())].as_bytes();
                let at = random.below(line_end + 1).min(input.len());
                input.splice(at..at, token.iter().copied());
            }
            1 if !input.is_empty() => {
                let at = random.below(input.len());
                input[at] = u8::try_from(random.below(256)).unwrap_or(b'x');
            }
            _ if !input.is_empty() => {
                let at = random.below(input.len());
                input.remove(at);
            }
            _ => {}
        }
    }
    input
}

/// Positive — every committed seed is a request, and passes the decode property.
#[test]
fn every_committed_seed_passes_the_decode_property() {
    let seeds = seeds();
    assert!(seeds.len() > 100, "the seeds are the built-in matrix; {} found", seeds.len());
    for (name, bytes) in &seeds {
        assert!(request_of(bytes).is_some(), "{name} is not a request");
        check_decode(bytes).unwrap_or_else(|report| panic!("{name}: {report}"));
    }
}

/// Positive — a fixed sample of mutated seeds passes the decode property on stable: the fuzzer's
/// search, a few hundred steps of it, in every CI run.
#[test]
fn a_fixed_sample_of_mutated_seeds_passes_the_decode_property() {
    let seeds = seeds();
    let mut random = XorShift(0x9e37_79b9_7f4a_7c15);
    for step in 0..400 {
        let (name, seed) = &seeds[random.below(seeds.len())];
        let input = mutate(seed, &mut random);
        check_decode(&input)
            .unwrap_or_else(|report| panic!("step {step} from {name}: {report}\n{}", String::from_utf8_lossy(&input)));
    }
}

/// Positive — a fixed sample of encode inputs passes the encode property on stable.
#[test]
fn a_fixed_sample_of_encode_inputs_passes_the_encode_property() {
    let mut random = XorShift(0x2545_f491_4f6c_dd1d);
    let alphabet: Vec<char> = "abcXYZ019/._-~ %+&<>\"'=?#\té€".chars().collect();
    let differ = Differ::new().expect("both stacks build");
    let mut heads_with_metadata = 0;
    for step in 0..60 {
        let fields: Vec<String> = (0..6)
            .map(|_| {
                (0..random.below(14))
                    .map(|_| alphabet[random.below(alphabet.len())])
                    .collect()
            })
            .collect();
        let input = fields.join("\0").into_bytes();
        check_encode(&input).unwrap_or_else(|report| panic!("step {step} {fields:?}: {report}"));
        let head = outputs_of(&input).remove(1);
        let OracleOutput::HeadObject(output) = (head.output)() else {
            panic!("the second sample is a head answer");
        };
        let compared = differ.encode(&head).expect("the harness runs").status.s3s != 500;
        if output.metadata.is_some() && compared {
            heads_with_metadata += 1;
        }
    }
    assert!(
        heads_with_metadata >= 30,
        "only {heads_with_metadata} of 60 head samples compared a metadata header"
    );
}

/// Negative — the reader refuses what is not a request both stacks can be handed.
#[test]
fn the_reader_refuses_what_is_not_a_request() {
    for input in [
        &b""[..],
        b"GET",
        b"GET bkt/k\n\n",
        b"G(T /bkt/k\n\n",
        b"GET /bkt/k\nno colon here\n\n",
        b"GET /bkt/k\nbad name: v\n\n",
        b"GET /bkt/k\nx: \x7f\n\n",
        b"PUT /bkt/k\nx-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD\n\nbody",
        b"GET /bkt/k\x7f\n\n",
        b"PUT /bkt/k?x-id=PutO#&c\x18\n\n",
        b"GET /bkt%2Fk\n\n",
        b"GET /bkt%2fk?list-type=2\n\n",
    ] {
        assert_eq!(request_of(input), None, "{:?}", String::from_utf8_lossy(input));
    }
}

/// Negative — framing is the transport's and the hint is a known class: the reader drops both and
/// says so by what it sends; an SSE-C request is sent as over TLS.
#[test]
fn the_reader_owns_framing_and_drops_the_operation_hint() {
    let request =
        request_of(b"PUT /bkt/k?x-id=CopyObject&tagging\r\ncontent-length: 99\r\ntransfer-encoding: chunked\r\n\r\nhello")
            .expect("a request");
    assert_eq!(request.target, "/bkt/k?tagging");
    assert_eq!(request.headers, vec![("content-length".to_owned(), b"5".to_vec())]);
    assert_eq!(request.body.concat(), b"hello");
    assert!(!request.secure);
    let bare = request_of(b"POST /bkt/k?uploads\n\n").expect("a request");
    assert_eq!(bare.headers, vec![("content-length".to_owned(), b"0".to_vec())]);
    let get = request_of(b"GET /bkt/k?x-id=GetObject\n\n").expect("a request");
    assert_eq!((get.target.as_str(), get.headers.len()), ("/bkt/k", 0));
    assert!(
        request_of(b"GET /bkt/a%2Fb\n\n").is_some(),
        "an escaped slash inside a key is data both stacks agree on"
    );
    // rustfs/gateway#1013 is fixed: a date that is not ASCII is compared like any other value.
    let reproducer = request_of(b"GET /bkt/k?response-expires=Thu%99%matchL0A00%matchL\n\n").expect("a request");
    check_decode(&render(&reproducer)).expect("both stacks refuse or read it without a misroute");
    let sse = request_of(b"GET /bkt/k\nx-amz-server-side-encryption-customer-algorithm: AES256\n\n").expect("a request");
    assert!(sse.secure);
}

/// Positive — a request written and read back is the request, framing aside.
#[test]
fn a_rendered_request_reads_back() {
    let request = RawRequest::put("/bkt/k?tagging", b"<Tagging/>").header("content-type", "application/xml");
    let read = request_of(&render(&request)).expect("a request");
    assert_eq!(read.method, request.method);
    assert_eq!(read.target, request.target);
    assert_eq!(read.body.concat(), request.body.concat());
    let mut expected = request.headers.clone();
    expected.sort();
    let mut headers = read.headers;
    headers.sort();
    assert_eq!(headers, expected);
}

/// Negative — a gateway that misroutes object paths fails the decode property with a route
/// difference.
#[test]
fn a_misrouting_gateway_fails_the_decode_property() {
    let broken = Differ::with_fault(Fault::GatewayMisroutesObjects).expect("both stacks build");
    let request = request_of(b"GET /bkt/key\n\n").expect("a request");
    let differences = route_differences(&broken, &request).expect("the harness runs");
    assert!(differences.iter().any(|finding| finding.item == Item::Route), "{differences:?}");
    let healthy = Differ::new().expect("both stacks build");
    assert!(route_differences(&healthy, &request).expect("the harness runs").is_empty());
}

/// Negative — a gateway that reorders XML children fails the encode property.
#[test]
fn a_reordering_gateway_fails_the_encode_property() {
    let broken = Differ::with_fault(Fault::GatewayXmlElementsReordered).expect("both stacks build");
    let listing = outputs_of(b"p/\x00/\x00tok\x00p/0\x00p/a\x00p/b").remove(0);
    assert!(!encode_differences(&broken, &listing).expect("the harness runs").is_empty());
    let healthy = Differ::new().expect("both stacks build");
    assert!(encode_differences(&healthy, &listing).expect("the harness runs").is_empty());
    assert_eq!(
        healthy.encode(&listing).expect("the harness runs").unconvertible,
        None,
        "the fuzzed listing converts"
    );
}

/// Negative (a-df-0020) — a finding becomes a draft that names itself a draft: the gateway's
/// refusal as the expectation, the request as read, `FUZZ-DRAFT` where a person must write, and
/// the next free number beside the drafts already there.
#[test]
fn a_reproducing_finding_becomes_a_numbered_draft() {
    let dir = std::env::temp_dir().join(format!("difftest-drafts-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a draft directory");
    std::fs::write(dir.join("c-fuzz-0007.toml"), "").expect("an earlier draft");
    let broken = Differ::with_fault(Fault::GatewayMisroutesObjects).expect("both stacks build");
    let (path, text) = draft_with(&broken, b"GET /bkt/key\nx-amz-request-payer: requester\n\n", &dir).expect("a draft");
    assert_eq!(path, dir.join("c-fuzz-0008.toml"));
    let parsed: toml::Table = toml::from_str(&text).unwrap_or_else(|error| panic!("the draft is TOML: {error}\n{text}"));
    assert!(parsed.contains_key("case") && parsed.contains_key("request") && parsed.contains_key("expect"));
    for expected in [
        "id = \"c-fuzz-0008\"",
        "title = \"FUZZ-DRAFT: GET /bkt/key reaches ListObjects on the gateway and GetObject on s3s\"",
        "rationale = \"FUZZ-DRAFT:",
        "summary = \"FUZZ-DRAFT:",
        "kind = \"observed\"",
        "target = \"/bkt/key\"",
        "[\"x-amz-request-payer\", \"requester\"]",
        "status = 400",
        "code = \"InvalidBucketName\"",
        "operation = \"ListObjects\"",
    ] {
        assert!(text.contains(expected), "missing {expected} in\n{text}");
    }
}

/// Negative — a finding whose text echoes control characters still makes a draft that is TOML,
/// and a request compared as over TLS is refused rather than drafted for plaintext.
#[test]
fn a_draft_escapes_what_the_stacks_echo_and_refuses_tls_requests() {
    let dir = std::env::temp_dir().join(format!("difftest-escaped-drafts-{}", std::process::id()));
    let broken = Differ::with_fault(Fault::GatewayMisroutesObjects).expect("both stacks build");
    let (_, text) = draft_with(&broken, b"GET /bkt/key\nx-trace: a\tb\\\"c\n\n", &dir).expect("a draft");
    let parsed: toml::Table = toml::from_str(&text).unwrap_or_else(|error| panic!("the draft is TOML: {error}\n{text}"));
    let headers = parsed["request"]["raw_headers"].as_array().expect("raw headers");
    assert_eq!(headers[0].as_array().map(|pair| pair[1].as_str()), Some(Some("a\tb\\\"c")));
    let sse = b"GET /bkt/key\nx-amz-server-side-encryption-customer-algorithm: AES256\n\n";
    let refused = draft_with(&broken, sse, &dir).expect_err("a TLS request");
    assert!(refused.contains("TLS"), "{refused}");
}

/// Negative — what is not a finding any more, or not a request, or not a refusal, is not converted.
#[test]
fn only_a_reproducing_refusal_is_converted() {
    let dir = std::env::temp_dir().join(format!("difftest-no-drafts-{}", std::process::id()));
    let healthy = Differ::new().expect("both stacks build");
    let stale = draft_with(&healthy, b"GET /bkt/key\n\n", &dir).expect_err("no longer reproduces");
    assert!(stale.contains("no longer reproduces"), "{stale}");
    let garbage = draft_with(&healthy, b"not a request", &dir).expect_err("not a request");
    assert!(garbage.contains("not a request"), "{garbage}");
    assert!(!dir.exists(), "nothing was written");
}

/// Negative — the encode inputs carry no control character, the one class the property already
/// reported: a field of controls alone is empty.
#[test]
fn encode_inputs_drop_control_characters() {
    let samples = outputs_of(b"\x01\n\x7f\xc2\x83\xef\xbf\xbf\xef\xbf\xbe\x00a\tb");
    let listing = (samples[0].output)();
    let OracleOutput::ListObjectsV2(listing) = listing else {
        panic!("the first sample is a listing");
    };
    assert_eq!(listing.prefix.as_deref(), Some("\u{83}"), "a C1 character is no listing class");
    assert_eq!(listing.delimiter.as_deref(), Some("ab"));
    let head = |input: &[u8]| {
        let OracleOutput::HeadObject(head) = (outputs_of(input)[1].output)() else {
            panic!("the second sample is a head answer");
        };
        head
    };
    let tab_joined = head(b"\x00\x00n\x00a=\t?b");
    assert_eq!(
        tab_joined.metadata.and_then(|metadata| metadata.get("n").cloned()).as_deref(),
        Some("a=\t?b"),
        "a tab is kept: both stacks encode it (rustfs/gateway#996)"
    );
    let lookalike = head(b"t\tx\x01\x00\x00n\x00a=?b==???=");
    assert_eq!(lookalike.content_type.as_deref(), Some("t\tx"), "a tab is legal in a header value");
    assert_eq!(
        lookalike.metadata.and_then(|metadata| metadata.get("n").cloned()).as_deref(),
        Some("a=b===")
    );
    let named = head(b"\x00\x00x/Y z\x00\xc2\x83v");
    assert_eq!(
        named.metadata.map(|metadata| metadata.into_iter().collect::<Vec<_>>()),
        Some(vec![("xyz".to_owned(), "\u{83}v".to_owned())])
    );
    let long = "a".repeat(60);
    let ascii = head(format!("\0\0n\0{long}").as_bytes());
    assert_eq!(
        ascii.metadata.and_then(|metadata| metadata.get("n").cloned()),
        Some(long),
        "a long ASCII value is kept whole"
    );
    let tabbed = head(b"\0\0n\0a\tb\0");
    assert_eq!(tabbed.metadata.and_then(|metadata| metadata.get("n").cloned()).as_deref(), Some("a\tb"));
    let tabbed_accented = head("\0\0n\0é\tb".as_bytes());
    assert_eq!(
        tabbed_accented
            .metadata
            .and_then(|metadata| metadata.get("n").cloned())
            .as_deref(),
        Some("é\tb")
    );
    let controlled = head(format!("\0\0n\0\t{}", "a".repeat(60)).as_bytes());
    assert_eq!(
        controlled.metadata.and_then(|metadata| metadata.get("n").map(String::len)),
        Some(40),
        "an encoded value is cut"
    );
    let accented = head(format!("\0\0n\0{}", "é".repeat(30)).as_bytes());
    assert_eq!(accented.metadata.and_then(|metadata| metadata.get("n").cloned()), Some("é".repeat(20)));
}

/// Negative — a gateway that adds a header fails the encode property on the head sample.
#[test]
fn an_extra_header_fails_the_encode_property_on_the_head_answer() {
    let broken = Differ::with_fault(Fault::GatewayExtraHeader).expect("both stacks build");
    let head = outputs_of(b"text/plain\0\0n\0v").remove(1);
    assert!(!encode_differences(&broken, &head).expect("the harness runs").is_empty());
    let healthy = Differ::new().expect("both stacks build");
    assert!(encode_differences(&healthy, &head).expect("the harness runs").is_empty());
}

/// Negative — s3s failing to write its own answer (an error document holding a control character
/// it echoed from the request) is a 500 refusal on the s3s side, compared like any other, not a
/// harness failure that would stop a fuzz run or a corpus runner.
#[test]
fn an_s3s_service_failure_is_a_500_refusal() {
    let request = request_of(b"GET /bkt/k?response-expires=Thu%1C\n\n").expect("a request");
    let diff = crate::decode_diff(&request).expect("the harness runs");
    let refusal = diff.error.s3s.expect("s3s refused");
    assert_eq!((refusal.status, refusal.code), (500, None));
}

/// Negative — what a draft quotes is escaped: quotes, backslashes and every control character, so
/// a stack that echoes request bytes into a message cannot break the draft's TOML.
#[test]
fn a_draft_escapes_quotes_backslashes_and_controls() {
    assert_eq!(crate::fuzz_case::escape("a\u{1}b\"c\\d\u{9f}"), "a\\u0001b\\\"c\\\\d\\u009F");
}
