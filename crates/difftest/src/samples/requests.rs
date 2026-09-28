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

//! The request matrix: every diffed operation's requests, and exactly which registered
//! differences each must produce.
//!
//! Responsible for: the rows — one request each, with the exact set of known-diff ids its findings
//! must match — and the fixtures they share. Library code, not test code, so the `decode-diff`
//! runner and the fuzz targets start from the same requests the tests hold.
//! NOT responsible for: judging the rows (`tests/matrix.rs`) or the negative controls.
//! Upstream: the library's request type. Downstream: tests, the runners, the fuzz seeds.

use http::Method;

use super::{OWNER, sse};
use crate::RawRequest;

/// One request and the register ids its findings must match, no more and no fewer.
#[derive(Clone, Debug)]
pub struct RequestRow {
    /// A stable name for reports.
    pub name: &'static str,
    /// The request.
    pub request: RawRequest,
    /// The register ids its decode diff produces.
    pub expect: &'static [&'static str],
}

fn row(name: &'static str, request: RawRequest, expect: &'static [&'static str]) -> RequestRow {
    RequestRow { name, request, expect }
}

const HTTP_DATE: &str = "Thu, 01 Jan 2026 00:00:00 GMT";
const DELETE_BODY: &[u8] =
    b"<Delete><Object><Key>a</Key></Object><Object><Key>b</Key><VersionId>v1</VersionId></Object><Quiet>true</Quiet></Delete>";
const DELETE_MD5: &str = "518mvoIMO6cC8X/s9Ak1Cg==";
const VERSIONING_BODY: &[u8] =
    b"<VersioningConfiguration><Status>Enabled</Status><MfaDelete>Disabled</MfaDelete></VersioningConfiguration>";
const VERSIONING_MD5: &str = "0WNnnpeLLX5q+WR6BTXy2w==";
const COMPLETE_BODY: &[u8] = b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"e1\"</ETag><ChecksumCRC32>AAAAAA==</ChecksumCRC32></Part><Part><PartNumber>2</PartNumber><ETag>\"e2\"</ETag></Part></CompleteMultipartUpload>";

fn get_full() -> RawRequest {
    sse(RawRequest::get(
        "/bkt/dir/key.txt?versionId=v1&partNumber=2&response-cache-control=no-cache&response-content-disposition=attachment\
         &response-content-encoding=gzip&response-content-language=en&response-content-type=text%2Fplain\
         &response-expires=Thu%2C%2001%20Jan%202026%2000%3A00%3A00%20GMT",
    )
    .header("range", "bytes=0-9")
    .header("if-match", "\"abc\"")
    .header("if-none-match", "\"def\"")
    .header("if-modified-since", HTTP_DATE)
    .header("if-unmodified-since", "Fri, 02 Jan 2026 00:00:00 GMT")
    .header("x-amz-checksum-mode", "ENABLED")
    .header("x-amz-request-payer", "requester")
    .header("x-amz-expected-bucket-owner", OWNER))
}

fn head_full() -> RawRequest {
    sse(RawRequest::head(
        "/bkt/key?versionId=v1&partNumber=1&response-cache-control=no-cache&response-content-disposition=attachment\
         &response-content-encoding=gzip&response-content-language=en&response-content-type=text%2Fplain\
         &response-expires=Thu%2C%2001%20Jan%202026%2000%3A00%3A00%20GMT",
    )
    .header("range", "bytes=-5")
    .header("if-match", "*")
    .header("if-none-match", "W/\"w\"")
    .header("if-modified-since", HTTP_DATE)
    .header("if-unmodified-since", HTTP_DATE)
    .header("x-amz-checksum-mode", "ENABLED")
    .header("x-amz-request-payer", "requester")
    .header("x-amz-expected-bucket-owner", OWNER))
}

fn put_full() -> RawRequest {
    sse(RawRequest::put("/bkt/k", b"hello world")
        .header("content-type", "text/plain")
        .header("cache-control", "no-cache")
        .header("content-disposition", "inline")
        .header("content-encoding", "identity")
        .header("content-language", "en")
        .header("content-md5", "XrY7u+Ae7tCTyyK7j1rNww==")
        .header("expires", HTTP_DATE)
        .header("x-amz-acl", "private")
        .header("x-amz-grant-read", "id=1")
        .header("x-amz-grant-full-control", "id=2")
        .header("x-amz-grant-read-acp", "id=3")
        .header("x-amz-grant-write-acp", "id=4")
        .header("x-amz-meta-color", "blue")
        .header("x-amz-meta-size", "large")
        .header("x-amz-storage-class", "STANDARD_IA")
        .header("x-amz-website-redirect-location", "/other")
        .header("x-amz-tagging", "a=b")
        .header("x-amz-object-lock-mode", "GOVERNANCE")
        .header("x-amz-object-lock-retain-until-date", "2030-01-01T00:00:00.123Z")
        .header("x-amz-object-lock-legal-hold", "ON")
        .header("x-amz-request-payer", "requester")
        .header("x-amz-checksum-crc32", "DUoRhQ==")
        .header("x-amz-sdk-checksum-algorithm", "CRC32")
        .header("if-none-match", "*")
        .header("x-amz-write-offset-bytes", "0")
        .header("x-amz-expected-bucket-owner", OWNER))
}

/// The members `put_full` cannot set together with SSE-C, and `if-match`.
fn put_kms() -> RawRequest {
    RawRequest::put("/bkt/k", b"x")
        .header("x-amz-server-side-encryption", "aws:kms")
        .header("x-amz-server-side-encryption-aws-kms-key-id", "key-1")
        .header("x-amz-server-side-encryption-context", "e30=")
        .header("x-amz-server-side-encryption-bucket-key-enabled", "true")
        .header("if-match", "\"abc\"")
}

fn copy_full() -> RawRequest {
    sse(RawRequest::new(Method::PUT, "/bkt/dst")
        .header("x-amz-copy-source", "/src/dir/a%20b.txt?versionId=v9")
        .header("x-amz-copy-source-if-match", "\"abc\"")
        .header("x-amz-copy-source-if-none-match", "\"def\"")
        .header("x-amz-copy-source-if-modified-since", HTTP_DATE)
        .header("x-amz-copy-source-if-unmodified-since", "Fri, 02 Jan 2026 00:00:00 GMT")
        .header("x-amz-copy-source-server-side-encryption-customer-algorithm", "AES256")
        .header(
            "x-amz-copy-source-server-side-encryption-customer-key",
            "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        )
        .header("x-amz-copy-source-server-side-encryption-customer-key-md5", "hRasmdxgYDKV3nvbahU1MA==")
        .header("x-amz-metadata-directive", "REPLACE")
        .header("x-amz-tagging-directive", "REPLACE")
        .header("x-amz-tagging", "a=b")
        .header("x-amz-meta-a", "1")
        .header("content-type", "text/plain")
        .header("cache-control", "no-cache")
        .header("content-disposition", "inline")
        .header("content-encoding", "identity")
        .header("content-language", "en")
        .header("expires", HTTP_DATE)
        .header("x-amz-acl", "private")
        .header("x-amz-grant-read", "id=1")
        .header("x-amz-grant-full-control", "id=2")
        .header("x-amz-grant-read-acp", "id=3")
        .header("x-amz-grant-write-acp", "id=4")
        .header("x-amz-storage-class", "STANDARD")
        .header("x-amz-website-redirect-location", "/other")
        .header("x-amz-object-lock-mode", "GOVERNANCE")
        .header("x-amz-object-lock-retain-until-date", "2030-01-01T00:00:00Z")
        .header("x-amz-object-lock-legal-hold", "OFF")
        .header("x-amz-checksum-algorithm", "SHA256")
        .header("if-match", "\"t1\"")
        .header("if-none-match", "\"t2\"")
        .header("x-amz-request-payer", "requester")
        .header("x-amz-source-expected-bucket-owner", OWNER)
        .header("x-amz-expected-bucket-owner", OWNER))
}

fn copy_kms() -> RawRequest {
    RawRequest::new(Method::PUT, "/bkt/dst")
        .header("x-amz-copy-source", "src/k")
        .header("x-amz-server-side-encryption", "aws:kms")
        .header("x-amz-server-side-encryption-aws-kms-key-id", "key-1")
        .header("x-amz-server-side-encryption-context", "e30=")
        .header("x-amz-server-side-encryption-bucket-key-enabled", "false")
}

fn create_mpu_full() -> RawRequest {
    sse(RawRequest::new(Method::POST, "/bkt/k?uploads")
        .header("content-type", "text/plain")
        .header("cache-control", "no-cache")
        .header("content-disposition", "inline")
        .header("content-encoding", "identity")
        .header("content-language", "en")
        .header("expires", HTTP_DATE)
        .header("x-amz-acl", "private")
        .header("x-amz-grant-read", "id=1")
        .header("x-amz-grant-full-control", "id=2")
        .header("x-amz-grant-read-acp", "id=3")
        .header("x-amz-grant-write-acp", "id=4")
        .header("x-amz-meta-a", "1")
        .header("x-amz-storage-class", "STANDARD")
        .header("x-amz-website-redirect-location", "/other")
        .header("x-amz-tagging", "a=b")
        .header("x-amz-object-lock-mode", "COMPLIANCE")
        .header("x-amz-object-lock-retain-until-date", "2030-01-01T00:00:00Z")
        .header("x-amz-object-lock-legal-hold", "ON")
        .header("x-amz-checksum-algorithm", "CRC32C")
        .header("x-amz-checksum-type", "COMPOSITE")
        .header("x-amz-request-payer", "requester")
        .header("x-amz-expected-bucket-owner", OWNER))
}

fn create_mpu_kms() -> RawRequest {
    RawRequest::new(Method::POST, "/bkt/k?uploads")
        .header("x-amz-server-side-encryption", "aws:kms")
        .header("x-amz-server-side-encryption-aws-kms-key-id", "key-1")
        .header("x-amz-server-side-encryption-context", "e30=")
        .header("x-amz-server-side-encryption-bucket-key-enabled", "true")
}

/// The `x-amz-checksum-*` header naming `body`'s digest under `algorithm`, computed by the
/// gateway's own checksummer.
fn checksum(algorithm: rustfs_gateway_types::ChecksumAlgorithm, body: &[u8]) -> (&'static str, String) {
    let mut digest = algorithm.checksummer();
    digest.update(body);
    let digest = digest.finalize();
    let spec = rustfs_gateway_types::ChecksumSpec::from_digest(algorithm, &digest)
        .unwrap_or_else(|_| unreachable!("a digest is always its algorithm's width"));
    (algorithm.header_name(), spec.render_base64().to_owned())
}

/// Every checksum algorithm, with the spelling `x-amz-sdk-checksum-algorithm` takes.
const ALGORITHMS: [(rustfs_gateway_types::ChecksumAlgorithm, &str); 10] = {
    use rustfs_gateway_types::ChecksumAlgorithm as A;
    [
        (A::Crc32, "CRC32"),
        (A::Crc32c, "CRC32C"),
        (A::Crc64Nvme, "CRC64NVME"),
        (A::Md5, "MD5"),
        (A::Sha1, "SHA1"),
        (A::Sha256, "SHA256"),
        (A::Sha512, "SHA512"),
        (A::XxHash128, "XXHASH128"),
        (A::XxHash3, "XXHASH3"),
        (A::XxHash64, "XXHASH64"),
    ]
};

/// A PUT or part upload of `body` carrying its checksum under every algorithm in turn, each
/// named by both algorithm headers (one per stack, `kd-decode-0001`).
fn checksum_rows(rows: &mut Vec<RequestRow>) {
    const PUT_NAMES: [&str; 10] = [
        "put-checksum-crc32",
        "put-checksum-crc32c",
        "put-checksum-crc64nvme",
        "put-checksum-md5",
        "put-checksum-sha1",
        "put-checksum-sha256",
        "put-checksum-sha512",
        "put-checksum-xxhash128",
        "put-checksum-xxhash3",
        "put-checksum-xxhash64",
    ];
    const PART_NAMES: [&str; 10] = [
        "part-checksum-crc32",
        "part-checksum-crc32c",
        "part-checksum-crc64nvme",
        "part-checksum-md5",
        "part-checksum-sha1",
        "part-checksum-sha256",
        "part-checksum-sha512",
        "part-checksum-xxhash128",
        "part-checksum-xxhash3",
        "part-checksum-xxhash64",
    ];
    const COMPLETE_NAMES: [&str; 10] = [
        "complete-checksum-crc32",
        "complete-checksum-crc32c",
        "complete-checksum-crc64nvme",
        "complete-checksum-md5",
        "complete-checksum-sha1",
        "complete-checksum-sha256",
        "complete-checksum-sha512",
        "complete-checksum-xxhash128",
        "complete-checksum-xxhash3",
        "complete-checksum-xxhash64",
    ];
    const PART_ELEMENTS: [&str; 10] = [
        "ChecksumCRC32",
        "ChecksumCRC32C",
        "ChecksumCRC64NVME",
        "ChecksumMD5",
        "ChecksumSHA1",
        "ChecksumSHA256",
        "ChecksumSHA512",
        "ChecksumXXHASH128",
        "ChecksumXXHASH3",
        "ChecksumXXHASH64",
    ];
    let body = b"hello world";
    for (index, (algorithm, spelled)) in ALGORITHMS.into_iter().enumerate() {
        // A whole-object CRC is combinable across parts; every other algorithm is a checksum of
        // the part checksums, written with the part count.
        let (header, value) = checksum(algorithm, body);
        let (kind, value) = if algorithm.is_crc() {
            ("FULL_OBJECT", value.clone())
        } else {
            ("COMPOSITE", format!("{value}-2"))
        };
        let element = PART_ELEMENTS[index];
        let (_, part_value) = checksum(algorithm, b"part");
        let complete_body = format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"e1\"</ETag><{element}>{part_value}</{element}></Part></CompleteMultipartUpload>"
        );
        rows.push(row(
            COMPLETE_NAMES[index],
            RawRequest::post("/bkt/k?uploadId=u", complete_body.as_bytes())
                .header(header, &value)
                .header("x-amz-checksum-type", kind),
            &[],
        ));
        let (header, value) = checksum(algorithm, body);
        rows.push(row(
            PUT_NAMES[index],
            RawRequest::put("/bkt/k", body)
                .header(header, &value)
                .header("x-amz-sdk-checksum-algorithm", spelled)
                .header("x-amz-checksum-algorithm", spelled),
            &[],
        ));
        rows.push(row(
            PART_NAMES[index],
            RawRequest::put("/bkt/k?partNumber=1&uploadId=u", body)
                .header(header, &value)
                .header("x-amz-sdk-checksum-algorithm", spelled)
                .header("x-amz-checksum-algorithm", spelled),
            &[],
        ));
    }
}

/// Every request row. Names are unique; the expectation is the exact set of register ids.
#[must_use]
#[allow(clippy::too_many_lines, reason = "one table, read row by row")]
pub(super) fn requests() -> Vec<RequestRow> {
    let (delete_crc_header, delete_crc) = checksum(rustfs_gateway_types::ChecksumAlgorithm::Crc32, DELETE_BODY);
    let (versioning_crc_header, versioning_crc) = checksum(rustfs_gateway_types::ChecksumAlgorithm::Crc32, VERSIONING_BODY);
    let mut rows = vec![
        // ── GetObject / HeadObject ──
        row("get-full", get_full(), &[]),
        row("get-bare", RawRequest::get("/bkt/k"), &[]),
        row("get-suffix-range", RawRequest::get("/bkt/k").header("range", "bytes=-10"), &[]),
        row("get-open-range", RawRequest::get("/bkt/k").header("range", "bytes=10-"), &[]),
        row("get-weak-etag", RawRequest::get("/bkt/k").header("if-none-match", "W/\"w\""), &[]),
        row("get-zero-part", RawRequest::get("/bkt/k?partNumber=0"), &[]),
        row("get-unknown-checksum-mode", RawRequest::get("/bkt/k").header("x-amz-checksum-mode", "bogus"), &[]),
        row("get-empty-version", RawRequest::get("/bkt/k?versionId="), &[]),
        row("get-encoded-key", RawRequest::get("/bkt/a%2Fb%20c%3F.txt"), &[]),
        row("get-if-range", RawRequest::get("/bkt/k").header("if-range", "\"abc\"").header("range", "bytes=0-1"), &["kd-decode-0003"]),
        row("get-bad-range", RawRequest::get("/bkt/k").header("range", "bytes=abc"), &["kd-decode-0017"]),
        row("get-multi-range", RawRequest::get("/bkt/k").header("range", "bytes=0-1,5-6"), &["kd-decode-0017"]),
        row("get-items-range", RawRequest::get("/bkt/k").header("range", "items=0-1"), &["kd-decode-0017"]),
        row("get-bad-date", RawRequest::get("/bkt/k").header("if-modified-since", "yesterday"), &["kd-decode-0018"]),
        row("get-bad-etag", RawRequest::get("/bkt/k").header("if-match", "\"unterminated"), &["kd-decode-0019"]),
        row("get-bad-part", RawRequest::get("/bkt/k?partNumber=abc"), &["kd-decode-0023"]),
        row("get-bad-expires", RawRequest::get("/bkt/k?response-expires=notadate"), &["kd-decode-0023"]),
        row("get-sse-plaintext", sse(RawRequest::get("/bkt/k")).plaintext(), &["kd-decode-0016"]),
        row("get-dotdot-key", RawRequest::get("/bkt/a/../b"), &["kd-decode-0015"]),
        row("get-bad-bucket", RawRequest::get("/Bad_Bucket/k"), &["kd-decode-0024"]),
        row("get-short-bucket", RawRequest::get("/ab/k"), &["kd-decode-0024"]),
        row("head-full", head_full(), &[]),
        row("head-bare", RawRequest::head("/bkt/k"), &[]),
        row("head-bad-part", RawRequest::head("/bkt/k?partNumber=abc"), &[]),
        // ── PutObject ──
        row("put-full", put_full(), &["kd-decode-0001"]),
        row("put-kms", put_kms(), &[]),
        row("put-bare", RawRequest::put("/bkt/k", b""), &[]),
        row("put-split-body", RawRequest::put("/bkt/k", b"abcdef").body_pieces(&[b"ab", b"cd", b"ef"]), &[]),
        row("put-expires-text", RawRequest::put("/bkt/k", b"abc").header("expires", "never"), &[]),
        row("put-unknown-acl", RawRequest::put("/bkt/k", b"abc").header("x-amz-acl", "bogus"), &[]),
        row("put-unknown-storage-class", RawRequest::put("/bkt/k", b"abc").header("x-amz-storage-class", "bogus"), &[]),
        row("put-meta-encoded-word", RawRequest::put("/bkt/k", b"abc").header("x-amz-meta-name", "=?UTF-8?B?w6k=?="), &[]),
        row("put-meta-upper", RawRequest::put("/bkt/k", b"abc").header("X-Amz-Meta-Upper", "V"), &[]),
        row("put-tagging-escape", RawRequest::put("/bkt/k", b"abc").header("x-amz-tagging", "a=%ZZ"), &[]),
        row("put-part-without-upload", RawRequest::put("/bkt/k?partNumber=1", b"x"), &[]),
        row("put-version-query", RawRequest::put("/bkt/k?versionId=v1", b"abc"), &["kd-decode-0002"]),
        row("put-no-length", RawRequest::put("/bkt/k", b"abc").without("content-length"), &["kd-decode-0012"]),
        row(
            "put-two-checksums",
            RawRequest::put("/bkt/k", b"hello world")
                .header("x-amz-checksum-crc32", "DUoRhQ==")
                .header("x-amz-checksum-sha1", "Kq5sNclPz7QV2+lfQIuc6R7oRu0="),
            &["kd-decode-0013"],
        ),
        row("put-bad-md5", RawRequest::put("/bkt/k", b"abc").header("content-md5", "nope"), &["kd-decode-0014"]),
        row(
            "put-bad-lock-date",
            RawRequest::put("/bkt/k", b"abc")
                .header("x-amz-object-lock-mode", "GOVERNANCE")
                .header("x-amz-object-lock-retain-until-date", "tomorrow"),
            &["kd-decode-0023"],
        ),
        row("put-bad-write-offset", RawRequest::put("/bkt/k", b"abc").header("x-amz-write-offset-bytes", "x"), &["kd-decode-0023"]),
        // ── DeleteObject / DeleteObjects ──
        row(
            "delete-full",
            RawRequest::delete("/bkt/k?versionId=v2")
                .header("x-amz-mfa", "123 456")
                .header("x-amz-bypass-governance-retention", "true")
                .header("if-match", "\"abc\"")
                .header("x-amz-if-match-last-modified-time", HTTP_DATE)
                .header("x-amz-if-match-size", "12")
                .header("x-amz-request-payer", "requester")
                .header("x-amz-expected-bucket-owner", OWNER),
            &[],
        ),
        row("delete-bare", RawRequest::delete("/bkt/k"), &[]),
        row("delete-bad-bypass", RawRequest::delete("/bkt/k").header("x-amz-bypass-governance-retention", "maybe"), &["kd-decode-0023"]),
        row("delete-bad-size", RawRequest::delete("/bkt/k").header("x-amz-if-match-size", "big"), &["kd-decode-0023"]),
        row(
            "delete-objects",
            RawRequest::post("/bkt?delete", DELETE_BODY)
                .header("content-md5", DELETE_MD5)
                .header("x-amz-mfa", "123 456")
                .header("x-amz-bypass-governance-retention", "true")
                .header("x-amz-request-payer", "requester")
                .header("x-amz-expected-bucket-owner", OWNER),
            &[],
        ),
        row(
            "delete-objects-no-md5",
            RawRequest::post("/bkt?delete", b"<Delete><Object><Key>a</Key></Object></Delete>"),
            &["kd-decode-0020"],
        ),
        row(
            "delete-objects-malformed",
            RawRequest::post("/bkt?delete", b"<Delete><Object>").header("content-md5", "2/tgmBdmQLO+511KLYgSag=="),
            &["kd-decode-0025"],
        ),
        // ── CopyObject ──
        row("copy-full", copy_full(), &[]),
        row("copy-kms", copy_kms(), &[]),
        row("copy-bare", RawRequest::new(Method::PUT, "/bkt/dst").header("x-amz-copy-source", "src/k"), &[]),
        row(
            "copy-unknown-directive",
            RawRequest::new(Method::PUT, "/bkt/dst")
                .header("x-amz-copy-source", "src/k")
                .header("x-amz-metadata-directive", "bogus"),
            &[],
        ),
        row("copy-no-key", RawRequest::new(Method::PUT, "/bkt/dst").header("x-amz-copy-source", "nokey"), &["kd-decode-0026"]),
        row(
            "copy-access-point",
            RawRequest::new(Method::PUT, "/bkt/dst")
                .header("x-amz-copy-source", "arn:aws:s3:us-east-1:123456789012:accesspoint/ap/object/k"),
            &["kd-decode-0027"],
        ),
        // ── listings ──
        row(
            "list-v1",
            RawRequest::get("/bkt?prefix=a%2F&delimiter=%2F&marker=a%2Fb&max-keys=10&encoding-type=url")
                .header("x-amz-request-payer", "requester")
                .header("x-amz-expected-bucket-owner", OWNER),
            &[],
        ),
        row("list-v1-negative-max", RawRequest::get("/bkt?max-keys=-1"), &[]),
        row("list-v1-bare", RawRequest::get("/bkt"), &["kd-decode-0005"]),
        row("list-v1-unknown-encoding", RawRequest::get("/bkt?encoding-type=bogus"), &["kd-decode-0005"]),
        row("list-v3-is-v1", RawRequest::get("/bkt?list-type=3"), &["kd-decode-0005"]),
        row("list-v1-bad-max", RawRequest::get("/bkt?max-keys=abc"), &["kd-decode-0023"]),
        row(
            "list-v2",
            RawRequest::get(
                "/bkt?list-type=2&prefix=p&delimiter=%2F&continuation-token=tok&start-after=s&max-keys=5&fetch-owner=true&encoding-type=url",
            )
            .header("x-amz-request-payer", "requester")
            .header("x-amz-expected-bucket-owner", OWNER),
            &[],
        ),
        row("list-v2-bare", RawRequest::get("/bkt?list-type=2"), &["kd-decode-0006", "kd-decode-0007"]),
        row("list-v2-empty-token", RawRequest::get("/bkt?list-type=2&continuation-token="), &["kd-decode-0006", "kd-decode-0007"]),
        row("list-v2-bad-fetch", RawRequest::get("/bkt?list-type=2&fetch-owner=maybe"), &["kd-decode-0023"]),
        row(
            "list-versions",
            RawRequest::get("/bkt?versions&prefix=p&key-marker=k&version-id-marker=v&max-keys=7&delimiter=%2F&encoding-type=url")
                .header("x-amz-request-payer", "requester")
                .header("x-amz-expected-bucket-owner", OWNER),
            &[],
        ),
        row("list-versions-bare", RawRequest::get("/bkt?versions"), &["kd-decode-0008"]),
        row(
            "list-uploads",
            RawRequest::get("/bkt?uploads&prefix=p&key-marker=k&upload-id-marker=u&max-uploads=3&delimiter=%2F&encoding-type=url")
                .header("x-amz-request-payer", "requester")
                .header("x-amz-expected-bucket-owner", OWNER),
            &[],
        ),
        row("list-uploads-bare", RawRequest::get("/bkt?uploads"), &["kd-decode-0009"]),
        // ── multipart ──
        row("create-mpu", create_mpu_full(), &[]),
        row("create-mpu-kms", create_mpu_kms(), &[]),
        row("create-mpu-bare", RawRequest::new(Method::POST, "/bkt/k?uploads"), &[]),
        row(
            "upload-part",
            sse(RawRequest::put("/bkt/k?partNumber=3&uploadId=up-1", b"part-bytes")
                .header("content-md5", "J7Ph78rJKYDUMevg/+smbA==")
                .header("x-amz-checksum-sha256", "Ipvar83SrlL+B5gOlN/4PP1f4d4gCmAkqmWH1V6gfoQ=")
                .header("x-amz-request-payer", "requester")
                .header("x-amz-expected-bucket-owner", OWNER)),
            &[],
        ),
        row("upload-part-bare", RawRequest::put("/bkt/k?partNumber=1&uploadId=u", b""), &[]),
        row("upload-part-zero", RawRequest::put("/bkt/k?partNumber=0&uploadId=u", b"x"), &["kd-decode-0022"]),
        row("upload-part-10001", RawRequest::put("/bkt/k?partNumber=10001&uploadId=u", b"x"), &["kd-decode-0022"]),
        row("upload-part-unmintable-id", RawRequest::put("/bkt/k?partNumber=1&uploadId=/abs", b"x"), &["kd-decode-0004"]),
        row(
            "complete",
            sse(RawRequest::post("/bkt/k?uploadId=up-1", COMPLETE_BODY)
                .header("x-amz-mp-object-size", "100")
                .header("x-amz-checksum-type", "FULL_OBJECT")
                .header("x-amz-checksum-crc32", "AAAAAA==")
                .header("if-match", "\"m\"")
                .header("if-none-match", "*")
                .header("x-amz-request-payer", "requester")
                .header("x-amz-expected-bucket-owner", OWNER)),
            &[],
        ),
        row("complete-no-parts", RawRequest::post("/bkt/k?uploadId=u", b"<CompleteMultipartUpload></CompleteMultipartUpload>"), &[]),
        row("complete-no-body", RawRequest::post("/bkt/k?uploadId=u", b""), &["kd-decode-0025"]),
        row("complete-malformed", RawRequest::post("/bkt/k?uploadId=u", b"<CompleteMultipartUpload><Part>"), &["kd-decode-0025"]),
        row(
            "abort",
            RawRequest::delete("/bkt/k?uploadId=up-1")
                .header("x-amz-if-match-initiated-time", HTTP_DATE)
                .header("x-amz-request-payer", "requester")
                .header("x-amz-expected-bucket-owner", OWNER),
            &[],
        ),
        row(
            "list-parts",
            sse(RawRequest::get("/bkt/k?uploadId=up-1&max-parts=4&part-number-marker=2")
                .header("x-amz-request-payer", "requester")
                .header("x-amz-expected-bucket-owner", OWNER)),
            &[],
        ),
        row("list-parts-bare", RawRequest::get("/bkt/k?uploadId=u"), &["kd-decode-0010"]),
        row("list-parts-bad-max", RawRequest::get("/bkt/k?uploadId=u&max-parts=x"), &["kd-decode-0023"]),
        // ── buckets ──
        row(
            "create-bucket",
            RawRequest::put(
                "/newbkt",
                b"<CreateBucketConfiguration><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>",
            )
            .header("x-amz-acl", "private")
            .header("x-amz-grant-read", "id=1")
            .header("x-amz-grant-full-control", "id=2")
            .header("x-amz-grant-read-acp", "id=3")
            .header("x-amz-grant-write", "id=4")
            .header("x-amz-grant-write-acp", "id=5")
            .header("x-amz-bucket-object-lock-enabled", "true")
            .header("x-amz-object-ownership", "BucketOwnerEnforced"),
            &[],
        ),
        row("create-bucket-empty-body", RawRequest::put("/newbkt", b""), &[]),
        row("create-bucket-bare", RawRequest::new(Method::PUT, "/newbkt"), &[]),
        row("create-bucket-malformed", RawRequest::put("/newbkt", b"<CreateBucketConfiguration>"), &["kd-decode-0025"]),
        row("create-bucket-bad-name", RawRequest::new(Method::PUT, "/Bad_Name"), &["kd-decode-0024"]),
        row("delete-bucket", RawRequest::delete("/bkt").header("x-amz-expected-bucket-owner", OWNER), &[]),
        row("head-bucket", RawRequest::head("/bkt").header("x-amz-expected-bucket-owner", OWNER), &[]),
        row("list-buckets", RawRequest::get("/?max-buckets=10&prefix=b&continuation-token=t&bucket-region=us-east-1"), &[]),
        row("list-buckets-zero-max", RawRequest::get("/?max-buckets=0"), &[]),
        row("list-buckets-bare", RawRequest::get("/"), &["kd-decode-0011"]),
        row("location", RawRequest::get("/bkt?location").header("x-amz-expected-bucket-owner", OWNER), &[]),
        row("get-versioning", RawRequest::get("/bkt?versioning").header("x-amz-expected-bucket-owner", OWNER), &[]),
        row(
            "put-versioning",
            RawRequest::put("/bkt?versioning", VERSIONING_BODY)
                .header("content-md5", VERSIONING_MD5)
                .header("x-amz-mfa", "123 456")
                .header("x-amz-expected-bucket-owner", OWNER),
            &[],
        ),
        row(
            "put-versioning-no-md5",
            RawRequest::put("/bkt?versioning", b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"),
            &["kd-decode-0021"],
        ),
        // ── no operation, or one the diff does not project ──
        row("unrouted-post", RawRequest::post("/bkt/k", b""), &["kd-decode-0028"]),
        row("unrouted-patch", RawRequest::new(Method::PATCH, "/bkt/k"), &["kd-decode-0028"]),
        row("unprojected-object-tagging", RawRequest::get("/bkt/k?tagging"), &["kd-decode-0029"]),
        row("unprojected-bucket-acl", RawRequest::get("/bkt?acl"), &["kd-decode-0029"]),
        row("unprojected-bucket-policy", RawRequest::get("/bkt?policy"), &["kd-decode-0029"]),
        // ── members only one model carries ──
        row(
            "put-event-hold",
            RawRequest::put("/bkt/k", b"x")
                .header("x-amz-object-lock-event-hold", "ON")
                .header("x-amz-object-lock-event-hold-duration-days", "1"),
            &["kd-decode-0037"],
        ),
        row("put-event-hold-years", RawRequest::put("/bkt/k", b"x").header("x-amz-object-lock-event-hold-duration-years", "1"), &["kd-decode-0037"]),
        row(
            "copy-event-hold",
            RawRequest::new(Method::PUT, "/bkt/dst")
                .header("x-amz-copy-source", "src/k")
                .header("x-amz-object-lock-event-hold", "ON")
                .header("x-amz-object-lock-event-hold-duration-days", "1"),
            &["kd-decode-0038"],
        ),
        row(
            "copy-event-hold-years",
            RawRequest::new(Method::PUT, "/bkt/dst")
                .header("x-amz-copy-source", "src/k")
                .header("x-amz-object-lock-event-hold-duration-years", "1"),
            &["kd-decode-0038"],
        ),
        row(
            "create-mpu-event-hold",
            RawRequest::new(Method::POST, "/bkt/k?uploads")
                .header("x-amz-object-lock-event-hold", "ON")
                .header("x-amz-object-lock-event-hold-duration-days", "1"),
            &["kd-decode-0039"],
        ),
        row(
            "create-mpu-event-hold-years",
            RawRequest::new(Method::POST, "/bkt/k?uploads").header("x-amz-object-lock-event-hold-duration-years", "1"),
            &["kd-decode-0039"],
        ),
        row(
            "copy-annotation-directive",
            RawRequest::new(Method::PUT, "/bkt/dst")
                .header("x-amz-copy-source", "src/k")
                .header("x-amz-object-annotation-directive", "COPY"),
            &["kd-decode-0040"],
        ),
        row("copy-target-version", RawRequest::new(Method::PUT, "/bkt/dst?versionId=v1").header("x-amz-copy-source", "src/k"), &["kd-decode-0041"]),
        row("create-mpu-version", RawRequest::new(Method::POST, "/bkt/k?uploads&versionId=v1"), &["kd-decode-0042"]),
        row("list-v1-attributes", RawRequest::get("/bkt").header("x-amz-optional-object-attributes", "RestoreStatus"), &["kd-decode-0005"]),
        row(
            "list-v2-attributes",
            RawRequest::get("/bkt?list-type=2").header("x-amz-optional-object-attributes", "RestoreStatus"),
            &["kd-decode-0006", "kd-decode-0007"],
        ),
        row(
            "list-versions-attributes",
            RawRequest::get("/bkt?versions").header("x-amz-optional-object-attributes", "RestoreStatus"),
            &["kd-decode-0008"],
        ),
        row(
            "delete-objects-conditions",
            RawRequest::post("/bkt?delete", b"<Delete><Object><Key>a</Key><ETag>\"e1\"</ETag><LastModifiedTime>Thu, 01 Jan 2026 00:00:00 GMT</LastModifiedTime><Size>12</Size></Object></Delete>").header("content-md5", "6MtSlqyPpAWnEImDgd0S7w=="),
            &["kd-decode-0046"],
        ),
        row(
            "delete-objects-iso-modified-time",
            RawRequest::post("/bkt?delete", b"<Delete><Object><Key>a</Key><LastModifiedTime>2026-01-01T00:00:00Z</LastModifiedTime></Object></Delete>").header("content-md5", "wMu22G1zbAmxonJP/ymRgg=="),
            &["kd-decode-0047", "kd-decode-0023"],
        ),
        row("create-bucket-namespace", RawRequest::new(Method::PUT, "/newbkt").header("x-amz-bucket-namespace", "global"), &["kd-decode-0048"]),
        row("create-bucket-directory-configuration", RawRequest::put("/newbkt", b"<CreateBucketConfiguration><LocationConstraint>eu-west-1</LocationConstraint><Location><Name>usw2-az1</Name><Type>AvailabilityZone</Type></Location><Bucket><DataRedundancy>SingleAvailabilityZone</DataRedundancy><Type>Directory</Type></Bucket><Tags><Tag><Key>k</Key><Value>v</Value></Tag></Tags></CreateBucketConfiguration>"), &["kd-decode-0049"]),
        row("delete-bucket-force", RawRequest::delete("/bkt").header("x-minio-force-delete", "true"), &["kd-decode-0050"]),
        row(
            "put-versioning-excluded-prefixes",
            RawRequest::put("/bkt?versioning", b"<VersioningConfiguration><Status>Enabled</Status><ExcludedPrefixes><Prefix>tmp/</Prefix></ExcludedPrefixes><ExcludeFolders>true</ExcludeFolders></VersioningConfiguration>").header("content-md5", "Wa47PRGv0uNTKQpT3bkHzg=="),
            &["kd-decode-0051"],
        ),
        // ── a body that ends in an error on one stack ──
        row("put-checksum-mismatch", RawRequest::put("/bkt/k", b"hello world").header("x-amz-checksum-crc32", "AAAAAA=="), &["kd-decode-0052"]),
        row("put-md5-mismatch", RawRequest::put("/bkt/k", b"hello world").header("content-md5", "eV8yArF8trw9S3cdjGyerw=="), &["kd-decode-0052"]),
        // ── the SDK operation hint ──
        row("put-x-id-copy", RawRequest::put("/bkt/k?x-id=CopyObject", b"abc"), &["kd-decode-0055", "kd-decode-0056"]),
        row("put-x-id-put", RawRequest::put("/bkt/k?x-id=PutObject", b"abc"), &[]),
        row("list-x-id-v2-without-list-type", RawRequest::get("/bkt?x-id=ListObjectsV2"), &["kd-decode-0057"]),
        row("list-v2-with-x-id", RawRequest::get("/bkt?list-type=2&x-id=ListObjectsV2"), &["kd-decode-0006", "kd-decode-0007"]),
        row("get-x-id-tagging", RawRequest::get("/bkt/k?x-id=GetObjectTagging"), &["kd-decode-0058", "kd-decode-0059"]),
        row(
            "post-x-id-create-upload",
            RawRequest::new(Method::POST, "/bkt/k?x-id=CreateMultipartUpload"),
            &["kd-decode-0060", "kd-decode-0061"],
        ),
        row("delete-x-id-mismatch", RawRequest::delete("/bkt/k?x-id=DeleteObjects"), &["kd-decode-0062", "kd-decode-0063"]),
        row("get-unc-shaped-key", RawRequest::get("/bkt///server/share"), &["kd-decode-0072"]),
        row(
            "copy-unquoted-if-match",
            RawRequest::put("/bkt/dst", b"")
                .header("x-amz-copy-source", "/bkt/src/plain.txt")
                .header("x-amz-copy-source-if-match", "5eb63bbbe01eeed093cb22bb8f5acdc3"),
            &["kd-decode-0073"],
        ),
        row("put-empty-content-type", RawRequest::put("/bkt/k", b"x").header("content-type", ""), &["kd-decode-0074"]),
        row("put-versioning-empty-body", RawRequest::put("/bkt?versioning", b""), &["kd-decode-0053", "kd-decode-0054"]),
        // ── the algorithm header without its checksum ──
        row(
            "delete-objects-algorithm-with-checksum",
            RawRequest::post("/bkt?delete", DELETE_BODY)
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .header("x-amz-checksum-algorithm", "CRC32")
                .header(delete_crc_header, &delete_crc),
            &[],
        ),
        row(
            "delete-objects-sdk-algorithm-only",
            RawRequest::post("/bkt?delete", DELETE_BODY)
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .header(delete_crc_header, &delete_crc),
            &["kd-decode-0033"],
        ),
        row(
            "delete-objects-algorithm-without-checksum",
            RawRequest::post("/bkt?delete", DELETE_BODY)
                .header("content-md5", DELETE_MD5)
                .header("x-amz-sdk-checksum-algorithm", "CRC32"),
            &["kd-decode-0030"],
        ),
        row(
            "put-versioning-algorithm-with-checksum",
            RawRequest::put("/bkt?versioning", VERSIONING_BODY)
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .header("x-amz-checksum-algorithm", "CRC32")
                .header(versioning_crc_header, &versioning_crc),
            &[],
        ),
        row(
            "put-versioning-sdk-algorithm-only",
            RawRequest::put("/bkt?versioning", VERSIONING_BODY)
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .header(versioning_crc_header, &versioning_crc),
            &["kd-decode-0034"],
        ),
        row(
            "put-versioning-algorithm-without-checksum",
            RawRequest::put("/bkt?versioning", VERSIONING_BODY)
                .header("content-md5", VERSIONING_MD5)
                .header("x-amz-sdk-checksum-algorithm", "CRC32"),
            &["kd-decode-0031"],
        ),
        row(
            "part-sdk-algorithm-only",
            RawRequest::put("/bkt/k?partNumber=1&uploadId=u", b"hello world")
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .header("x-amz-checksum-crc32", "DUoRhQ=="),
            &["kd-decode-0032"],
        ),
        row(
            "part-algorithm-without-checksum",
            RawRequest::put("/bkt/k?partNumber=1&uploadId=u", b"x").header("x-amz-sdk-checksum-algorithm", "CRC32"),
            &["kd-decode-0035"],
        ),
        row(
            "put-algorithm-without-checksum",
            RawRequest::put("/bkt/k", b"x").header("x-amz-sdk-checksum-algorithm", "CRC32"),
            &["kd-decode-0036"],
        ),
    ];
    checksum_rows(&mut rows);
    rows
}
