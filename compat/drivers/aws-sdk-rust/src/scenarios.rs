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

//! The abstract scenarios, expressed as aws-sdk-s3 calls.
//!
//! Responsible for: one function per implemented scenario id, with the same sizes, keys and
//! failure messages as the aws-sdk-go exemplar, each ending in `Ok(())` or an `Outcome`.
//! NOT responsible for: judging wire facts (payload mode, chunk count, trailer). The streaming and
//! trailer scenarios only send the SDK's ordinary upload shape and compare bytes; whether the wire
//! carried signed chunks or a trailer is `ci/compat/report.py`'s call against the probe log.
//!
//! Upstream: `main.rs`, which has already created the bucket. Downstream: the system under test,
//! and `plain_http.rs` for redeeming presigned URLs.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{
    BucketVersioningStatus, CompletedMultipartUpload, CompletedPart, Delete, ObjectIdentifier, VersioningConfiguration,
};

use crate::{fail, plain_http, Driver, Step};

const IDS: &[&str] = &[
    "bucket-lifecycle",
    "small-object-roundtrip",
    "large-multipart-upload",
    "list-pagination",
    "range-download",
    "presigned-get",
    "presigned-put",
    "versioned-object",
    "copy-object",
    "delete-batch",
    "streaming-chunked-upload",
    "trailer-chunked-upload",
];

pub fn known(scenario: &str) -> bool {
    IDS.contains(&scenario)
}

pub async fn run(scenario: &str, d: &Driver) -> Step {
    match scenario {
        "bucket-lifecycle" => bucket_lifecycle(d).await,
        "small-object-roundtrip" => small_object_roundtrip(d).await,
        "large-multipart-upload" => large_multipart_upload(d).await,
        "list-pagination" => list_pagination(d).await,
        "range-download" => range_download(d).await,
        "presigned-get" => presigned_get(d).await,
        "presigned-put" => presigned_put(d).await,
        "versioned-object" => versioned_object(d).await,
        "copy-object" => copy_object(d).await,
        "delete-batch" => delete_batch(d).await,
        "streaming-chunked-upload" => streaming_chunked_upload(d).await,
        "trailer-chunked-upload" => trailer_chunked_upload(d).await,
        other => fail(format!("scenario {other} has no implementation")),
    }
}

fn random(size: usize) -> Step<Vec<u8>> {
    let mut payload = vec![0; size];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut payload)?;
    Ok(payload)
}

impl Driver {
    async fn get(&self, key: &str, range: Option<&str>, version: Option<&str>) -> Step<Vec<u8>> {
        let out = self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .set_range(range.map(str::to_string))
            .set_version_id(version.map(str::to_string))
            .send()
            .await?;
        Ok(out.body.collect().await?.to_vec())
    }

    /// PutObject of an in-memory body; the SDK signs the whole payload's SHA-256 for it.
    async fn put(&self, key: &str, body: Vec<u8>) -> Step<aws_sdk_s3::operation::put_object::PutObjectOutput> {
        Ok(self
            .s3
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(body))
            .send()
            .await?)
    }

    /// Writes `payload` under the scratch directory, uploads it with the SDK's ordinary file body,
    /// and reads it back.
    async fn put_file_and_compare(&self, key: &str, payload: &[u8]) -> Step {
        let path = Path::new(&self.work).join(key);
        std::fs::write(&path, payload)?;
        let body = ByteStream::from_path(&path).await?;
        self.s3.put_object().bucket(&self.bucket).key(key).body(body).send().await?;
        let read = self.get(key, None, None).await?;
        if read != payload {
            return fail(format!("read back {} bytes that differ from the {} written", read.len(), payload.len()));
        }
        Ok(())
    }
}

async fn bucket_lifecycle(d: &Driver) -> Step {
    d.s3.head_bucket().bucket(&d.bucket).send().await?;
    d.s3.delete_bucket().bucket(&d.bucket).send().await?;
    if d.s3.head_bucket().bucket(&d.bucket).send().await.is_ok() {
        return fail("the bucket answered HeadBucket after it was deleted");
    }
    Ok(())
}

async fn small_object_roundtrip(d: &Driver) -> Step {
    let payload = random(4096)?;
    d.put("small.bin", payload.clone()).await?;
    let read = d.get("small.bin", None, None).await?;
    if read != payload {
        return fail(format!("read back {} bytes that differ from the {} written", read.len(), payload.len()));
    }
    let head = d.s3.head_object().bucket(&d.bucket).key("small.bin").send().await?;
    let length = head.content_length.unwrap_or_default();
    if length != payload.len() as i64 {
        return fail(format!("HeadObject reported {length} for a {} byte object", payload.len()));
    }
    Ok(())
}

/// aws-sdk-s3 has no high-level transfer manager (that is the separate aws-s3-transfer-manager
/// crate, which is not part of the SDK), so this is the SDK's own multipart API called explicitly:
/// CreateMultipartUpload, one UploadPart per 5 MiB part, then CompleteMultipartUpload.
async fn large_multipart_upload(d: &Driver) -> Step {
    const PART: usize = 5 * 1024 * 1024;
    let payload = random(12 * 1024 * 1024)?;
    let created =
        d.s3.create_multipart_upload()
            .bucket(&d.bucket)
            .key("multipart.bin")
            .send()
            .await?;
    let Some(upload_id) = created.upload_id else {
        return fail("CreateMultipartUpload returned no upload id");
    };
    let mut parts = Vec::new();
    for (index, chunk) in payload.chunks(PART).enumerate() {
        let number = index as i32 + 1;
        let uploaded =
            d.s3.upload_part()
                .bucket(&d.bucket)
                .key("multipart.bin")
                .upload_id(&upload_id)
                .part_number(number)
                .body(ByteStream::from(chunk.to_vec()))
                .send()
                .await?;
        parts.push(
            CompletedPart::builder()
                .part_number(number)
                .set_e_tag(uploaded.e_tag)
                .set_checksum_crc32(uploaded.checksum_crc32)
                .build(),
        );
    }
    d.s3.complete_multipart_upload()
        .bucket(&d.bucket)
        .key("multipart.bin")
        .upload_id(&upload_id)
        .multipart_upload(CompletedMultipartUpload::builder().set_parts(Some(parts)).build())
        .send()
        .await?;
    let read = d.get("multipart.bin", None, None).await?;
    if read != payload {
        return fail(format!("read back {} bytes that differ from the {} written", read.len(), payload.len()));
    }
    let head = d.s3.head_object().bucket(&d.bucket).key("multipart.bin").send().await?;
    let etag = head.e_tag.unwrap_or_default();
    if !etag.contains('-') {
        return fail(format!("a multipart object reported the single-part entity tag {etag}"));
    }
    Ok(())
}

async fn list_pagination(d: &Driver) -> Step {
    let keys: Vec<String> = (0..25).map(|index| format!("page/{index:04}.txt")).collect();
    for key in &keys {
        d.put(key, key.as_bytes().to_vec()).await?;
    }
    let mut pages_stream =
        d.s3.list_objects_v2()
            .bucket(&d.bucket)
            .prefix("page/")
            .max_keys(7)
            .into_paginator()
            .send();
    let mut seen = Vec::new();
    let mut pages = 0;
    while let Some(page) = pages_stream.next().await {
        let page = page?;
        pages += 1;
        seen.extend(page.contents().iter().filter_map(|entry| entry.key().map(str::to_string)));
        if pages > 20 {
            return fail("the listing did not terminate within 20 pages");
        }
    }
    seen.sort();
    if seen != keys {
        return fail(format!("listed {} keys over {pages} page(s), expected {}", seen.len(), keys.len()));
    }
    if pages < 2 {
        return fail(format!("a {} key listing at page size 7 returned {pages} page(s)", keys.len()));
    }
    Ok(())
}

async fn range_download(d: &Driver) -> Step {
    let payload = random(1024 * 1024)?;
    d.put("ranged.bin", payload.clone()).await?;
    let read = d.get("ranged.bin", Some("bytes=1000-5000"), None).await?;
    if read != payload[1000..5001] {
        return fail(format!(
            "bytes=1000-5000 returned {} bytes that differ from the same slice of the source",
            read.len()
        ));
    }
    Ok(())
}

fn presigning() -> Step<PresigningConfig> {
    PresigningConfig::expires_in(Duration::from_secs(300)).map_err(|err| crate::Outcome::Fail(err.to_string()))
}

async fn presigned_get(d: &Driver) -> Step {
    let payload = random(2048)?;
    d.put("presigned.bin", payload.clone()).await?;
    let presigned =
        d.s3.get_object()
            .bucket(&d.bucket)
            .key("presigned.bin")
            .presigned(presigning()?)
            .await?;
    let response = plain_http::send(presigned.method(), presigned.uri(), presigned.headers(), None)?;
    if response.status != 200 {
        return fail(format!("a presigned GET was answered {}", response.status));
    }
    if response.body != payload {
        return fail(format!(
            "a presigned GET returned {} bytes, expected {}",
            response.body.len(),
            payload.len()
        ));
    }
    Ok(())
}

async fn presigned_put(d: &Driver) -> Step {
    let payload = random(2048)?;
    let presigned =
        d.s3.put_object()
            .bucket(&d.bucket)
            .key("presigned-put.bin")
            .presigned(presigning()?)
            .await?;
    let response = plain_http::send(presigned.method(), presigned.uri(), presigned.headers(), Some(&payload))?;
    if response.status != 200 && response.status != 201 {
        return fail(format!("a presigned PUT was answered {}", response.status));
    }
    let read = d.get("presigned-put.bin", None, None).await?;
    if read != payload {
        return fail("a presigned PUT stored bytes that differ from the ones sent");
    }
    Ok(())
}

async fn versioned_object(d: &Driver) -> Step {
    let enabled = VersioningConfiguration::builder()
        .status(BucketVersioningStatus::Enabled)
        .build();
    d.s3.put_bucket_versioning()
        .bucket(&d.bucket)
        .versioning_configuration(enabled)
        .send()
        .await?;
    let status = d.s3.get_bucket_versioning().bucket(&d.bucket).send().await?;
    if status.status != Some(BucketVersioningStatus::Enabled) {
        let reported = status.status.as_ref().map(|s| s.as_str()).unwrap_or("");
        return fail(format!("versioning reported {reported:?} after it was enabled"));
    }
    let first = d.put("versioned.bin", b"first".to_vec()).await?;
    d.put("versioned.bin", b"second".to_vec()).await?;
    let listing =
        d.s3.list_object_versions()
            .bucket(&d.bucket)
            .prefix("versioned.bin")
            .send()
            .await?;
    if listing.versions().len() < 2 {
        return fail(format!(
            "two writes to an enabled bucket enumerated {} version(s)",
            listing.versions().len()
        ));
    }
    let oldest = d.get("versioned.bin", None, first.version_id()).await?;
    if oldest != b"first" {
        return fail("an explicit version read returned the wrong version's bytes");
    }
    Ok(())
}

async fn copy_object(d: &Driver) -> Step {
    d.put("source.bin", b"copy me".to_vec()).await?;
    d.s3.copy_object()
        .bucket(&d.bucket)
        .key("target.bin")
        .copy_source(format!("{}/source.bin", d.bucket))
        .send()
        .await?;
    let read = d.get("target.bin", None, None).await?;
    if read != b"copy me" {
        return fail("a server-side copy produced different bytes");
    }
    Ok(())
}

async fn delete_batch(d: &Driver) -> Step {
    let mut objects = Vec::new();
    for index in 0..10 {
        let key = format!("batch/{index}.txt");
        d.put(&key, b"x".to_vec()).await?;
        objects.push(ObjectIdentifier::builder().key(key).build()?);
    }
    let delete = Delete::builder().set_objects(Some(objects)).quiet(true).build()?;
    d.s3.delete_objects().bucket(&d.bucket).delete(delete).send().await?;
    let listing = d.s3.list_objects_v2().bucket(&d.bucket).send().await?;
    let count = listing.key_count.unwrap_or_default();
    if count != 0 {
        return fail(format!("{count} key(s) survived a batch delete"));
    }
    Ok(())
}

/// A 9 MiB file body over the plaintext endpoint with SDK defaults. Measured: for a body read from
/// a file, aws-sdk-s3 declares STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER and sends signed
/// aws-chunked frames with its default CRC32 checksum in a signed trailer (an in-memory body is
/// instead signed as one whole-payload SHA-256). Nothing here forces that; the probe judges it.
async fn streaming_chunked_upload(d: &Driver) -> Step {
    let payload = random(9 * 1024 * 1024)?;
    d.put_file_and_compare("streaming.bin", &payload).await
}

/// A 1 MiB file body over the plaintext endpoint with SDK defaults: the same shape as above, which
/// is the one where aws-sdk-s3 carries its default CRC32 checksum in an x-amz-trailer behind
/// `Content-Encoding: aws-chunked`, so no TLS endpoint is needed. Whether a trailer arrived is the
/// probe's call, not this driver's.
async fn trailer_chunked_upload(d: &Driver) -> Step {
    let payload = random(1024 * 1024)?;
    d.put_file_and_compare("trailer.bin", &payload).await
}
