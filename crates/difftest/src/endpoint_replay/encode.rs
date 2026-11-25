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

//! Out-of-process `encode_diff` corpus replay against a live S3 candidate `--endpoint`.
//!
//! Responsible for: translating each `encode_diff` corpus input via `fuzz::outputs_of` into real
//! HTTP `PutObject`, `HeadObject`, `GetObject`, `ListObjectsV2` (plain, `encoding-type=url`, and
//! `continuation-token`), and cleanup `DeleteObject` exchanges so the live candidate exercises its
//! response-header and XML encoders on the wire; verifying no 5xx/crash/hang, consistent
//! `HeadObject`/`GetObject` readback after 2xx `PutObject`, and well-formed XML on 200 listings.
//! NOT responsible for: CLI parsing, raw TCP framing (`http_client.rs`), or `decode_diff` replay
//! (`mod.rs`).
//! Upstream: `fuzz.rs`, `endpoint_replay/mod.rs`, `endpoint_replay/http_client.rs`.
//! Downstream: `endpoint_replay/mod.rs`.

use std::collections::BTreeSet;

use http::HeaderValue;

use super::http_client::{
    encode_metadata_header_value, join_query, percent_encode, preview_body, truncate_utf8, validate_xml_document,
};
use super::{
    CorpusEntry, Endpoint, Options, Report, Target, ensure_bucket, maybe_mark_dead, record_failure, send_checked,
    send_signed_if_configured,
};
use crate::fuzz::outputs_of;
use crate::project::OracleOutput;
use crate::request::RawRequest;

const MAX_ENCODE_KEY_BYTES: usize = 200;
const OBJECT_BODY: &[u8] = b"hello";

pub(super) fn replay_encode_diff(
    options: &Options,
    endpoint: &Endpoint,
    entries: &[CorpusEntry],
    report: &mut Report,
) -> Result<(), String> {
    ensure_bucket(endpoint, &options.bucket, options.credentials.as_ref(), options.timeout)?;
    for (index, entry) in entries.iter().enumerate() {
        report.replayed += 1;
        let samples = outputs_of(&entry.bytes);
        let mut entry_error = None;
        for sample in samples {
            match (sample.output)() {
                OracleOutput::HeadObject(head) => {
                    if let Err(error) = exercise_head_encode(options, endpoint, index, &head, report) {
                        entry_error = Some(error);
                        break;
                    }
                }
                OracleOutput::ListObjectsV2(listing) => {
                    if let Err(error) = exercise_list_encode(options, endpoint, index, &listing, report) {
                        entry_error = Some(error);
                        break;
                    }
                }
                _ => {}
            }
        }
        if let Some(reason) = entry_error {
            record_failure(
                report,
                options.artifacts_dir.as_deref(),
                Target::EncodeDiff,
                &entry.label,
                &entry.bytes,
                &reason,
            );
            if maybe_mark_dead(options, endpoint, report) {
                break;
            }
        }
    }
    let _ = send_signed_if_configured(
        endpoint,
        RawRequest::delete(&format!("/{}", options.bucket)),
        options.credentials.as_ref(),
        options.timeout,
    );
    Ok(())
}

fn exercise_head_encode(
    options: &Options,
    endpoint: &Endpoint,
    index: usize,
    head: &crate::s3s::dto::HeadObjectOutput,
    report: &mut Report,
) -> Result<(), String> {
    let target = format!("/{}/enc/{index}/head", options.bucket);
    let mut put = RawRequest::put(&target, OBJECT_BODY);
    if let Some(content_type) = head.content_type.as_deref()
        && HeaderValue::from_bytes(content_type.as_bytes()).is_ok()
    {
        put.headers
            .push(("content-type".to_owned(), content_type.as_bytes().to_vec()));
    }
    if let Some(disposition) = head.content_disposition.as_deref()
        && HeaderValue::from_bytes(disposition.as_bytes()).is_ok()
    {
        put.headers
            .push(("content-disposition".to_owned(), disposition.as_bytes().to_vec()));
    }
    if let Some(metadata) = &head.metadata {
        for (name, value) in metadata {
            if name.is_empty() {
                continue;
            }
            let header_name = format!("x-amz-meta-{name}");
            let header_bytes = encode_metadata_header_value(value);
            if http::HeaderName::from_bytes(header_name.as_bytes()).is_ok() && HeaderValue::from_bytes(&header_bytes).is_ok() {
                put.headers.push((header_name, header_bytes));
            }
        }
    }

    let put_resp = send_checked(endpoint, put, options.credentials.as_ref(), options.timeout, report, "PutObject")?;
    if !(200..300).contains(&put_resp.status) {
        return Ok(());
    }

    let head_resp = send_checked(
        endpoint,
        RawRequest::head(&target),
        options.credentials.as_ref(),
        options.timeout,
        report,
        "HeadObject",
    )?;
    if head_resp.status != 200 {
        return Err(format!("HeadObject {target} after 2xx PutObject returned HTTP {}", head_resp.status));
    }

    let get_resp = send_checked(
        endpoint,
        RawRequest::get(&target),
        options.credentials.as_ref(),
        options.timeout,
        report,
        "GetObject",
    )?;
    if get_resp.status != 200 {
        return Err(format!(
            "GetObject {target} after 2xx PutObject returned HTTP {}: {}",
            get_resp.status,
            preview_body(&get_resp.body)
        ));
    }
    if get_resp.body != OBJECT_BODY {
        return Err(format!(
            "GetObject {target} returned {} body byte(s), expected {}",
            get_resp.body.len(),
            OBJECT_BODY.len()
        ));
    }

    let _ = send_checked(
        endpoint,
        RawRequest::delete(&target),
        options.credentials.as_ref(),
        options.timeout,
        report,
        "DeleteObject",
    )?;
    Ok(())
}

fn exercise_list_encode(
    options: &Options,
    endpoint: &Endpoint,
    index: usize,
    listing: &crate::s3s::dto::ListObjectsV2Output,
    report: &mut Report,
) -> Result<(), String> {
    let scope_prefix = format!("l/{index}/");
    let mut created_targets = Vec::new();
    let mut seen_keys = BTreeSet::new();

    if let Some(contents) = &listing.contents {
        for object in contents {
            let Some(raw_key) = object.key.as_deref() else {
                continue;
            };
            let trimmed = truncate_utf8(raw_key.trim_start_matches('/'), MAX_ENCODE_KEY_BYTES);
            if trimmed.is_empty() || !seen_keys.insert(trimmed.to_owned()) {
                continue;
            }
            let encoded_key = percent_encode(trimmed, false);
            let target = format!("/{}/{scope_prefix}{encoded_key}", options.bucket);
            let put_resp = send_checked(
                endpoint,
                RawRequest::put(&target, OBJECT_BODY),
                options.credentials.as_ref(),
                options.timeout,
                report,
                "PutObject(list-key)",
            )?;
            if (200..300).contains(&put_resp.status) {
                created_targets.push(target);
            }
        }
    }

    let full_prefix = format!(
        "{scope_prefix}{}",
        truncate_utf8(listing.prefix.as_deref().unwrap_or_default(), MAX_ENCODE_KEY_BYTES)
    );
    let mut base_params = vec![("list-type", "2".to_owned()), ("prefix", percent_encode(&full_prefix, true))];
    if let Some(delimiter) = listing.delimiter.as_deref().filter(|value| !value.is_empty()) {
        base_params.push(("delimiter", percent_encode(truncate_utf8(delimiter, 64), true)));
    }
    if let Some(after) = listing.start_after.as_deref().filter(|value| !value.is_empty()) {
        let scoped_after = format!("{scope_prefix}{}", truncate_utf8(after, MAX_ENCODE_KEY_BYTES));
        base_params.push(("start-after", percent_encode(&scoped_after, true)));
    }

    let mut list_result = Ok(());
    let plain_query = join_query(&base_params);
    let mut queries = vec![plain_query.clone(), format!("{plain_query}&encoding-type=url")];
    if let Some(token) = listing.continuation_token.as_deref().filter(|value| !value.is_empty()) {
        queries.push(format!(
            "{plain_query}&continuation-token={}",
            percent_encode(truncate_utf8(token, MAX_ENCODE_KEY_BYTES), true)
        ));
    }

    for query in queries {
        let target = format!("/{}?{query}", options.bucket);
        match send_checked(
            endpoint,
            RawRequest::get(&target),
            options.credentials.as_ref(),
            options.timeout,
            report,
            "ListObjectsV2",
        ) {
            Ok(resp) if resp.status == 200 => {
                if let Err(xml_err) = validate_xml_document(&resp.body) {
                    list_result = Err(format!("ListObjectsV2 {target} returned malformed XML: {xml_err}"));
                    break;
                }
            }
            Ok(_) => {}
            Err(error) => {
                list_result = Err(error);
                break;
            }
        }
    }

    for target in created_targets {
        if let Err(error) = send_checked(
            endpoint,
            RawRequest::delete(&target),
            options.credentials.as_ref(),
            options.timeout,
            report,
            "DeleteObject(cleanup)",
        ) && list_result.is_ok()
        {
            list_result = Err(error);
            break;
        }
    }

    list_result
}
