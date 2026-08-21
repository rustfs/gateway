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

//! SigV2 client signing for the in-process conformance transport.
//!
//! Responsible for: turning a supported SigV2 sign specification into real request headers.
//! NOT responsible for: SigV4, presigned SigV2, POST policies, or judging the response.
//! Upstream: `super::sign_request`. Downstream: the facade SigV2 signer and host resolver.

use rustfs_gateway::sig::{RawQuery, SigV2Mode, SigV2Signer, SigV2StringToSignSpec};
use rustfs_gateway::{BucketName, EffectiveHost, HostQuery, HostResolver, VirtualHostStyle};

use crate::sut::SutError;
use crate::value::Value;

use super::BASE_DOMAINS;

pub(super) struct HeaderSignInput<'a> {
    sign: &'a Value,
    method: &'a http::Method,
    path: &'a str,
    query: &'a str,
    headers: &'a mut http::HeaderMap,
    host: &'a EffectiveHost,
    access_key: &'a str,
    secret: &'a [u8],
    token: Option<&'a str>,
}

impl<'a> HeaderSignInput<'a> {
    pub(super) fn new(
        sign: &'a Value,
        method: &'a http::Method,
        path: &'a str,
        query: &'a str,
        headers: &'a mut http::HeaderMap,
        host: &'a EffectiveHost,
        credentials: (&'a str, &'a [u8], Option<&'a str>),
    ) -> Self {
        let (access_key, secret, token) = credentials;
        Self {
            sign,
            method,
            path,
            query,
            headers,
            host,
            access_key,
            secret,
            token,
        }
    }
}

pub(super) fn sign_header(input: HeaderSignInput<'_>) -> Result<Vec<(String, String)>, SutError> {
    let HeaderSignInput {
        sign,
        method,
        path,
        query,
        headers,
        host,
        access_key,
        secret,
        token,
    } = input;
    for (key, description) in [
        ("signSpec.signed_headers", "an explicit signed-header set"),
        ("signSpec.payload_hash", "a SigV4 payload hash"),
        ("signSpec.expires_s", "a presigned expiry"),
        ("signSpec.tamper", "post-signing tampering"),
        ("signSpec.service", "a SigV4 service scope"),
        ("signSpec.region", "a SigV4 region scope"),
    ] {
        if sign.read(key).is_some() {
            return Err(SutError::Environment(format!(
                "`sign.mode = \"sigv2_header\"` does not support {description}"
            )));
        }
    }
    if let Some(token) = token {
        let value = http::HeaderValue::from_str(token)
            .map_err(|_| SutError::Environment("the fixture session token is not a header value".to_owned()))?;
        headers.append(rustfs_gateway::sig::X_AMZ_SECURITY_TOKEN_HEADER, value);
    }
    let resolver = VirtualHostStyle::new(BASE_DOMAINS)
        .map_err(|error| SutError::Environment(format!("the base domains are not usable: {error}")))?;
    let resolved = resolver.resolve(&HostQuery { host, path, method });
    let raw_query = RawQuery::new(query);
    let spec = SigV2StringToSignSpec::new(
        SigV2Mode::HeaderAuth,
        method,
        path,
        &raw_query,
        headers,
        resolved.bucket().map(BucketName::as_str),
    );
    let authorization = SigV2Signer::new(access_key, secret)
        .and_then(|signer| signer.authorization(&spec))
        .map_err(|error| SutError::Environment(format!("the SigV2 request could not be signed: {error}")))?;
    let value = http::HeaderValue::from_str(&authorization)
        .map_err(|_| SutError::Environment("the SigV2 authorization value is not a header value".to_owned()))?;
    headers.append(http::header::AUTHORIZATION, value);
    headers
        .iter()
        .map(|(name, value)| {
            value
                .to_str()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
                .map_err(|_| SutError::Environment(format!("`{name}` is not a text header value")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::inprocess::{HOST, InProcess, Wire, sign_request};
    use crate::{time, value::Value};

    #[test]
    fn a_sigv2_header_mode_builds_the_legacy_authorization_value() {
        let sign = Value::Table(vec![("mode".to_owned(), Value::String("sigv2_header".to_owned()))]);
        let wire = Wire {
            method: "GET".to_owned(),
            target: "/conf-sig?acl".to_owned(),
            headers: Vec::new(),
            raw_head: None,
            h2_frames: false,
            http_version: None,
            body: Vec::new(),
            frames: Vec::new(),
            steps: Vec::new(),
            sign: Some(sign.clone()),
        };
        let headers = vec![
            ("host".to_owned(), HOST.to_owned()),
            ("date".to_owned(), "Fri, 02 Jan 2026 03:04:05 GMT".to_owned()),
        ];
        let request_time = time::parse_rfc3339(time::DEFAULT_FIXED).expect("the pinned fixture time");
        let target = InProcess::new(PathBuf::from("."));

        let (signed, request_target) =
            sign_request(&sign, &wire, &headers, &request_time, target.limits(), 0).expect("SigV2 header signing must be wired");

        assert_eq!(request_target, wire.target);
        assert!(
            signed
                .iter()
                .any(|(name, value)| name == "authorization" && value.starts_with("AWS "))
        );
    }
}
