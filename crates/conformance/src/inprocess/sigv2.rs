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
//! Responsible for: turning a supported SigV2 sign specification into real header or presigned
//! requests. NOT responsible for: SigV4, POST policies, or judging the response.
//! Upstream: `super::sign_request`. Downstream: the facade SigV2 signer and host resolver.

use rustfs_gateway::sig::{RawQuery, SecurityFloor, SigV2Mode, SigV2Signer, SigV2StringToSignSpec};
use rustfs_gateway::{BucketName, EffectiveHost, HostQuery, HostResolver, ServiceBuilder, VirtualHostStyle};

use crate::sut::SutError;
use crate::value::Value;

use super::BASE_DOMAINS;

pub(super) fn configure_case(builder: ServiceBuilder, case_id: &str) -> ServiceBuilder {
    match case_id {
        "c-sig-0545" | "c-sig-0548" => builder.security_floor(SecurityFloor::new().enable_sigv2_presigned_compatibility()),
        _ => builder,
    }
}

pub(super) struct SignInput<'a> {
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

impl<'a> SignInput<'a> {
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

pub(super) fn sign_header(input: SignInput<'_>) -> Result<Vec<(String, String)>, SutError> {
    let SignInput {
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
    if sign.read("signSpec.signed_headers").is_some() {
        return Err(unsupported("sigv2_header", "an explicit signed-header set"));
    }
    if sign.read("signSpec.payload_hash").is_some() {
        return Err(unsupported("sigv2_header", "a SigV4 payload hash"));
    }
    if sign.read("signSpec.expires_s").is_some() {
        return Err(unsupported("sigv2_header", "a presigned expiry"));
    }
    if sign.read("signSpec.tamper").is_some() {
        return Err(unsupported("sigv2_header", "post-signing tampering"));
    }
    if sign.read("signSpec.service").is_some() {
        return Err(unsupported("sigv2_header", "a SigV4 service scope"));
    }
    if sign.read("signSpec.region").is_some() {
        return Err(unsupported("sigv2_header", "a SigV4 region scope"));
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

pub(super) fn sign(
    mode: &str,
    input: SignInput<'_>,
    request_time: &crate::time::Instant,
    original_target: &str,
) -> Result<(Vec<(String, String)>, String), SutError> {
    match mode {
        "sigv2_header" => Ok((sign_header(input)?, original_target.to_owned())),
        "presigned_v2" => sign_presigned(input, request_time),
        _ => Err(SutError::Environment(format!("`sign.mode = \"{mode}\"` is not SigV2"))),
    }
}

pub(super) fn sign_presigned(
    input: SignInput<'_>,
    request_time: &crate::time::Instant,
) -> Result<(Vec<(String, String)>, String), SutError> {
    let SignInput {
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
    for (path, description) in [
        ("signSpec.signed_headers", "an explicit signed-header set"),
        ("signSpec.payload_hash", "a SigV4 payload hash"),
        ("signSpec.tamper", "post-signing tampering"),
        ("signSpec.service", "a SigV4 service scope"),
        ("signSpec.region", "a SigV4 region scope"),
    ] {
        if sign.read(path).is_some() {
            return Err(unsupported("presigned_v2", description));
        }
    }
    if token.is_some() {
        return Err(unsupported("presigned_v2", "temporary credentials"));
    }
    let lifetime = sign.read("signSpec.expires_s").and_then(Value::as_integer).unwrap_or(900);
    let lifetime = u64::try_from(lifetime)
        .ok()
        .filter(|lifetime| *lifetime > 0)
        .ok_or_else(|| SutError::Environment("a SigV2 presigned expiry must be a positive duration".to_owned()))?;
    let now = u64::try_from(request_time.unix_seconds)
        .map_err(|_| SutError::Environment("a SigV2 presigned request cannot use a pre-epoch clock".to_owned()))?;
    let expires = now
        .checked_add(lifetime)
        .ok_or_else(|| SutError::Environment("the SigV2 presigned expiry overflowed".to_owned()))?;

    let mut signed_query = query.to_owned();
    append_query_pair(&mut signed_query, "AWSAccessKeyId", access_key);
    append_query_pair(&mut signed_query, "Expires", &expires.to_string());
    let resolver = VirtualHostStyle::new(BASE_DOMAINS)
        .map_err(|error| SutError::Environment(format!("the base domains are not usable: {error}")))?;
    let resolved = resolver.resolve(&HostQuery { host, path, method });
    let raw_query = RawQuery::new(&signed_query);
    let spec = SigV2StringToSignSpec::new(
        SigV2Mode::PresignedUrl,
        method,
        path,
        &raw_query,
        headers,
        resolved.bucket().map(BucketName::as_str),
    );
    let signature = SigV2Signer::new(access_key, secret)
        .and_then(|signer| signer.presigned_signature(&spec))
        .map_err(|error| SutError::Environment(format!("the SigV2 request could not be presigned: {error}")))?;
    append_query_pair(&mut signed_query, "Signature", &encode_base64_query_value(&signature));
    let signed_headers = headers
        .iter()
        .map(|(name, value)| {
            value
                .to_str()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
                .map_err(|_| SutError::Environment(format!("`{name}` is not a text header value")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((signed_headers, super::rebuild_target(path, &signed_query)))
}

fn append_query_pair(query: &mut String, name: &str, value: &str) {
    if !query.is_empty() {
        query.push('&');
    }
    query.push_str(name);
    query.push('=');
    query.push_str(value);
}

fn encode_base64_query_value(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'+' => encoded.push_str("%2B"),
            b'/' => encoded.push_str("%2F"),
            b'=' => encoded.push_str("%3D"),
            _ => encoded.push(char::from(byte)),
        }
    }
    encoded
}

fn unsupported(mode: &str, description: &str) -> SutError {
    SutError::Environment(format!("`sign.mode = \"{mode}\"` does not support {description}"))
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

    #[test]
    fn a_sigv2_presigned_mode_builds_an_absolute_expiry_query() {
        let sign = Value::Table(vec![
            ("mode".to_owned(), Value::String("presigned_v2".to_owned())),
            ("expires_s".to_owned(), Value::Integer(60)),
        ]);
        let wire = Wire {
            method: "GET".to_owned(),
            target: "/conf-sig?foo=1".to_owned(),
            headers: Vec::new(),
            raw_head: None,
            h2_frames: false,
            http_version: None,
            body: Vec::new(),
            frames: Vec::new(),
            steps: Vec::new(),
            sign: Some(sign.clone()),
        };
        let headers = vec![("host".to_owned(), HOST.to_owned())];
        let request_time = time::parse_rfc3339(time::DEFAULT_FIXED).expect("the pinned fixture time");
        let target = InProcess::new(PathBuf::from("."));

        let (_, request_target) =
            sign_request(&sign, &wire, &headers, &request_time, target.limits(), 0).expect("SigV2 presigning must be wired");

        assert!(request_target.contains("AWSAccessKeyId="));
        assert!(request_target.contains("Expires=1767323105"));
        assert!(request_target.contains("Signature="));
        assert!(request_target.contains("foo=1"));
    }
}
