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

//! The STS parity matrix's requests: one `POST` and every way it is signed.
//!
//! Responsible for: [`Sent`] and [`Signing`] — host, path, query, media type and body, unsigned,
//! SigV4-signed by a hand-written signer over any service and payload digest (with or without the
//! digest header), SigV4-presigned and SigV2-signed by the signature crate's client signers, with
//! the shared secret or a forged one.
//! NOT responsible for: sending them or comparing the answers (`super`).
//! Upstream: the signature crate's client signers and `super`'s constants. Downstream: `super`.

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request};
use rustfs_gateway_http::RawHost;
use rustfs_gateway_sig::{
    AmzDate, PayloadMode, RawQuery, RequestNow, SigService, SigV2Mode, SigV2Signer, SigV2StringToSignSpec, SigV4Signer,
    SigningCredentials, SigningRequest, SigningScope,
};
use sha2::{Digest as _, Sha256};

use super::super::context::{ACCESS_KEY, SECRET_KEY, amz_date};
use super::{FORM, PATH_HOST, REGION};

/// How a request is signed.
#[derive(Clone, Copy, Debug)]
pub(super) enum Signing {
    /// No credentials at all.
    Anonymous,
    /// A SigV4 header signature under `service`, over the body's digest, sending that digest in
    /// `x-amz-content-sha256` or not; with `secret`.
    Header {
        service: &'static str,
        send_digest: bool,
        secret: &'static str,
    },
    /// A SigV4 header signature over `UNSIGNED-PAYLOAD`.
    HeaderUnsigned { service: &'static str },
    /// A SigV4 presigned URL under `service`, with `secret`.
    Presigned { service: SigService, secret: &'static str },
    /// A SigV2 header signature, with `secret`.
    V2Header { secret: &'static str },
    /// A SigV2 presigned URL.
    V2Presigned,
    /// A SigV4 header signature naming an access key no store holds.
    UnknownKey,
}

/// One `POST` as it goes on the wire.
#[derive(Clone, Debug)]
pub(super) struct Sent {
    host: &'static str,
    path: &'static str,
    query: &'static str,
    content_type: Option<&'static str>,
    pub(super) body: Bytes,
    signing: Signing,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    inner.update(data);
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// The query in SigV4 canonical form: every pair `key=value`, sorted. The fixtures use no byte a
/// canonical query would escape.
fn canonical_query(query: &str) -> String {
    let mut pairs: Vec<String> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            if pair.contains('=') {
                pair.to_owned()
            } else {
                format!("{pair}=")
            }
        })
        .collect();
    pairs.sort();
    pairs.join("&")
}

impl Sent {
    pub(super) fn new(signing: Signing) -> Self {
        Self {
            host: PATH_HOST,
            path: "/",
            query: "",
            content_type: Some(FORM),
            body: Bytes::from_static(b"Action=AssumeRole&Version=2011-06-15&DurationSeconds=900"),
            signing,
        }
    }

    pub(super) fn host(mut self, host: &'static str) -> Self {
        self.host = host;
        self
    }

    pub(super) fn path(mut self, path: &'static str) -> Self {
        self.path = path;
        self
    }

    pub(super) fn query(mut self, query: &'static str) -> Self {
        self.query = query;
        self
    }

    pub(super) fn content_type(mut self, content_type: Option<&'static str>) -> Self {
        self.content_type = content_type;
        self
    }

    pub(super) fn body(mut self, body: Bytes) -> Self {
        self.body = body;
        self
    }

    fn target(&self, query: &str) -> String {
        if query.is_empty() {
            self.path.to_owned()
        } else {
            format!("{}?{query}", self.path)
        }
    }

    /// The request, signed at `now`.
    pub(super) fn request(&self, now: RequestNow) -> Request<Bytes> {
        let stamp = amz_date(now.unix_seconds());
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, HeaderValue::from_static(self.host));
        if let Some(content_type) = self.content_type {
            headers.insert(http::header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        }
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(self.body.len()));
        let mut query = self.query.to_owned();
        match self.signing {
            Signing::Anonymous => {}
            Signing::Header {
                service,
                send_digest,
                secret,
            } => self.sign_header(&mut headers, &stamp, service, &sha256_hex(&self.body), send_digest, ACCESS_KEY, secret),
            Signing::HeaderUnsigned { service } => {
                self.sign_header(&mut headers, &stamp, service, "UNSIGNED-PAYLOAD", true, ACCESS_KEY, SECRET_KEY);
            }
            Signing::UnknownKey => {
                let digest = sha256_hex(&self.body);
                self.sign_header(&mut headers, &stamp, "sts", &digest, true, "AKIDNOSUCHKEY", SECRET_KEY);
            }
            Signing::Presigned { service, secret } => query = self.presign(&headers, &stamp, service, secret),
            Signing::V2Header { secret } => self.sign_v2_header(&mut headers, now, secret),
            Signing::V2Presigned => query = self.presign_v2(&headers, now),
        }
        let mut builder = Request::builder().method(Method::POST).uri(self.target(&query));
        for (name, value) in &headers {
            builder = builder.header(name, value);
        }
        builder.body(self.body.clone()).expect("a fixture request")
    }

    #[allow(clippy::too_many_arguments)] // One hand signer for every header form the matrix sends.
    fn sign_header(
        &self,
        headers: &mut HeaderMap,
        stamp: &str,
        service: &str,
        payload: &str,
        send_digest: bool,
        access_key: &str,
        secret: &str,
    ) {
        let day = &stamp[..8];
        headers.insert("x-amz-date", HeaderValue::from_str(stamp).expect("a stamp"));
        if send_digest {
            headers.insert("x-amz-content-sha256", HeaderValue::from_str(payload).expect("a digest"));
        }
        let mut signed: Vec<(String, String)> = headers
            .iter()
            .filter(|(name, _)| name.as_str() != "content-length")
            .map(|(name, value)| (name.as_str().to_owned(), value.to_str().expect("text").trim().to_owned()))
            .collect();
        signed.sort();
        let names = signed.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>().join(";");
        let lines: String = signed.iter().map(|(name, value)| format!("{name}:{value}\n")).collect();
        let canonical = format!("POST\n{}\n{}\n{lines}\n{names}\n{payload}", self.path, canonical_query(self.query));
        let scope = format!("{day}/{REGION}/{service}/aws4_request");
        let string_to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", sha256_hex(canonical.as_bytes()));
        let mut key = hmac(format!("AWS4{secret}").as_bytes(), day.as_bytes());
        for part in [REGION, service, "aws4_request"] {
            key = hmac(&key, part.as_bytes());
        }
        let signature = hex::encode(hmac(&key, string_to_sign.as_bytes()));
        let authorization =
            format!("AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={names}, Signature={signature}");
        headers.insert(http::header::AUTHORIZATION, HeaderValue::from_str(&authorization).expect("text"));
    }

    fn presign(&self, headers: &HeaderMap, stamp: &str, service: SigService, secret: &str) -> String {
        let stamp = AmzDate::parse(stamp).expect("a stamp");
        let scope = SigningScope::new(stamp.day(), REGION, service).expect("a scope");
        let credentials = SigningCredentials::new(ACCESS_KEY, secret.as_bytes()).expect("credentials");
        let mut signer = SigV4Signer::new(credentials, scope);
        let host = RawHost::from_host_header(self.host.as_bytes()).expect("a host");
        let mut host_only = HeaderMap::new();
        host_only.insert(http::header::HOST, headers[http::header::HOST].clone());
        let signing = SigningRequest::new(&Method::POST, self.path, self.query, &host_only, &host, PayloadMode::Unsigned, stamp);
        signer
            .presign(&signing, 900)
            .expect("a presignable request")
            .query()
            .to_owned()
    }

    fn sign_v2_header(&self, headers: &mut HeaderMap, now: RequestNow, secret: &str) {
        let date = httpdate(now);
        headers.insert(http::header::DATE, HeaderValue::from_str(&date).expect("a date"));
        let raw = RawQuery::new(self.query);
        let bucket = self.vhost_bucket();
        let spec = SigV2StringToSignSpec::new(SigV2Mode::HeaderAuth, &Method::POST, self.path, &raw, headers, bucket);
        let authorization = SigV2Signer::new(ACCESS_KEY, secret.as_bytes())
            .expect("a signer")
            .authorization(&spec)
            .expect("a signable request");
        headers.insert(http::header::AUTHORIZATION, HeaderValue::from_str(&authorization).expect("text"));
    }

    fn presign_v2(&self, headers: &HeaderMap, now: RequestNow) -> String {
        let expires = now.unix_seconds() + 900;
        let query = if self.query.is_empty() {
            format!("AWSAccessKeyId={ACCESS_KEY}&Expires={expires}")
        } else {
            format!("{}&AWSAccessKeyId={ACCESS_KEY}&Expires={expires}", self.query)
        };
        let raw = RawQuery::new(&query);
        let spec =
            SigV2StringToSignSpec::new(SigV2Mode::PresignedUrl, &Method::POST, self.path, &raw, headers, self.vhost_bucket());
        let signature = SigV2Signer::new(ACCESS_KEY, SECRET_KEY.as_bytes())
            .expect("a signer")
            .presigned_signature(&spec)
            .expect("a signable request");
        let escaped: String = signature
            .bytes()
            .map(|byte| match byte {
                b'+' => "%2B".to_owned(),
                b'/' => "%2F".to_owned(),
                b'=' => "%3D".to_owned(),
                other => char::from(other).to_string(),
            })
            .collect();
        format!("{query}&Signature={escaped}")
    }

    fn vhost_bucket(&self) -> Option<&'static str> {
        self.host.strip_suffix(".example.test")
    }
}

/// `now` as an RFC 1123 date, the spelling SigV2's `Date` header carries: the civil date from the
/// day count, 1970-01-01 being a Thursday.
fn httpdate(now: RequestNow) -> String {
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let seconds = now.unix_seconds();
    let (days, of_day) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{}, {day:02} {} {year:04} {:02}:{:02}:{:02} GMT",
        WEEKDAYS[usize::try_from(days.rem_euclid(7)).expect("a weekday")],
        MONTHS[usize::try_from(month - 1).expect("a month")],
        of_day / 3600,
        of_day % 3600 / 60,
        of_day % 60
    )
}
