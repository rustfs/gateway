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

//! Native AWS REST-JSON error rendering for non-S3 services such as S3 Vectors.
//!
//! Responsible for: [`ErrorFormat`], [`AMZN_ERROR_TYPE_HEADER`], [`render_for_format`],
//! [`render_rest_json`], and RFC 8259 JSON error document serialisation without external crates.
//! NOT responsible for: S3 XML rendering (`super::render`), choosing error codes or statuses
//! (`rustfs-gateway-core`), or request trace minting (`crate::trace`).
//! Upstream: `super::S3Error`, `crate::trace::RequestTrace`, `rustfs_gateway_sig::SigService`.
//! Downstream: `crate::service::outcome`, `crate::stamp`.

use http::Response;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, ETAG, HeaderName, HeaderValue};
use rustfs_gateway_core::BodyPolicy;
use rustfs_gateway_sig::SigService;
use rustfs_gateway_stream::Body;
use rustfs_gateway_types::EtagRender;

use super::{S3Error, render};
use crate::trace::RequestTrace;

/// The AWS REST-JSON error code header (`x-amzn-errortype`).
pub(crate) const AMZN_ERROR_TYPE_HEADER: HeaderName = HeaderName::from_static("x-amzn-errortype");

/// Wire format for rendered gateway refusals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum ErrorFormat {
    /// S3 XML (`application/xml`, `<Error>...</Error>`).
    #[default]
    S3Xml,
    /// AWS REST-JSON (`application/json`, `x-amzn-errortype`, `{"message":"..."}`).
    RestJson,
}

impl ErrorFormat {
    /// Selects the wire error format for an assembled signing service.
    pub(crate) const fn for_service(service: Option<SigService>) -> Self {
        match service {
            Some(SigService::S3Vectors) => Self::RestJson,
            _ => Self::S3Xml,
        }
    }
}

/// Renders `error` in the assembly's wire format (`S3Xml` or `RestJson`).
pub(crate) fn render_for_format(error: &S3Error, trace: &RequestTrace, format: ErrorFormat) -> Response<Body> {
    match format {
        ErrorFormat::S3Xml => render(error, trace),
        ErrorFormat::RestJson => render_rest_json(error, trace),
    }
}

/// Renders an AWS REST-JSON error response and retains `S3Error` and connection intent extensions.
pub(crate) fn render_rest_json(error: &S3Error, trace: &RequestTrace) -> Response<Body> {
    let body = match error.body_policy {
        BodyPolicy::None => None,
        BodyPolicy::ErrorDocument => Some(json_document(error)),
    };
    let mut response = Response::new(match body {
        Some(ref body) => Body::from(body.clone().into_bytes()),
        None => Body::empty(),
    });
    *response.status_mut() = error.status;
    let headers = response.headers_mut();
    for header in error.headers() {
        let name = header.name();
        if crate::stamp::is_reserved(&name) {
            continue;
        }
        if let Ok(value) = HeaderValue::from_str(&header.value()) {
            headers.insert(name, value);
        }
    }
    if let Some(code) = &error.code
        && let Ok(value) = HeaderValue::from_str(code.as_str())
    {
        headers.insert(AMZN_ERROR_TYPE_HEADER, value);
    }
    if let Some(body) = body {
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Ok(value) = HeaderValue::from_str(&body.len().to_string()) {
            headers.insert(CONTENT_LENGTH, value);
        }
    }
    if let Some(etag) = &error.etag
        && let Ok(value) = HeaderValue::from_str(&etag.render(EtagRender::HeaderQuoted))
    {
        headers.insert(ETAG, value);
    }
    trace.apply(headers);
    response.extensions_mut().insert(error.clone());
    response.extensions_mut().insert(error.connection);
    crate::close::attach_lingering_read(error.code.as_ref(), error.body_unfinished, &mut response);
    response
}

/// Serialises `error` into an RFC 8259 JSON object (`{"message":"..."}` or `{}`).
pub(crate) fn json_document(error: &S3Error) -> String {
    let Some(message) = error.message() else {
        return "{}".to_owned();
    };
    let mut out = String::with_capacity(message.len().saturating_add(16));
    out.push_str(r#"{"message":""#);
    write_json_escaped(message, &mut out);
    out.push_str(r#""}"#);
    out
}

/// Appends `text` escaped according to RFC 8259 §7 string escaping rules.
fn write_json_escaped(text: &str, out: &mut String) {
    const HEX: [char; 16] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
    for ch in text.chars() {
        match ch {
            '"' => out.push_str(r#"\""#),
            '\\' => out.push_str(r#"\\"#),
            '\u{08}' => out.push_str(r"\b"),
            '\u{0C}' => out.push_str(r"\f"),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            ch if (ch as u32) < 0x20 => {
                let byte = ch as u32;
                let high = usize::try_from((byte >> 4) & 0x0F).unwrap_or(0);
                let low = usize::try_from(byte & 0x0F).unwrap_or(0);
                out.push_str(r"\u00");
                out.push(HEX.get(high).copied().unwrap_or('0'));
                out.push(HEX.get(low).copied().unwrap_or('0'));
            }
            ch => out.push(ch),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::close::ConnectionIntent;
    use crate::render::from_handler;
    use http::StatusCode;
    use rustfs_gateway_core::{HandlerError, ResponseKind};
    use rustfs_gateway_types::ErrorCode;

    fn trace() -> RequestTrace {
        RequestTrace::from_bits(0x0123_4567_89AB_CDEF, 0xAAAA)
    }

    #[test]
    fn error_format_selects_rest_json_only_for_s3vectors() {
        assert_eq!(ErrorFormat::for_service(Some(SigService::S3Vectors)), ErrorFormat::RestJson);
        assert_eq!(ErrorFormat::for_service(None), ErrorFormat::S3Xml);
        assert_eq!(ErrorFormat::for_service(Some(SigService::S3)), ErrorFormat::S3Xml);
        assert_eq!(ErrorFormat::for_service(Some(SigService::S3Express)), ErrorFormat::S3Xml);
    }

    #[test]
    fn json_document_escapes_rfc8259_control_and_delimiter_characters() {
        let mut escaped = String::new();
        write_json_escaped("bad \"quote\" \\ slash \n\r\t\u{08}\u{0C}\u{00}\u{1F}", &mut escaped);
        assert_eq!(escaped, r#"bad \"quote\" \\ slash \n\r\t\b\f\u0000\u001f"#);

        let err = from_handler(
            HandlerError::new(
                ErrorCode::custom("ValidationException", StatusCode::BAD_REQUEST),
                "bad \"quote\" \\ slash \n\r\t",
            ),
            ResponseKind::Other,
            ConnectionIntent::MayKeepAlive,
        );
        assert_eq!(json_document(&err), r#"{"message":"bad \"quote\" \\ slash \n\r\t"}"#);
    }

    #[tokio::test]
    async fn n_rest_json_response_never_emits_xml_and_retains_typed_extensions() {
        let err = from_handler(
            HandlerError::new(ErrorCode::custom("ConflictException", StatusCode::CONFLICT), "already exists"),
            ResponseKind::Other,
            ConnectionIntent::Close,
        );
        let response = render_for_format(&err, &trace(), ErrorFormat::RestJson);
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            response.headers().get(AMZN_ERROR_TYPE_HEADER).and_then(|v| v.to_str().ok()),
            Some("ConflictException")
        );
        assert_eq!(response.extensions().get::<S3Error>(), Some(&err));
        assert_eq!(response.extensions().get::<ConnectionIntent>(), Some(&ConnectionIntent::Close));
        let wire = crate::wire::collect(response).await.expect("collected");
        let body = String::from_utf8(wire.body().to_vec()).expect("utf8");
        assert_eq!(body, r#"{"message":"already exists"}"#);
        assert!(!body.contains("<Error"));
    }

    #[tokio::test]
    async fn n_bodyless_rest_json_error_omits_body_and_content_type_and_handles_missing_message() {
        let etag = rustfs_gateway_types::ETag::new("abc").expect("etag");
        let err = crate::render::from_resolution(
            rustfs_gateway_core::resolve(rustfs_gateway_core::ErrorContext::not_modified(etag), ResponseKind::Other),
            ResponseKind::Other,
        );
        assert_eq!(json_document(&err), "{}");
        let response = render_for_format(&err, &trace(), ErrorFormat::RestJson);
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert!(!response.headers().contains_key(CONTENT_TYPE));
        assert!(!response.headers().contains_key(CONTENT_LENGTH));
        let wire = crate::wire::collect(response).await.expect("collected");
        assert!(wire.body().is_empty());
    }
}
