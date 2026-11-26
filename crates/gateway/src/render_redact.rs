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

//! Redaction of sensitive query parameters and signed headers inside verbose signature diagnostics.
//!
//! Responsible for: stripping credentials, session tokens, ADR-0042 bearer query tokens, presigned
//! SSE-C/KMS query parameters, and sensitive signed headers (`authorization`,
//! `proxy-authorization`, `cookie`, `set-cookie`, `x-amz-security-token`, SSE-C/KMS headers) from
//! a SigV4 canonical request before it can appear in a `verbose_signature_errors` XML body.
//! NOT responsible for: deciding whether verbose signature errors are enabled, rendering XML, or
//! zeroizing `SignatureMismatchDetail` buffers (`rustfs-gateway-sig`).
//! Upstream: `crate::render::from_auth_with_detail`. Downstream: `<CanonicalRequest>` XML element.

/// Redacts sensitive query parameters and header lines from a canonical request string.
///
/// `extra_bearer_param` is the routed operation's declared ADR-0042 `QueryBearerClaim::param()`,
/// when present, so non-default bearer parameter names are redacted alongside `token`.
pub(super) fn redact_sensitive_canonical_values(canonical_request: &str, extra_bearer_param: Option<&str>) -> String {
    canonical_request
        .lines()
        .enumerate()
        .map(|(line_number, line)| {
            if line_number == 2 {
                return redact_query_line(line, extra_bearer_param);
            }
            let Some((name, _)) = line.split_once(':') else {
                return line.to_owned();
            };
            if is_sensitive_header(name) {
                format!("{name}:__REDACTED__")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_query_line(line: &str, extra_bearer_param: Option<&str>) -> String {
    line.split('&')
        .map(|parameter| match parameter.split_once('=') {
            Some((name, _)) if is_sensitive_query_param(name, extra_bearer_param) => format!("{name}=__REDACTED__"),
            _ => parameter.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn is_sensitive_query_param(name: &str, extra_bearer_param: Option<&str>) -> bool {
    if extra_bearer_param.is_some_and(|param| name == param || name.eq_ignore_ascii_case(param)) {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "x-amz-credential"
            | "x-amz-security-token"
            | "x-amz-s3session-token"
            | "x-amz-signature"
            | "signature"
            | "awsaccesskeyid"
            | "token"
    ) || is_sensitive_sse_name(&lower)
}

fn is_sensitive_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "x-amz-security-token" | "x-amz-s3session-token" | "authorization" | "proxy-authorization" | "cookie" | "set-cookie"
    ) || is_sensitive_sse_name(&lower)
}

fn is_sensitive_sse_name(lower: &str) -> bool {
    (lower.starts_with("x-amz-server-side-encryption-") && (lower.contains("customer-key") || lower.ends_with("aws-kms-key-id")))
        || (lower.starts_with("x-amz-copy-source-server-side-encryption-") && lower.contains("customer-key"))
}

#[cfg(test)]
mod tests {
    use super::redact_sensitive_canonical_values;

    /// Negative — credentials, bearer tokens (default and declared), presigned SSE-C/KMS query
    /// keys, and sensitive signed headers (`authorization`, `proxy-authorization`, `cookie`,
    /// `set-cookie`, `x-amz-security-token`, SSE-C/KMS) must all be redacted, even with mixed-case
    /// verbatim spellings.
    #[test]
    fn n_sensitive_query_params_and_headers_are_redacted() {
        let canonical = concat!(
            "GET\n",
            "/bucket/key\n",
            "AWSAccessKeyId=AKIA123&Signature=sig2&X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key=copykey&",
            "X-Amz-Credential=cred&X-Amz-Security-Token=stoken&X-Amz-Server-Side-Encryption-AWS-KMS-Key-Id=kms1&",
            "X-Amz-Server-Side-Encryption-Customer-Key=ckey&X-Amz-Server-Side-Encryption-Customer-Key-MD5=cmd5&",
            "X-Amz-Signature=sig4&dl_token=custombearer&list-type=2&token=defaultbearer\n",
            "Authorization:AWS4-HMAC-SHA256 Secret\n",
            "Cookie:session=secret-cookie\n",
            "host:s3.example.test\n",
            "proxy-authorization:Basic c2VjcmV0\n",
            "set-cookie:sid=secret-set\n",
            "x-amz-security-token:hdr-stoken\n",
            "x-amz-server-side-encryption-customer-key:hdr-ckey\n",
            "\n",
            "authorization;cookie;host;proxy-authorization;set-cookie;x-amz-security-token;x-amz-server-side-encryption-customer-key\n",
            "UNSIGNED-PAYLOAD"
        );
        let redacted = redact_sensitive_canonical_values(canonical, Some("dl_token"));
        for secret in [
            "AKIA123",
            "sig2",
            "copykey",
            "cred",
            "stoken",
            "kms1",
            "ckey",
            "cmd5",
            "sig4",
            "custombearer",
            "defaultbearer",
            "AWS4-HMAC-SHA256 Secret",
            "session=secret-cookie",
            "Basic c2VjcmV0",
            "sid=secret-set",
            "hdr-stoken",
            "hdr-ckey",
        ] {
            assert!(!redacted.contains(secret), "secret `{secret}` survived redaction: {redacted}");
        }
        assert!(redacted.contains("list-type=2"), "non-sensitive query parameter was altered: {redacted}");
        assert!(redacted.contains("host:s3.example.test"), "non-sensitive header was altered: {redacted}");
        assert!(redacted.contains("dl_token=__REDACTED__"), "{redacted}");
        assert!(redacted.contains("token=__REDACTED__"), "{redacted}");
        assert!(redacted.contains("Cookie:__REDACTED__"), "{redacted}");
        assert!(redacted.contains("Authorization:__REDACTED__"), "{redacted}");
        assert!(redacted.contains("proxy-authorization:__REDACTED__"), "{redacted}");
        assert!(redacted.contains("set-cookie:__REDACTED__"), "{redacted}");
    }
}
