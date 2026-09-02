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

//! External HTTP(S) endpoint syntax, resolution, and transport selection.
//!
//! Responsible for: validating one authority-only endpoint, selecting its default port, resolving
//! its socket address, and binding HTTPS to verified TLS state. NOT responsible for: opening the
//! socket, HTTP framing, or judging observations. Upstream: `external`; downstream: `external_tls`.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;

use super::external_tls::ExternalTransport;
use crate::socket::Connection;
use crate::sut::SutError;

/// A resolved endpoint and the authority that must appear in `Host`.
#[derive(Clone, Debug)]
pub(super) struct ExternalEndpoint {
    authority: String,
    address: SocketAddr,
    transport: ExternalTransport,
}

impl ExternalEndpoint {
    #[cfg(test)]
    pub(super) fn parse(text: &str) -> Result<Self, SutError> {
        Self::parse_with_ca(text, None)
    }

    pub(super) fn parse_with_ca(text: &str, ca_path: Option<&Path>) -> Result<Self, SutError> {
        let (authority, secure, default_port) = if let Some(authority) = text.strip_prefix("http://") {
            (authority, false, 80)
        } else if let Some(authority) = text.strip_prefix("https://") {
            (authority, true, 443)
        } else {
            return Err(SutError::Environment(
                "external endpoint must be an absolute `http://` or `https://` URL".to_owned(),
            ));
        };
        let authority = authority.strip_suffix('/').unwrap_or(authority);
        validate_authority(authority)?;
        let transport = ExternalTransport::new(authority, secure, ca_path)?;
        let socket_authority = socket_authority(authority, default_port)?;
        let address = socket_authority
            .to_socket_addrs()
            .map_err(|error| SutError::Environment(format!("external endpoint `{authority}` could not be resolved: {error}")))?
            .next()
            .ok_or_else(|| SutError::Environment(format!("external endpoint `{authority}` resolved to no addresses")))?;
        Ok(Self {
            authority: authority.to_owned(),
            address,
            transport,
        })
    }

    pub(super) fn authority(&self) -> &str {
        &self.authority
    }

    #[cfg(test)]
    pub(super) const fn address(&self) -> SocketAddr {
        self.address
    }

    pub(super) fn open(&self) -> Result<Connection, SutError> {
        self.transport.open(self.address)
    }

    pub(super) const fn is_tls(&self) -> bool {
        self.transport.is_tls()
    }

    pub(super) fn description(&self) -> String {
        let wire = if self.is_tls() { "verified TLS" } else { "raw TCP" };
        format!("external HTTP/1.1 endpoint at {} over {wire}", self.authority)
    }
}

fn validate_authority(authority: &str) -> Result<(), SutError> {
    if authority.is_empty() {
        return Err(SutError::Environment("external endpoint has no authority".to_owned()));
    }
    if authority.contains(['/', '?', '#']) {
        return Err(SutError::Environment(
            "external endpoint must not contain a path, query, or fragment".to_owned(),
        ));
    }
    if authority.contains('@') {
        return Err(SutError::Environment("external endpoint must not contain user information".to_owned()));
    }
    Ok(())
}

fn socket_authority(authority: &str, default_port: u16) -> Result<String, SutError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| SutError::Environment("external endpoint has an unterminated IPv6 address".to_owned()))?;
        let suffix = &rest[close + 1..];
        return match suffix {
            "" => Ok(format!("{authority}:{default_port}")),
            suffix if suffix.starts_with(':') && suffix.len() > 1 => Ok(authority.to_owned()),
            _ => Err(SutError::Environment(
                "external endpoint has invalid text after its IPv6 address".to_owned(),
            )),
        };
    }
    match authority.matches(':').count() {
        0 => Ok(format!("{authority}:{default_port}")),
        1 => Ok(authority.to_owned()),
        _ => Err(SutError::Environment(
            "an IPv6 external endpoint must enclose its address in brackets".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cleartext_authority_and_preserves_host() {
        let endpoint = ExternalEndpoint::parse("http://127.0.0.1:9000").expect("valid endpoint");

        assert_eq!(endpoint.authority(), "127.0.0.1:9000");
        assert_eq!(endpoint.address().port(), 9000);
    }

    #[test]
    fn rejects_endpoint_paths_instead_of_discarding_them() {
        let error = ExternalEndpoint::parse("http://s3.example.test/prefix").expect_err("paths are unsupported");

        assert!(error.to_string().contains("path"));
    }
}
