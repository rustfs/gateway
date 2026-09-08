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
//! every socket address within an absolute setup deadline, and trying each transport address.
//! Not responsible for: HTTP framing or judging observations. Upstream: `external`; downstream:
//! `external_tls`.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Instant;

use super::external_tls::ExternalTransport;
use crate::socket::Connection;
use crate::sut::SutError;

/// An endpoint and the authority that must appear in `Host`.
#[derive(Clone, Debug)]
pub(super) struct ExternalEndpoint {
    authority: String,
    socket_authority: String,
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
        Ok(Self {
            authority: authority.to_owned(),
            socket_authority,
            transport,
        })
    }

    pub(super) fn authority(&self) -> &str {
        &self.authority
    }

    #[cfg(test)]
    pub(super) fn socket_authority(&self) -> &str {
        &self.socket_authority
    }

    pub(super) fn open(&self, deadline: Instant) -> Result<Connection, SutError> {
        self.open_with(
            deadline,
            |authority| authority.to_socket_addrs().map(|resolved| resolved.collect()),
            |transport, address, attempt_deadline| transport.open(address, attempt_deadline),
        )
    }

    fn open_with<R, C>(&self, deadline: Instant, resolver: R, mut connector: C) -> Result<Connection, SutError>
    where
        R: FnOnce(String) -> std::io::Result<Vec<SocketAddr>> + Send + 'static,
        C: FnMut(&ExternalTransport, SocketAddr, Instant) -> Result<Connection, SutError>,
    {
        let addresses = resolve_with_deadline(self.socket_authority.clone(), deadline, resolver)?;
        if addresses.is_empty() {
            return Err(SutError::Environment(format!(
                "external endpoint `{}` resolved to no addresses",
                self.authority
            )));
        }
        let address_count = addresses.len();
        let mut attempted = 0_usize;
        let mut last_error = None;
        for (index, address) in addresses.into_iter().enumerate() {
            let now = Instant::now();
            let Some(remaining) = deadline.checked_duration_since(now).filter(|duration| !duration.is_zero()) else {
                break;
            };
            let attempts_left = address_count.saturating_sub(index).max(1) as u32;
            let attempt_deadline = now.checked_add(remaining / attempts_left).unwrap_or(deadline).min(deadline);
            attempted = attempted.saturating_add(1);
            match connector(&self.transport, address, attempt_deadline) {
                Ok(connection) => return Ok(connection),
                Err(error) => last_error = Some(error),
            }
        }
        if Instant::now() >= deadline {
            return Err(SutError::Environment(format!(
                "external endpoint `{}` exhausted its setup deadline after {attempted} address attempt(s)",
                self.authority
            )));
        }
        let detail = last_error.map_or_else(|| "no address was attempted".to_owned(), |error| error.to_string());
        Err(SutError::Environment(format!(
            "external endpoint `{}` could not connect to any of its {attempted} attempted address(es): {detail}",
            self.authority
        )))
    }

    pub(super) const fn is_tls(&self) -> bool {
        self.transport.is_tls()
    }

    pub(super) fn description(&self) -> String {
        let wire = if self.is_tls() { "verified TLS" } else { "raw TCP" };
        format!("external HTTP/1.1 endpoint at {} over {wire}", self.authority)
    }
}

fn resolve_with_deadline<F>(socket_authority: String, deadline: Instant, resolver: F) -> Result<Vec<SocketAddr>, SutError>
where
    F: FnOnce(String) -> std::io::Result<Vec<SocketAddr>> + Send + 'static,
{
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| SutError::Environment("external endpoint setup deadline expired before DNS resolution".to_owned()))?;
    let diagnostic = socket_authority.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("gateway-external-dns".to_owned())
        .spawn(move || {
            let _ = sender.send(resolver(socket_authority));
        })
        .map_err(|error| SutError::Environment(format!("cannot start DNS resolution for `{diagnostic}`: {error}")))?;
    match receiver.recv_timeout(remaining) {
        Ok(Ok(addresses)) => Ok(addresses),
        Ok(Err(error)) => Err(SutError::Environment(format!(
            "external endpoint `{diagnostic}` could not be resolved: {error}"
        ))),
        Err(RecvTimeoutError::Timeout) => Err(SutError::Environment(format!(
            "external endpoint `{diagnostic}` DNS resolution exceeded the setup deadline"
        ))),
        Err(RecvTimeoutError::Disconnected) => Err(SutError::Environment(format!(
            "external endpoint `{diagnostic}` DNS resolver ended without a result"
        ))),
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
    use std::net::TcpListener;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn parses_cleartext_authority_and_preserves_host() {
        let endpoint = ExternalEndpoint::parse("http://127.0.0.1:9000").expect("valid endpoint");

        assert_eq!(endpoint.authority(), "127.0.0.1:9000");
        assert_eq!(endpoint.socket_authority(), "127.0.0.1:9000");
    }

    #[test]
    fn rejects_endpoint_paths_instead_of_discarding_them() {
        let error = ExternalEndpoint::parse("http://s3.example.test/prefix").expect_err("paths are unsupported");

        assert!(error.to_string().contains("path"));
    }

    #[test]
    fn falls_back_after_the_first_resolved_address_exhausts_its_share() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind IPv4 fallback listener");
        listener.set_nonblocking(true).expect("bound accept observation");
        let port = listener.local_addr().expect("listener address").port();
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(500);
            loop {
                match listener.accept() {
                    Ok(_) => return true,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return false,
                    Err(error) => panic!("accept fallback connection: {error}"),
                }
            }
        });
        let endpoint = ExternalEndpoint::parse(&format!("http://fallback.invalid:{port}")).expect("valid endpoint syntax");
        let first = SocketAddr::from(([192, 0, 2, 1], port));
        let second = SocketAddr::from(([127, 0, 0, 1], port));
        let mut attempts = Vec::new();

        let opened = endpoint.open_with(
            Instant::now() + Duration::from_millis(200),
            move |_| Ok(vec![first, second]),
            |transport, address, attempt_deadline| {
                attempts.push(address);
                if address == first {
                    if let Some(delay) = attempt_deadline.checked_duration_since(Instant::now()) {
                        thread::sleep(delay);
                    }
                    return Err(SutError::Environment("scripted first-address timeout".to_owned()));
                }
                transport.open(address, attempt_deadline)
            },
        );
        let accepted = server.join().expect("fallback server exits");

        assert!(opened.is_ok(), "a stalled first address must not hide a reachable fallback");
        assert_eq!(attempts, vec![first, second], "resolved addresses are attempted in order");
        assert!(accepted, "the reachable IPv4 fallback was attempted");
    }

    #[test]
    fn a_stalled_resolver_returns_at_the_absolute_setup_deadline() {
        let started = Instant::now();
        let deadline = started + Duration::from_millis(25);

        let error = resolve_with_deadline("stalled.example:443".to_owned(), deadline, |_| {
            thread::sleep(Duration::from_millis(200));
            Ok(Vec::new())
        })
        .expect_err("a resolver may not hold the case past its setup deadline");
        let elapsed = started.elapsed();

        assert!(error.to_string().contains("DNS resolution exceeded the setup deadline"));
        assert!(elapsed >= Duration::from_millis(25));
        assert!(elapsed < Duration::from_millis(100), "resolver timeout was not bounded: {elapsed:?}");
    }

    #[test]
    fn dns_time_is_not_granted_again_to_a_stalled_tls_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind silent TLS peer");
        let address = listener.local_addr().expect("silent TLS address");
        let server = thread::spawn(move || {
            let (_socket, _) = listener.accept().expect("accept TLS client");
            thread::sleep(Duration::from_millis(250));
        });
        let endpoint = ExternalEndpoint::parse("https://shared-budget.invalid:443").expect("valid endpoint syntax");
        let started = Instant::now();
        let deadline = started + Duration::from_millis(100);

        let opened = endpoint.open_with(
            deadline,
            move |_| {
                thread::sleep(Duration::from_millis(60));
                Ok(vec![address])
            },
            |transport, address, attempt_deadline| transport.open(address, attempt_deadline),
        );
        let elapsed = started.elapsed();
        server.join().expect("silent TLS peer exits");

        assert!(opened.is_err(), "the TLS handshake must consume the same setup budget as DNS");
        assert!(elapsed >= Duration::from_millis(95));
        assert!(
            elapsed < Duration::from_millis(135),
            "the setup budget was restarted after DNS: {elapsed:?}"
        );
    }
}
