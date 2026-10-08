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

//! What an external endpoint says about itself: the `Server` header of an unsigned `HEAD /`.
//!
//! Responsible for: one probe exchange before the run, reported verbatim — the header's value
//! when the target sends one, nothing when it does not. The report's `target_build` is this and
//! only this; a product name the probe did not observe is never substituted for it.
//! NOT responsible for: the exchange mechanics (`super::external`), judging any case, or the
//! endpoint's own parsing (`super::external_endpoint`).
//! Upstream: `super::external`. Downstream: `crate::cli`, through [`super::Conn`].

use std::time::{Duration, Instant};

use super::external::execute_socket_exchange;
use super::{Conn, Head};
use crate::inprocess::Wire;
use crate::sut::{SutError, TargetIdentity};

/// How long the probe may take, connection setup included. Generous for a loopback or a LAN
/// candidate, and far below any case budget: a target that cannot answer a `HEAD /` in this time
/// is not one the run can measure.
const PROBE_BUDGET: Duration = Duration::from_secs(10);

impl Conn {
    /// Probes the external endpoint once and reports its URL and its `Server` header.
    ///
    /// # Errors
    ///
    /// Returns [`SutError::Environment`] when the endpoint cannot be reached or does not answer
    /// with a complete HTTP/1.1 response head.
    pub(super) fn external_identity(&mut self) -> Result<TargetIdentity, SutError> {
        let endpoint = self
            .external
            .clone()
            .ok_or_else(|| SutError::Environment("external identity probe has no configured endpoint".to_owned()))?;
        let started = Instant::now();
        let deadline = started
            .checked_add(PROBE_BUDGET)
            .ok_or_else(|| SutError::Environment("external identity probe deadline cannot be represented".to_owned()))?;
        let headers = vec![
            ("host".to_owned(), endpoint.authority().to_owned()),
            ("connection".to_owned(), "close".to_owned()),
        ];
        let mut bytes = b"HEAD / HTTP/1.1\r\n".to_vec();
        for (name, value) in &headers {
            bytes.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        bytes.extend_from_slice(b"\r\n");
        let wire = Wire {
            method: "HEAD".to_owned(),
            target: "/".to_owned(),
            headers,
            raw_head: None,
            h2_frames: Vec::new(),
            http_version: None,
            body: Vec::new(),
            frames: Vec::new(),
            steps: Vec::new(),
            sign: None,
        };
        let head = Head {
            bytes,
            declared_length: 0,
        };
        let mut connection = endpoint.open(deadline)?;
        let result = execute_socket_exchange(&mut connection, &wire, &head, started, deadline, !endpoint.is_tls())?;
        let build = result
            .observation
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("server"))
            .map(|(_, value)| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        Ok(TargetIdentity {
            endpoint: Some(endpoint.url()),
            build,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sut::Sut;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// A server that answers the first request with `response` and hands the request bytes back.
    fn answering(response: &'static [u8]) -> (String, std::thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let address = listener.local_addr().expect("local address");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).expect("read request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            stream.write_all(response).expect("write response");
            request
        });
        (format!("http://{address}"), handle)
    }

    fn probe(url: &str) -> Result<TargetIdentity, SutError> {
        Conn::external(std::path::PathBuf::from("."), url)
            .expect("external target")
            .identity()
    }

    /// Positive — the header is reported as sent, beside the URL the run was pointed at.
    #[test]
    fn the_server_header_is_reported_verbatim() {
        let (url, server) =
            answering(b"HTTP/1.1 403 Forbidden\r\nServer: RustFS\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let identity = probe(&url).expect("probed");
        assert_eq!(identity.build.as_deref(), Some("RustFS"));
        assert_eq!(identity.endpoint.as_deref(), Some(url.as_str()));
        let request = server.join().expect("server thread");
        let request = String::from_utf8(request).expect("ASCII request");
        assert!(request.starts_with("HEAD / HTTP/1.1\r\n"), "{request}");
        assert!(
            !request.to_ascii_lowercase().contains("authorization"),
            "the probe is unsigned: {request}"
        );
    }

    /// Negative — a target that names no build gets none; the probe does not know what it is
    /// talking to and must not say.
    #[test]
    fn a_target_without_a_server_header_reports_no_build() {
        let (url, server) = answering(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let identity = probe(&url).expect("probed");
        assert_eq!(identity.build, None);
        assert_eq!(identity.endpoint.as_deref(), Some(url.as_str()));
        server.join().expect("server thread");
    }

    /// Negative — an empty header is no observation either.
    #[test]
    fn an_empty_server_header_reports_no_build() {
        let (url, server) = answering(b"HTTP/1.1 403 Forbidden\r\nServer:   \r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        assert_eq!(probe(&url).expect("probed").build, None);
        server.join().expect("server thread");
    }

    /// Negative — a target that cannot be reached is an environment error, not an identity.
    #[test]
    fn a_refused_connection_is_an_environment_error() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("reserve address");
        let address = listener.local_addr().expect("local address");
        drop(listener);
        assert!(matches!(probe(&format!("http://{address}")), Err(SutError::Environment(_))));
    }

    /// Negative — a target that is not pointed at a URL has nothing to probe.
    #[test]
    fn a_local_target_reports_no_identity() {
        let identity = Conn::new(std::path::PathBuf::from(".")).identity().expect("nothing to ask");
        assert_eq!(identity, TargetIdentity::default());
    }
}
