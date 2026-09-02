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

//! External TLS client setup and certificate trust.
//!
//! Responsible for: constructing a verified HTTP/1.1 TLS client from public roots plus an
//! optional caller-supplied CA certificate. NOT responsible for: endpoint syntax, HTTP framing,
//! request judgement, or HTTP/2. Upstream: `external`; downstream: `crate::socket::Connection`.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};

use crate::socket::Connection;
use crate::sut::SutError;

/// Socket protocol and trust state selected by the endpoint scheme.
#[derive(Clone)]
pub(super) enum ExternalTransport {
    Cleartext,
    Tls {
        server_name: ServerName<'static>,
        config: Arc<ClientConfig>,
    },
}

impl fmt::Debug for ExternalTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cleartext => formatter.write_str("Cleartext"),
            Self::Tls { server_name, .. } => formatter.debug_tuple("Tls").field(server_name).finish(),
        }
    }
}

impl ExternalTransport {
    pub(super) fn new(authority: &str, secure: bool, ca_path: Option<&Path>) -> Result<Self, SutError> {
        if !secure {
            if ca_path.is_some() {
                return Err(SutError::Environment(
                    "an external CA certificate requires an `https://` endpoint".to_owned(),
                ));
            }
            return Ok(Self::Cleartext);
        }

        let host = server_host(authority)?;
        let server_name = ServerName::try_from(host.to_owned())
            .map_err(|_| SutError::Environment(format!("external TLS endpoint has an invalid server name `{host}`")))?;
        let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(path) = ca_path {
            add_pem_roots(&mut roots, path)?;
        }
        let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self::Tls {
            server_name,
            config: Arc::new(config),
        })
    }

    pub(super) fn open(&self, address: std::net::SocketAddr) -> Result<Connection, SutError> {
        match self {
            Self::Cleartext => Connection::open(address),
            Self::Tls { server_name, config } => Connection::open_tls(address, server_name.clone(), Arc::clone(config)),
        }
    }

    pub(super) const fn is_tls(&self) -> bool {
        matches!(self, Self::Tls { .. })
    }
}

fn server_host(authority: &str) -> Result<&str, SutError> {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest
            .split_once(']')
            .map(|(host, _)| host)
            .filter(|host| !host.is_empty())
            .ok_or_else(|| SutError::Environment("external TLS endpoint has an invalid IPv6 server name".to_owned()));
    }
    Ok(authority.rsplit_once(':').map_or(authority, |(host, _)| host))
}

fn add_pem_roots(roots: &mut RootCertStore, path: &Path) -> Result<(), SutError> {
    let bytes = std::fs::read(path).map_err(|error| {
        SutError::Environment(format!("cannot read external TLS CA certificate `{}`: {error}", path.display()))
    })?;
    let mut count = 0_usize;
    for certificate in CertificateDer::pem_slice_iter(&bytes) {
        let certificate = certificate.map_err(|error| {
            SutError::Environment(format!("cannot parse external TLS CA certificate `{}`: {error}", path.display()))
        })?;
        roots.add(certificate).map_err(|error| {
            SutError::Environment(format!("external TLS CA certificate `{}` is invalid: {error}", path.display()))
        })?;
        count = count.saturating_add(1);
    }
    if count == 0 {
        return Err(SutError::Environment(format!(
            "external TLS CA certificate `{}` contains no PEM certificate",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::Duration;

    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection, StreamOwned};

    use super::super::{Conn, external_endpoint::ExternalEndpoint};
    use crate::sut::Sut;

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    struct TempPem(PathBuf);

    impl TempPem {
        fn new(contents: &str) -> Self {
            let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("rustfs-gateway-conformance-ca-{}-{sequence}.pem", std::process::id()));
            std::fs::write(&path, contents).expect("write temporary CA");
            Self(path)
        }
    }

    impl Drop for TempPem {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn tls_server() -> (String, String, thread::JoinHandle<Vec<u8>>) {
        let certified = rcgen::generate_simple_self_signed(["127.0.0.1".to_owned()]).expect("generate certificate");
        let certificate_pem = certified.cert.pem();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], key)
            .expect("configure test TLS server");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS listener");
        let address = listener.local_addr().expect("TLS listener address");
        let server = thread::spawn(move || {
            let Ok((socket, _)) = listener.accept() else {
                return Vec::new();
            };
            let Ok(connection) = ServerConnection::new(config) else {
                return Vec::new();
            };
            let mut stream = StreamOwned::new(connection, socket);
            let mut request = Vec::new();
            let mut block = [0_u8; 1024];
            loop {
                match stream.read(&mut block) {
                    Ok(0) | Err(_) => return request,
                    Ok(read) => request.extend_from_slice(&block[..read]),
                }
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .expect("write TLS response");
            stream.flush().expect("flush TLS response");
            request
        });
        (format!("https://{address}"), certificate_pem, server)
    }

    #[test]
    fn https_endpoint_has_a_verified_tls_entry_point() {
        let target = Conn::external_with_ca(PathBuf::from("."), "https://localhost:443", None)
            .expect("construction configures public roots without opening the endpoint");

        assert!(target.describe().contains("TLS"));
    }

    #[test]
    fn explicit_ca_verifies_tls_and_preserves_authored_request_bytes() {
        let (url, certificate, server) = tls_server();
        let ca = TempPem::new(&certificate);
        let endpoint = ExternalEndpoint::parse_with_ca(&url, Some(&ca.0)).expect("trusted endpoint");
        let mut connection = endpoint.open().expect("open TLS connection");
        let authored = format!("GET /bucket/key?versionId=7 HTTP/1.1\r\nHost: {}\r\n\r\n", endpoint.authority());

        connection.write(authored.as_bytes()).expect("write authored request");
        let response = connection.read_response(Duration::from_secs(2)).expect("read TLS response");
        let received = server.join().expect("TLS server exits");

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        assert_eq!(received, authored.as_bytes());
    }

    #[test]
    fn untrusted_certificate_is_an_environment_error() {
        let (url, _certificate, server) = tls_server();
        let endpoint = ExternalEndpoint::parse(&url).expect("endpoint syntax and public roots are valid");
        let mut connection = endpoint.open().expect("TCP opens before TLS verification");

        let error = connection
            .write(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .expect_err("self-signed endpoint must not be trusted implicitly");
        server.join().expect("TLS server exits");

        assert!(error.to_string().contains("certificate") || error.to_string().contains("TLS"));
    }

    #[test]
    fn empty_ca_file_is_rejected_before_connecting() {
        let ca = TempPem::new("");

        let error = ExternalEndpoint::parse_with_ca("https://127.0.0.1:443", Some(&ca.0))
            .expect_err("empty CA cannot silently fall back to public roots");

        assert!(error.to_string().contains("contains no PEM certificate"));
    }

    #[test]
    fn ca_file_is_rejected_for_cleartext_endpoint() {
        let ca = TempPem::new("not a certificate");

        let error =
            ExternalEndpoint::parse_with_ca("http://127.0.0.1:80", Some(&ca.0)).expect_err("CA must not be accepted and ignored");

        assert!(error.to_string().contains("https://"));
    }
}
