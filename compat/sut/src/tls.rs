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

//! Certificate material for the optional encrypted listener.
//!
//! Responsible for: turning `--tls-cert`/`--tls-key` PEM files, or `--tls-self-signed <ca-path>`,
//! into the server crate's [`TlsMaterial`], and writing the throwaway certificate authority a
//! runner hands to the clients it drives.
//! NOT responsible for: the handshake, reload or ALPN (`rustfs-gateway-server`'s `TlsHandle`), or
//! telling the gateway a connection was encrypted (`crate::transport`).
//! Upstream: `crate::parse_options`. Downstream: `main`, which serves the material on `--tls-port`.
//!
//! Why a generated authority and a leaf rather than one self-signed leaf: a verifying client such as
//! rustls refuses a CA certificate used as an end-entity, and one that is not a CA cannot anchor a
//! chain. Only the authority's certificate is written; its private key never leaves this process,
//! so the file is safe to hand to a container or attach to a CI artifact.

use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustfs_gateway_server::TlsMaterial;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Names every generated leaf answers to, whatever `--host` is. A runner that dials `localhost`
/// and one that dials the loopback address must both verify.
const LOOPBACK_NAMES: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

/// Where the encrypted listener's certificate comes from.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum TlsSource {
    /// An operator-supplied PEM chain (leaf first) and its PEM private key.
    Files { certificate: PathBuf, private_key: PathBuf },
    /// A certificate authority generated at start-up, written to `authority_out`, and a leaf it
    /// signed for `names`.
    SelfSigned { authority_out: PathBuf, names: Vec<String> },
}

/// The encrypted listener: which port it binds and what it presents.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct TlsListener {
    pub(crate) port: u16,
    pub(crate) source: TlsSource,
}

/// The TLS flags as given, before they are checked against each other.
#[derive(Default)]
pub(crate) struct TlsArgs {
    pub(crate) port: Option<u16>,
    pub(crate) certificate: Option<PathBuf>,
    pub(crate) private_key: Option<PathBuf>,
    pub(crate) self_signed: Option<PathBuf>,
    pub(crate) extra_names: Vec<String>,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

impl TlsArgs {
    /// Checks the flags against each other. `None` means no encrypted listener, which is the
    /// default and leaves the plaintext listener exactly as it was.
    ///
    /// Every half-configuration is refused rather than guessed at: a port with no certificate
    /// would listen for handshakes it cannot complete, and a certificate with no port would be a
    /// flag that silently does nothing.
    pub(crate) fn resolve(self, host: IpAddr) -> io::Result<Option<TlsListener>> {
        let source = match (self.certificate, self.private_key, self.self_signed) {
            (None, None, None) => None,
            (Some(certificate), Some(private_key), None) => Some(TlsSource::Files {
                certificate,
                private_key,
            }),
            (None, None, Some(authority_out)) => Some(TlsSource::SelfSigned {
                authority_out,
                names: leaf_names(host, &self.extra_names),
            }),
            (Some(_), None, None) | (None, Some(_), None) => {
                return Err(invalid("--tls-cert and --tls-key are only valid together"));
            }
            (_, _, Some(_)) => {
                return Err(invalid("--tls-self-signed generates its own certificate; drop --tls-cert and --tls-key"));
            }
        };
        if !self.extra_names.is_empty() && !matches!(source, Some(TlsSource::SelfSigned { .. })) {
            return Err(invalid(
                "--tls-san names what a generated certificate covers; it is only valid with --tls-self-signed",
            ));
        }
        match (self.port, source) {
            (None, None) => Ok(None),
            (Some(port), Some(source)) => Ok(Some(TlsListener { port, source })),
            (Some(_), None) => Err(invalid("--tls-port needs --tls-cert and --tls-key, or --tls-self-signed")),
            (None, Some(_)) => Err(invalid("TLS material was given without --tls-port to serve it on")),
        }
    }
}

/// The loopback names, the bound host when it is a concrete address, and every `--tls-san`, once
/// each and in that order.
fn leaf_names(host: IpAddr, extra: &[String]) -> Vec<String> {
    let mut names: Vec<String> = LOOPBACK_NAMES.iter().map(|name| (*name).to_owned()).collect();
    if !host.is_unspecified() {
        names.push(host.to_string());
    }
    names.extend(extra.iter().cloned());
    let mut seen = std::collections::BTreeSet::new();
    names.retain(|name| seen.insert(name.clone()));
    names
}

impl TlsSource {
    /// Produces the material the listener serves. For [`TlsSource::SelfSigned`] this also writes
    /// the authority's certificate, before anything listens, so a runner that waited for the port
    /// can rely on the file being there.
    pub(crate) fn load(&self) -> io::Result<TlsMaterial> {
        match self {
            Self::Files {
                certificate,
                private_key,
            } => from_files(certificate, private_key),
            Self::SelfSigned { authority_out, names } => self_signed(authority_out, names),
        }
    }
}

fn from_files(certificate: &Path, private_key: &Path) -> io::Result<TlsMaterial> {
    let unreadable = |what: &str, path: &Path, error: rustls::pki_types::pem::Error| {
        invalid(format!("{what} {} is not usable PEM: {error}", path.display()))
    };
    let chain = CertificateDer::pem_file_iter(certificate)
        .map_err(|error| unreadable("--tls-cert", certificate, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| unreadable("--tls-cert", certificate, error))?;
    if chain.is_empty() {
        return Err(invalid(format!("--tls-cert {} holds no CERTIFICATE block", certificate.display())));
    }
    let key = PrivateKeyDer::from_pem_file(private_key).map_err(|error| unreadable("--tls-key", private_key, error))?;
    Ok(TlsMaterial::from_der(
        chain.iter().map(|certificate| certificate.to_vec()).collect(),
        key.secret_der().to_vec(),
    ))
}

fn generation_failed(error: rcgen::Error) -> io::Error {
    io::Error::other(format!("cannot generate the throwaway certificate: {error}"))
}

fn self_signed(authority_out: &Path, names: &[String]) -> io::Result<TlsMaterial> {
    let authority_key = KeyPair::generate().map_err(generation_failed)?;
    let mut authority = CertificateParams::new(Vec::<String>::new()).map_err(generation_failed)?;
    authority.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    authority
        .distinguished_name
        .push(DnType::CommonName, "compat-sut throwaway authority");
    authority.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let authority_certificate = authority.self_signed(&authority_key).map_err(generation_failed)?;
    let issuer = Issuer::new(authority, authority_key);

    let leaf_key = KeyPair::generate().map_err(generation_failed)?;
    let mut leaf = CertificateParams::new(names.to_vec()).map_err(generation_failed)?;
    leaf.distinguished_name.push(DnType::CommonName, "compat-sut");
    leaf.is_ca = IsCa::ExplicitNoCa;
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_certificate = leaf.signed_by(&leaf_key, &issuer).map_err(generation_failed)?;

    if let Some(parent) = authority_out.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(authority_out, authority_certificate.pem())?;
    Ok(TlsMaterial::from_der(vec![leaf_certificate.der().to_vec()], leaf_key.serialize_der()))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{TlsArgs, TlsListener, TlsSource, leaf_names};

    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    use rustfs_gateway_server::TlsHandle;

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("compat-sut-tls-{}-{name}", std::process::id()))
    }

    #[test]
    fn no_tls_flag_means_no_encrypted_listener() {
        assert_eq!(TlsArgs::default().resolve(LOOPBACK).expect("the default is valid"), None);
    }

    #[test]
    fn a_self_signed_listener_resolves_with_its_port_and_names() {
        let resolved = TlsArgs {
            port: Some(9443),
            self_signed: Some(PathBuf::from("ca.pem")),
            extra_names: vec!["host.lima.internal".to_owned()],
            ..TlsArgs::default()
        }
        .resolve(LOOPBACK)
        .expect("a complete self-signed configuration");
        assert_eq!(
            resolved,
            Some(TlsListener {
                port: 9443,
                source: TlsSource::SelfSigned {
                    authority_out: PathBuf::from("ca.pem"),
                    names: vec![
                        "localhost".to_owned(),
                        "127.0.0.1".to_owned(),
                        "::1".to_owned(),
                        "host.lima.internal".to_owned()
                    ],
                },
            })
        );
    }

    /// Negative — every half-configuration is refused instead of guessed at.
    #[test]
    fn n_a_half_configured_listener_is_refused() {
        let port_only = TlsArgs {
            port: Some(9443),
            ..TlsArgs::default()
        };
        assert!(port_only.resolve(LOOPBACK).is_err());
        let material_only = TlsArgs {
            self_signed: Some(PathBuf::from("ca.pem")),
            ..TlsArgs::default()
        };
        assert!(material_only.resolve(LOOPBACK).is_err());
        let certificate_without_key = TlsArgs {
            port: Some(9443),
            certificate: Some(PathBuf::from("cert.pem")),
            ..TlsArgs::default()
        };
        assert!(certificate_without_key.resolve(LOOPBACK).is_err());
        let both_sources = TlsArgs {
            port: Some(9443),
            certificate: Some(PathBuf::from("cert.pem")),
            private_key: Some(PathBuf::from("key.pem")),
            self_signed: Some(PathBuf::from("ca.pem")),
            ..TlsArgs::default()
        };
        assert!(both_sources.resolve(LOOPBACK).is_err());
        let names_for_files = TlsArgs {
            port: Some(9443),
            certificate: Some(PathBuf::from("cert.pem")),
            private_key: Some(PathBuf::from("key.pem")),
            extra_names: vec!["example.test".to_owned()],
            ..TlsArgs::default()
        };
        assert!(names_for_files.resolve(LOOPBACK).is_err());
    }

    #[test]
    fn a_wildcard_host_adds_no_name_and_duplicates_collapse() {
        let names = leaf_names(IpAddr::V4(Ipv4Addr::UNSPECIFIED), &["localhost".to_owned()]);
        assert_eq!(names, ["localhost", "127.0.0.1", "::1"]);
        let names = leaf_names(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)), &[]);
        assert_eq!(names.last().map(String::as_str), Some("10.0.0.7"));
    }

    /// Positive — generated material is accepted by the server crate, and only a certificate is
    /// written: the authority's private key never reaches the file a runner hands out.
    #[test]
    fn generated_material_builds_a_handle_and_writes_only_a_certificate() {
        let authority = scratch("authority/ca.pem");
        let source = TlsSource::SelfSigned {
            authority_out: authority.clone(),
            names: leaf_names(LOOPBACK, &[]),
        };
        TlsHandle::new(source.load().expect("generation succeeds")).expect("the server crate accepts the material");
        let written = std::fs::read_to_string(&authority).expect("the authority certificate was written");
        assert!(written.starts_with("-----BEGIN CERTIFICATE-----"), "{written}");
        assert!(!written.contains("PRIVATE KEY"), "the authority's key must never be written");
        std::fs::remove_dir_all(authority.parent().expect("a parent directory")).expect("cleanup");
    }

    /// Positive and negative — operator PEM files round-trip, and a file without a certificate is
    /// refused rather than served as an empty chain.
    #[test]
    fn operator_pem_files_load_and_an_empty_chain_is_refused() {
        let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("a fixture certificate");
        let certificate = scratch("operator-cert.pem");
        let key = scratch("operator-key.pem");
        std::fs::write(&certificate, certified.cert.pem()).expect("write the certificate");
        std::fs::write(&key, certified.signing_key.serialize_pem()).expect("write the key");
        let source = TlsSource::Files {
            certificate: certificate.clone(),
            private_key: key.clone(),
        };
        TlsHandle::new(source.load().expect("the PEM files load")).expect("the server crate accepts them");

        std::fs::write(&certificate, "not a certificate\n").expect("overwrite the certificate");
        assert!(source.load().is_err());
        std::fs::remove_file(&certificate).expect("cleanup");
        std::fs::remove_file(&key).expect("cleanup");
    }
}
