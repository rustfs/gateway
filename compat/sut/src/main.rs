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

//! The external-suite system under test: the filesystem reference backend behind a real listener.
//!
//! Responsible for: parsing the command line, assembling `rustfs-gateway-fs` into a signed S3
//! endpoint that any third-party SDK or external suite can be pointed at — plaintext always, and
//! optionally a second, encrypted listener serving the very same service — publishing the
//! operation set that endpoint really registers, and recording one wire-evidence line per served
//! request.
//! NOT responsible for: production durability, the TLS handshake itself (`rustfs-gateway-server`),
//! deciding whether a scenario passed, or fixing any gap a client finds — a matrix failure is fixed
//! in the issue that owns the operation.
//! Upstream: `ci/compat/run_matrix.sh` and `ci/lib/sut.sh`, which start it before any driver or
//! suite runs.
//! Downstream: the drivers under `compat/drivers/**`, `ci/compat/report.py`, and the Ceph s3-tests
//! runner in `ci/s3tests/run.sh`.
//!
//! ```text
//! compat-sut --data <dir> --port 9100 --probe-log <path>
//! compat-sut --data <dir> --access-key MAIN --secret-key ... --owner-id s3gate-main \
//!            --alt-access-key ALT --alt-secret-key ... --alt-owner-id s3gate-alt \
//!            --tenant-access-key TENANT --tenant-secret-key ... --tenant-owner-id s3gate-tenant \
//!            --lc-debug-interval 10
//! compat-sut --data <dir> --port 9100 --tls-port 9443 --tls-self-signed <ca.pem> [--tls-san <name>]
//! compat-sut --data <dir> --port 9100 --tls-port 9443 --tls-cert <chain.pem> --tls-key <key.pem>
//! compat-sut --data <dir> --port 9100 --corpus-record <file.jsonl> --corpus-src <src>   # corpus-record builds
//! compat-sut --data <dir> --port 9100 --server-domains s3.example.com:9100,s3.local   # RUSTFS_SERVER_DOMAINS
//! compat-sut --print-capabilities
//! ```
//!
//! Some client behaviour exists only over TLS — botocore's `STREAMING-UNSIGNED-PAYLOAD-TRAILER`
//! uploads, and every test of MinIO mint's `aws-sdk-java-v2` suite (rustfs/gateway#719) — so the
//! encrypted listener is what makes those measurable. Plaintext stays on `--port` either way, so
//! nothing that already points at it changes.

mod corpus;
mod identity;
mod ownership;
mod policy_authorizer;
mod probe;
mod service;
mod storage_names;
mod tls;
mod transport;

use std::env;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustfs_gateway_fs::FsBackend;
use rustfs_gateway_server::{Server, ServerConfig, TlsHandle};

use crate::identity::{AccountArgs, Accounts};
use crate::ownership::BucketOwners;
use crate::probe::{ProbeLog, ProbeService};
use crate::service::{build_service, capability_names};
use crate::tls::{TlsArgs, TlsListener, TlsSource};
use crate::transport::DeclareTransport;

/// Everything the launcher accepts. There are no defaults for the **second** credential pair on
/// purpose: a matrix run whose driver and whose server disagree about the secret fails as
/// `SignatureDoesNotMatch` for every scenario at once, and a shared default is the easiest way to
/// arrive there — while a second identity that exists by default would let a cross-account case
/// pass without anybody having configured the distinction it measures.
pub(crate) struct Options {
    pub(crate) data: PathBuf,
    pub(crate) address: SocketAddr,
    pub(crate) accounts: Accounts,
    pub(crate) region: String,
    pub(crate) probe_log: Option<PathBuf>,
    /// How long one lifecycle day and one automatic sweep last. `None` leaves the reference
    /// backend's 24-hour cadence alone and starts no sweeper, which is what a matrix run wants and
    /// what a lifecycle suite cannot use.
    pub(crate) lifecycle_debug_interval: Option<Duration>,
    /// The optional encrypted listener, on the same host as the plaintext one.
    pub(crate) tls: Option<TlsListener>,
    /// Corpus recording, when `--corpus-record` asked for it (rustfs/backlog#1763).
    pub(crate) corpus: Option<CorpusRecording>,
    /// The virtual-hosted domains, as RustFS reads `RUSTFS_SERVER_DOMAINS` (rustfs/gateway#1136):
    /// comma-separated, each with an optional port. Empty reads every request path-style.
    pub(crate) server_domains: Vec<String>,
}

/// Where recorded requests go and which suite produced them. Both are required together: an entry
/// without a provenance source is refused by the corpus, so a recording without one is refused
/// here, before anything is served.
pub(crate) struct CorpusRecording {
    pub(crate) output: PathBuf,
    pub(crate) src: String,
}

fn parse_options<I, S>(arguments: I) -> Result<Options, io::Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut data = PathBuf::from(".");
    let mut region = "us-east-1".to_owned();
    let mut probe_log = None;
    let mut host = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut port = 9100_u16;
    let mut primary = AccountArgs::default();
    let mut secondary = AccountArgs::default();
    let mut tenant = AccountArgs::default();
    let mut lifecycle_debug_interval = None;
    let mut tls = TlsArgs::default();
    let mut corpus_output = None;
    let mut corpus_src = None;
    let mut server_domains = Vec::new();
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        let mut value = || -> Result<String, io::Error> {
            arguments
                .next()
                .map(|found| found.as_ref().to_owned())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "an option is missing its value"))
        };
        match argument.as_ref() {
            "--data" => data = PathBuf::from(value()?),
            "--host" => {
                host = value()?
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "--host requires an IP address"))?;
            }
            "--port" => {
                port = value()?
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "--port requires a number"))?;
            }
            "--access-key" => primary.access_key = Some(value()?),
            "--secret-key" => primary.secret_key = Some(value()?),
            "--owner-id" => primary.owner_id = Some(value()?),
            "--display-name" => primary.display_name = Some(value()?),
            "--alt-access-key" => secondary.access_key = Some(value()?),
            "--alt-secret-key" => secondary.secret_key = Some(value()?),
            "--alt-owner-id" => secondary.owner_id = Some(value()?),
            "--alt-display-name" => secondary.display_name = Some(value()?),
            "--tenant-access-key" => tenant.access_key = Some(value()?),
            "--tenant-secret-key" => tenant.secret_key = Some(value()?),
            "--tenant-owner-id" => tenant.owner_id = Some(value()?),
            "--tenant-display-name" => tenant.display_name = Some(value()?),
            "--lc-debug-interval" => {
                let seconds: u64 = value()?.parse().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--lc-debug-interval requires a number of seconds")
                })?;
                if seconds == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--lc-debug-interval must be at least one second; a zero-length day would make every \
                         object immediately eligible and every lifecycle assertion unfalsifiable",
                    ));
                }
                lifecycle_debug_interval = Some(Duration::from_secs(seconds));
            }
            "--region" => region = value()?,
            "--probe-log" => probe_log = Some(PathBuf::from(value()?)),
            "--tls-port" => {
                tls.port = Some(
                    value()?
                        .parse()
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "--tls-port requires a number"))?,
                );
            }
            "--tls-cert" => tls.certificate = Some(PathBuf::from(value()?)),
            "--tls-key" => tls.private_key = Some(PathBuf::from(value()?)),
            "--tls-self-signed" => tls.self_signed = Some(PathBuf::from(value()?)),
            "--tls-san" => tls.extra_names.push(value()?),
            "--corpus-record" => corpus_output = Some(PathBuf::from(value()?)),
            "--corpus-src" => corpus_src = Some(value()?),
            "--server-domains" => server_domains.extend(
                value()?
                    .split(',')
                    .map(str::trim)
                    .filter(|domain| !domain.is_empty())
                    .map(str::to_owned),
            ),
            unknown => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unknown argument: {unknown}")));
            }
        }
    }
    let tls = tls.resolve(host)?;
    if let Some(listener) = tls.as_ref()
        && listener.port == port
        && port != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--tls-port must differ from --port; the plaintext listener stays up beside the encrypted one",
        ));
    }
    let corpus = match (corpus_output, corpus_src) {
        (None, None) => None,
        (Some(output), Some(src)) => Some(CorpusRecording { output, src }),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--corpus-record and --corpus-src must be given together",
            ));
        }
    };
    Ok(Options {
        data,
        address: SocketAddr::new(host, port),
        accounts: Accounts::build(primary, secondary, tenant)?,
        region,
        probe_log,
        lifecycle_debug_interval,
        tls,
        corpus,
        server_domains,
    })
}

/// The identity banner, one line per configured identity.
///
/// This is what an operator or a configuration generator reads to fill the `user_id` and
/// `display_name` of a suite configuration such as `ci/s3tests/s3tests.conf.tmpl`, which compares
/// both values verbatim. **No secret appears here**, and none ever may: this launcher's output is
/// captured to a file by `ci/lib/sut.sh` and attached to a CI run as an artifact.
fn identity_lines(accounts: &Accounts) -> Vec<String> {
    accounts
        .roles()
        .map(|(role, account)| {
            format!(
                "compat-sut identity {role} access-key {} owner-id {} display-name {}",
                account.access_key, account.owner_id, account.display_name
            )
        })
        .collect()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw: Vec<String> = env::args().skip(1).collect();
    if raw.iter().any(|argument| argument == "--print-capabilities") {
        let directory = tempdir_for_capability_probe()?;
        let backend = FsBackend::open(&directory)?;
        for name in capability_names(&backend) {
            println!("{name}");
        }
        std::fs::remove_dir_all(&directory)?;
        return Ok(());
    }

    let options = parse_options(raw)?;
    std::fs::create_dir_all(&options.data)?;
    let backend = Arc::new(service::open_backend(&options)?);
    let owners = Arc::new(BucketOwners::default());
    let service = build_service(&options, &backend, &owners)?;
    // Started only when a debug cadence was configured: at the production 24-hour interval the
    // sweeper would do nothing a suite could observe, and starting it anyway would make the flag
    // look load-bearing when it was not.
    let scheduler = match options.lifecycle_debug_interval {
        Some(_) => Some(backend.start_lifecycle_scheduler()?),
        None => None,
    };

    let log = match options.probe_log.as_deref() {
        Some(path) => Some(Arc::new(ProbeLog::create(path)?)),
        None => None,
    };
    // Refused before any port is bound: a recorder that cannot start must stop the launcher, not
    // leave it serving unrecorded while a suite believes it is being recorded.
    let recorder = corpus::recorder(&options)?;
    // Both listeners serve this one value, so a request is authorized, served and recorded the same
    // way whichever socket it arrived on. The only difference is the transport fact, and that is
    // read from the socket by `DeclareTransport`, never from the request. The corpus recorder, when
    // there is one, is outermost, so it records the request as the client sent it.
    let served = tower::ServiceBuilder::new()
        .option_layer(recorder.clone())
        .service(DeclareTransport::new(ProbeService::new(service, log.clone())));

    // The encrypted listener is bound first. The plaintext port is what `ci/lib/sut.sh` polls for
    // readiness, so once it answers, the TLS port is bound too and a generated authority is
    // already on disk for the runner to hand out.
    let encrypted = match options.tls.as_ref() {
        Some(listener) => {
            let handle = TlsHandle::new(listener.source.load()?)?;
            let config = ServerConfig {
                bind_addr: SocketAddr::new(options.address.ip(), listener.port),
                ..ServerConfig::default()
            };
            Some(Server::new(config, served.clone()).with_tls(handle).serve()?)
        }
        None => None,
    };
    let config = ServerConfig {
        bind_addr: options.address,
        plaintext: true,
        ..ServerConfig::default()
    };
    let running = Server::new(config, served).serve()?;
    // The banner is the readiness signal `ci/compat/run_matrix.sh` waits for. It names the ports
    // that were actually bound, so `--port 0` and `--tls-port 0` are usable for a local run.
    println!("compat-sut listening on http://{}", running.local_addr);
    if let Some(encrypted) = encrypted.as_ref() {
        println!("compat-sut listening on https://{}", encrypted.local_addr);
    }
    if let Some(TlsSource::SelfSigned { authority_out, .. }) = options.tls.as_ref().map(|listener| &listener.source) {
        println!("compat-sut tls authority {}", authority_out.display());
    }
    println!("compat-sut region {}", options.region);
    for line in identity_lines(&options.accounts) {
        println!("{line}");
    }
    if let Some(interval) = options.lifecycle_debug_interval {
        println!("compat-sut lifecycle debug interval {}s", interval.as_secs());
    }

    tokio::signal::ctrl_c().await?;
    if let Some(encrypted) = encrypted {
        let report = encrypted.shutdown.trigger(Duration::from_secs(30)).await;
        println!("compat-sut tls shutdown drained={} aborted={}", report.drained, report.aborted);
        encrypted.task.await??;
    }
    let report = running.shutdown.trigger(Duration::from_secs(30)).await;
    if let Some(scheduler) = scheduler {
        let sweeps = scheduler.shutdown().await?;
        println!(
            "compat-sut lifecycle sweeps={} expired={} failed={}",
            sweeps.sweeps, sweeps.expired_objects, sweeps.failed_sweeps
        );
    }
    if let Some(log) = log.as_ref() {
        println!("compat-sut recorded {} probe record(s)", log.records());
    }
    if let Some(line) = corpus::report(recorder.as_ref()) {
        println!("{line}");
    }
    println!("compat-sut shutdown drained={} aborted={}", report.drained, report.aborted);
    running.task.await??;
    Ok(())
}

/// A throwaway directory for `--print-capabilities`, which must not disturb a real data root.
fn tempdir_for_capability_probe() -> io::Result<PathBuf> {
    let directory = env::temp_dir().join(format!("compat-sut-capabilities-{}", std::process::id()));
    std::fs::create_dir_all(&directory)?;
    Ok(directory)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{identity_lines, parse_options};

    #[test]
    fn an_option_without_its_value_is_refused() {
        assert!(parse_options(["--port"]).is_err());
        assert!(parse_options(["--data"]).is_err());
        assert!(parse_options(["--alt-access-key"]).is_err());
        assert!(parse_options(["--lc-debug-interval"]).is_err());
    }

    #[test]
    fn an_unknown_option_is_refused() {
        assert!(parse_options(["--listen-everywhere"]).is_err());
    }

    #[test]
    fn a_non_numeric_port_is_refused() {
        assert!(parse_options(["--port", "nine-thousand"]).is_err());
    }

    #[test]
    fn the_parsed_address_uses_both_host_and_port() {
        let options = parse_options(["--host", "127.0.0.1", "--port", "0"]).expect("a valid option pair");
        assert_eq!(options.address.port(), 0);
        assert!(options.address.ip().is_loopback());
    }

    /// Positive — the full two-identity command line reaches the served identity set.
    #[test]
    fn both_identities_reach_the_served_set() {
        let options = parse_options([
            "--access-key",
            "MAIN",
            "--secret-key",
            "main-secret",
            "--owner-id",
            "s3gate-main",
            "--display-name",
            "s3gate-main",
            "--alt-access-key",
            "ALT",
            "--alt-secret-key",
            "alt-secret",
            "--alt-owner-id",
            "s3gate-alt",
            "--alt-display-name",
            "s3gate-alt",
        ])
        .expect("two distinct identities");
        assert_eq!(options.accounts.owner_of("MAIN"), Some("s3gate-main"));
        assert_eq!(options.accounts.owner_of("ALT"), Some("s3gate-alt"));
        assert_eq!(options.accounts.all().count(), 2);
    }

    /// Positive — the tenant flags reach the served set as a third principal, and the banner names
    /// it `tenant`, which is the role ci/s3tests/run.sh configures `[s3 tenant]` with.
    #[test]
    fn the_tenant_identity_reaches_the_served_set() {
        let options = parse_options([
            "--access-key",
            "MAIN",
            "--secret-key",
            "main-secret",
            "--alt-access-key",
            "ALT",
            "--alt-secret-key",
            "alt-secret",
            "--tenant-access-key",
            "TENANT",
            "--tenant-secret-key",
            "tenant-secret",
            "--tenant-owner-id",
            "s3gate-tenant",
            "--tenant-display-name",
            "s3gate-tenant",
        ])
        .expect("three distinct identities");
        assert_eq!(options.accounts.owner_of("TENANT"), Some("s3gate-tenant"));
        assert_eq!(options.accounts.all().count(), 3);
        let lines = identity_lines(&options.accounts);
        assert_eq!(
            lines.last().map(String::as_str),
            Some("compat-sut identity tenant access-key TENANT owner-id s3gate-tenant display-name s3gate-tenant")
        );
        assert!(parse_options(["--tenant-access-key"]).is_err());
    }

    /// Negative — two identities that collapse into one principal are refused at the command line,
    /// before anything can be measured against them.
    #[test]
    fn n_a_collapsed_second_identity_is_refused_at_the_command_line() {
        assert!(
            parse_options([
                "--access-key",
                "SAME",
                "--secret-key",
                "main-secret",
                "--alt-access-key",
                "SAME",
                "--alt-secret-key",
                "alt-secret",
            ])
            .is_err()
        );
        assert!(
            parse_options([
                "--access-key",
                "MAIN",
                "--secret-key",
                "main-secret",
                "--owner-id",
                "one-account",
                "--alt-access-key",
                "ALT",
                "--alt-secret-key",
                "alt-secret",
                "--alt-owner-id",
                "one-account",
            ])
            .is_err()
        );
    }

    /// Negative — a recording without a provenance source, or a source without a recording, is
    /// refused at the command line.
    #[test]
    fn n_corpus_recording_flags_are_refused_alone() {
        assert!(parse_options(["--corpus-record", "out.jsonl"]).is_err());
        assert!(parse_options(["--corpus-src", "handwritten:gateway"]).is_err());
        assert!(parse_options(["--corpus-record"]).is_err());
    }

    /// Negative — in a build without the feature, asking to record stops the launcher instead of
    /// serving unrecorded.
    #[cfg(not(feature = "corpus-record"))]
    #[test]
    fn n_recording_is_refused_by_a_build_without_the_feature() {
        let options = parse_options(["--corpus-record", "out.jsonl", "--corpus-src", "handwritten:gateway"])
            .expect("a complete recording request");
        assert!(crate::corpus::recorder(&options).is_err());
        assert!(crate::corpus::recorder(&parse_options(["--data", "."]).expect("a valid line")).is_ok_and(|none| none.is_none()));
    }

    /// Negative — a zero-second lifecycle day is refused; every object would be born expired.
    #[test]
    fn n_a_zero_lifecycle_debug_interval_is_refused() {
        assert!(parse_options(["--lc-debug-interval", "0"]).is_err());
        assert!(parse_options(["--lc-debug-interval", "a-while"]).is_err());
    }

    /// Positive — the flag is off unless it is given, and on with the seconds that were given.
    #[test]
    fn the_lifecycle_debug_interval_is_absent_until_it_is_given() {
        assert!(
            parse_options(["--data", "."])
                .expect("a valid line")
                .lifecycle_debug_interval
                .is_none()
        );
        assert_eq!(
            parse_options(["--lc-debug-interval", "10"])
                .expect("a valid line")
                .lifecycle_debug_interval
                .map(|interval| interval.as_secs()),
            Some(10)
        );
    }

    /// Positive — the banner names each identity's owner id and display name, per identity.
    #[test]
    fn the_banner_names_each_identitys_owner_and_display_name() {
        let options = parse_options([
            "--access-key",
            "MAIN",
            "--secret-key",
            "main-secret",
            "--owner-id",
            "s3gate-main",
            "--display-name",
            "Main Fixture Owner",
            "--alt-access-key",
            "ALT",
            "--alt-secret-key",
            "alt-secret",
            "--alt-owner-id",
            "s3gate-alt",
            "--alt-display-name",
            "Alt Fixture Owner",
        ])
        .expect("two distinct identities");
        let lines = identity_lines(&options.accounts);
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "compat-sut identity main access-key MAIN owner-id s3gate-main display-name Main Fixture Owner"
        );
        assert_eq!(
            lines[1],
            "compat-sut identity alt access-key ALT owner-id s3gate-alt display-name Alt Fixture Owner"
        );
    }

    /// Negative — no banner line may carry a signing secret. This launcher's stdout is captured to
    /// a file and attached to a CI run as an artifact.
    #[test]
    fn n_no_banner_line_carries_a_secret() {
        let options = parse_options([
            "--access-key",
            "MAIN",
            "--secret-key",
            "main-secret-value",
            "--alt-access-key",
            "ALT",
            "--alt-secret-key",
            "alt-secret-value",
        ])
        .expect("two distinct identities");
        for line in identity_lines(&options.accounts) {
            assert!(!line.contains("main-secret-value"), "{line}");
            assert!(!line.contains("alt-secret-value"), "{line}");
        }
    }
}
