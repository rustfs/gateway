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

//! The client-matrix system under test: the filesystem reference backend behind a real listener.
//!
//! Responsible for: assembling `rustfs-gateway-fs` into a signed, plaintext S3 endpoint that any
//! third-party SDK can be pointed at, publishing the operation set that endpoint really registers,
//! and recording one wire-evidence line per served request.
//! NOT responsible for: production durability, TLS, deciding whether a scenario passed, or fixing
//! any gap a client finds — a matrix failure is fixed in the issue that owns the operation.
//! Upstream: `ci/compat/run_matrix.sh`, which starts it before any driver runs.
//! Downstream: the drivers under `compat/drivers/**` and `ci/compat/report.py`.
//!
//! ```text
//! compat-sut --data <dir> --port 9100 --probe-log <path>
//! compat-sut --print-capabilities
//! ```

mod probe;

use std::env;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustfs_gateway::{Credentials, RegionSet, S3Service, ServiceBuilder, SigV4Authenticator, StaticCredentials, allow_when};
use rustfs_gateway_fs::FsBackend;
use rustfs_gateway_server::{Server, ServerConfig};

use crate::probe::{ProbeLog, ProbeService};

/// Everything the launcher accepts. There are no defaults for the credential pair on purpose: a
/// matrix run whose driver and whose server disagree about the secret fails as `SignatureDoesNotMatch`
/// for every scenario at once, and a shared default is the easiest way to arrive there.
struct Options {
    data: PathBuf,
    address: SocketAddr,
    access_key: String,
    secret_key: String,
    region: String,
    probe_log: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            data: PathBuf::from("."),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9100),
            access_key: "AKIDEXAMPLE".to_owned(),
            secret_key: "secret".to_owned(),
            region: "us-east-1".to_owned(),
            probe_log: None,
        }
    }
}

fn parse_options<I, S>(arguments: I) -> Result<Options, io::Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut options = Options::default();
    let mut arguments = arguments.into_iter();
    let mut host = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut port = options.address.port();
    while let Some(argument) = arguments.next() {
        let mut value = || -> Result<String, io::Error> {
            arguments
                .next()
                .map(|found| found.as_ref().to_owned())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "an option is missing its value"))
        };
        match argument.as_ref() {
            "--data" => options.data = PathBuf::from(value()?),
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
            "--access-key" => options.access_key = value()?,
            "--secret-key" => options.secret_key = value()?,
            "--region" => options.region = value()?,
            "--probe-log" => options.probe_log = Some(PathBuf::from(value()?)),
            unknown => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unknown argument: {unknown}")));
            }
        }
    }
    options.address = SocketAddr::new(host, port);
    Ok(options)
}

/// The operation names the assembled service really registers.
///
/// This is the capability boundary the matrix consults: a scenario needing an operation absent
/// from this list is recorded as `unsupported` with that operation named, never as a pass and
/// never as a failure. It is read from the backend rather than written down twice, so the
/// declared boundary cannot drift away from the registry.
fn capability_names(backend: &FsBackend) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = backend.supported_operations().collect();
    names.sort_unstable();
    names
}

fn build_service(options: &Options, backend: &Arc<FsBackend>) -> Result<S3Service, Box<dyn std::error::Error>> {
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new(&options.access_key, options.secret_key.as_bytes())?));
    let supported = capability_names(backend);
    let builder = backend.register_crud(
        ServiceBuilder::new()
            .authenticator(SigV4Authenticator::new(credentials, RegionSet::new([options.region.clone()])?))
            // Not an allow-all: the matrix must see a refusal for anything outside the reference
            // backend's registered set, so that "the client asked for something we do not have"
            // is distinguishable from "the client asked correctly and we answered wrongly".
            .authorizer(allow_when(move |request| supported.contains(&request.operation))),
    );
    let service = backend
        .register_tagging(
            backend
                .register_lifecycle(backend.register_listing(backend.register_versioning(backend.register_multipart(builder)))),
        )
        .build()?;
    Ok(service)
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
    let backend = Arc::new(FsBackend::open(&options.data)?);
    let service = build_service(&options, &backend)?;

    let log = match options.probe_log.as_deref() {
        Some(path) => Some(Arc::new(ProbeLog::create(path)?)),
        None => None,
    };
    let config = ServerConfig {
        bind_addr: options.address,
        plaintext: true,
        ..ServerConfig::default()
    };

    // Both arms serve the same assembled service; only the evidence differs. The probe is opt-in
    // so that a driver being debugged by hand does not silently overwrite a matrix run's evidence.
    let running = match log.as_ref() {
        Some(log) => Server::new(config, ProbeService::new(service, Arc::clone(log))).serve()?,
        None => Server::new(config, service).serve()?,
    };
    // The banner is the readiness signal `ci/compat/run_matrix.sh` waits for. It names the port
    // that was actually bound, so `--port 0` is usable for a local run.
    println!("compat-sut listening on http://{}", running.local_addr);
    println!("compat-sut region {} access-key {}", options.region, options.access_key);

    tokio::signal::ctrl_c().await?;
    let report = running.shutdown.trigger(Duration::from_secs(30)).await;
    if let Some(log) = log.as_ref() {
        println!("compat-sut recorded {} probe record(s)", log.records());
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
mod tests {
    use super::parse_options;

    #[test]
    fn an_option_without_its_value_is_refused() {
        assert!(parse_options(["--port"]).is_err());
        assert!(parse_options(["--data"]).is_err());
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
}
