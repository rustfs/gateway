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
//! every socket address through one bounded worker within an absolute setup deadline, and trying
//! each transport address.
//! Not responsible for: HTTP framing or judging observations. Upstream: `external`; downstream:
//! `external_tls`.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::OnceLock;
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::thread;
use std::time::Instant;

use super::external_tls::ExternalTransport;
use crate::socket::Connection;
use crate::sut::SutError;

type ResolverJob = Box<dyn FnOnce() + Send + 'static>;
const RESOLVER_QUEUE_CAPACITY: usize = 8;

enum ResolverOutcome {
    Complete(std::io::Result<Vec<SocketAddr>>),
    Deadline,
}

struct ResolverWorker {
    sender: SyncSender<ResolverJob>,
}

impl ResolverWorker {
    fn start() -> std::io::Result<Self> {
        // One executing job and this fixed queue are the complete resolver resource budget. The
        // standard-library resolver cannot be cancelled, so a permanently stalled call must make
        // later callers fail closed instead of allocating another native thread for each attempt.
        let (sender, receiver) = mpsc::sync_channel::<ResolverJob>(RESOLVER_QUEUE_CAPACITY);
        thread::Builder::new()
            .name("gateway-external-dns".to_owned())
            .spawn(move || {
                while let Ok(job) = receiver.recv() {
                    job();
                }
            })?;
        Ok(Self { sender })
    }

    fn submit(&self, job: ResolverJob, diagnostic: &str) -> Result<(), SutError> {
        self.sender.try_send(job).map_err(|error| match error {
            TrySendError::Full(_) => SutError::Environment(format!(
                "external endpoint `{diagnostic}` DNS resolver capacity is unavailable while the bounded worker is occupied"
            )),
            TrySendError::Disconnected(_) => {
                SutError::Environment(format!("external endpoint `{diagnostic}` DNS resolver worker ended unexpectedly"))
            }
        })
    }
}

fn resolver_worker() -> Result<&'static ResolverWorker, SutError> {
    static WORKER: OnceLock<Result<ResolverWorker, String>> = OnceLock::new();
    match WORKER.get_or_init(|| ResolverWorker::start().map_err(|error| error.to_string())) {
        Ok(worker) => Ok(worker),
        Err(error) => Err(SutError::Environment(format!("cannot start DNS resolver worker: {error}"))),
    }
}

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
        self.open_with_worker(
            deadline,
            resolver_worker()?,
            |authority| authority.to_socket_addrs().map(|resolved| resolved.collect()),
            |transport, address, attempt_deadline| transport.open(address, attempt_deadline),
        )
    }

    /// [`Self::open`] for an authored HTTP/2 script: TLS offers only ALPN `h2`.
    pub(super) fn open_h2(&self, deadline: Instant) -> Result<Connection, SutError> {
        self.open_with_worker(
            deadline,
            resolver_worker()?,
            |authority| authority.to_socket_addrs().map(|resolved| resolved.collect()),
            |transport, address, attempt_deadline| transport.open_h2(address, attempt_deadline),
        )
    }

    #[cfg(test)]
    fn open_with<R, C>(&self, deadline: Instant, resolver: R, connector: C) -> Result<Connection, SutError>
    where
        R: FnOnce(String) -> std::io::Result<Vec<SocketAddr>> + Send + 'static,
        C: FnMut(&ExternalTransport, SocketAddr, Instant) -> Result<Connection, SutError>,
    {
        let worker = ResolverWorker::start()
            .map_err(|error| SutError::Environment(format!("cannot start isolated DNS resolver worker: {error}")))?;
        self.open_with_worker(deadline, &worker, resolver, connector)
    }

    fn open_with_worker<R, C>(
        &self,
        deadline: Instant,
        worker: &ResolverWorker,
        resolver: R,
        mut connector: C,
    ) -> Result<Connection, SutError>
    where
        R: FnOnce(String) -> std::io::Result<Vec<SocketAddr>> + Send + 'static,
        C: FnMut(&ExternalTransport, SocketAddr, Instant) -> Result<Connection, SutError>,
    {
        let addresses = resolve_with_worker(worker, self.socket_authority.clone(), deadline, resolver)?;
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

fn resolve_with_worker<F>(
    worker: &ResolverWorker,
    socket_authority: String,
    deadline: Instant,
    resolver: F,
) -> Result<Vec<SocketAddr>, SutError>
where
    F: FnOnce(String) -> std::io::Result<Vec<SocketAddr>> + Send + 'static,
{
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| SutError::Environment("external endpoint setup deadline expired before DNS resolution".to_owned()))?;
    let diagnostic = socket_authority.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    worker.submit(
        Box::new(move || {
            let outcome = if Instant::now() >= deadline {
                ResolverOutcome::Deadline
            } else {
                ResolverOutcome::Complete(resolver(socket_authority))
            };
            let _ = sender.send(outcome);
        }),
        &diagnostic,
    )?;
    match receiver.recv_timeout(remaining) {
        Ok(ResolverOutcome::Complete(Ok(addresses))) => Ok(addresses),
        Ok(ResolverOutcome::Complete(Err(error))) => Err(SutError::Environment(format!(
            "external endpoint `{diagnostic}` could not be resolved: {error}"
        ))),
        Ok(ResolverOutcome::Deadline) => Err(SutError::Environment(format!(
            "external endpoint `{diagnostic}` DNS resolution exceeded the setup deadline"
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
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
        let worker = ResolverWorker::start().expect("start isolated resolver worker");
        let started = Instant::now();
        let deadline = started + Duration::from_millis(25);
        let (finished_sender, finished_receiver) = mpsc::sync_channel(1);

        let error = resolve_with_worker(&worker, "stalled.example:443".to_owned(), deadline, move |_| {
            thread::sleep(Duration::from_millis(200));
            finished_sender.send(()).expect("test still awaits resolver completion");
            Ok(Vec::new())
        })
        .expect_err("a resolver may not hold the case past its setup deadline");
        let elapsed = started.elapsed();

        assert!(error.to_string().contains("DNS resolution exceeded the setup deadline"));
        assert!(elapsed >= Duration::from_millis(25));
        assert!(elapsed < Duration::from_millis(100), "resolver timeout was not bounded: {elapsed:?}");
        finished_receiver
            .recv_timeout(Duration::from_millis(250))
            .expect("the stalled resolver eventually releases its worker");
    }

    #[test]
    fn n_repeated_timeouts_do_not_accumulate_resolver_workers() {
        let worker = ResolverWorker::start().expect("start isolated resolver worker");
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let (finished_sender, finished_receiver) = mpsc::sync_channel(1);

        let first_release = Arc::clone(&release);
        let first_calls = Arc::clone(&calls);
        let first = resolve_with_worker(
            &worker,
            "first-stalled.example:443".to_owned(),
            Instant::now() + Duration::from_millis(20),
            move |_| {
                first_calls.fetch_add(1, Ordering::SeqCst);
                let (lock, wake) = &*first_release;
                let blocked = lock.lock().expect("resolver release lock");
                let _released = wake
                    .wait_while(blocked, |released| !*released)
                    .expect("resolver release notification");
                finished_sender.send(()).expect("test still awaits resolver completion");
                Ok(Vec::new())
            },
        )
        .expect_err("the first resolver exceeds its caller deadline");

        let mut repeated = Vec::new();
        for attempt in 0..16 {
            let repeated_calls = Arc::clone(&calls);
            repeated.push(resolve_with_worker(
                &worker,
                format!("repeated-{attempt}.example:443"),
                Instant::now() + Duration::from_millis(20),
                move |_| {
                    repeated_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(Vec::new())
                },
            ));
        }

        let (lock, wake) = &*release;
        *lock.lock().expect("resolver release lock") = true;
        wake.notify_one();
        finished_receiver
            .recv_timeout(Duration::from_millis(200))
            .expect("the released resolver finishes");

        assert!(first.to_string().contains("DNS resolution exceeded the setup deadline"));
        assert!(repeated.iter().all(|result| {
            let error = result
                .as_ref()
                .expect_err("a busy resolver worker refuses additional work")
                .to_string();
            error.contains("DNS resolver capacity is unavailable") || error.contains("DNS resolution exceeded the setup deadline")
        }));

        let recovery_deadline = Instant::now() + Duration::from_millis(200);
        let recovered = loop {
            let recovery_calls = Arc::clone(&calls);
            match resolve_with_worker(
                &worker,
                "recovered.example:443".to_owned(),
                Instant::now() + Duration::from_millis(20),
                move |_| {
                    recovery_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(Vec::new())
                },
            ) {
                Err(error)
                    if error.to_string().contains("DNS resolver capacity is unavailable")
                        && Instant::now() < recovery_deadline =>
                {
                    thread::yield_now();
                }
                result => break result,
            }
        };

        assert!(recovered.is_ok(), "the resolver worker must accept work after the stalled call exits");
        assert_eq!(calls.load(Ordering::SeqCst), 2, "only the stalled and recovery jobs may start");
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
