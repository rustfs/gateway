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

//! `--external`: the observer in front of an S3 endpoint started elsewhere (rustfs/backlog#2758).
//!
//! Responsible for: parsing the endpoint URL, and forwarding each request to it unchanged —
//! method, origin-form target, every header including the `Host` the client signed, and the body
//! byte for byte — then handing the endpoint's own response back unchanged. Each response is
//! marked with who answered it, so the probe record says whether the endpoint or the observer
//! spoke.
//! NOT responsible for: signing, verifying or storing anything — no backend runs in this mode —
//! nor for recording the wire facts (`crate::probe`, which wraps this service as it wraps the
//! launcher's own), nor for judging a cell (`ci/compat/report.py`).
//! Upstream: `crate::main`. Downstream: the external endpoint, and `crate::probe::ProbeService`.
//!
//! Why the matrix observes an external endpoint instead of handing it to the clients directly:
//! the matrix grades wire facts from what the server side recorded, never from a driver's account
//! (`compat/README.md`), and an endpoint started elsewhere records nothing for it. The observer is
//! that record. It answers on its own only when the endpoint cannot be reached, with `502`, and
//! marks that answer as its own so the reporter refuses to grade a cell nobody measured.
//!
//! One HTTP/1.1 connection per request: the endpoint sees each request on a fresh connection, and
//! no state of one exchange can leak into the next. TLS, when a client needs it, terminates at the
//! observer's own encrypted listener; the endpoint is always dialled in plaintext.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt as _;
use http_body_util::combinators::BoxBody;
use hyper_util::rt::TokioIo;

/// The response body the observer hands back: the endpoint's stream, or its own short refusal.
pub(crate) type ForwardBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// How long the observer waits for the endpoint to accept a connection before answering `502`.
const CONNECT_DEADLINE: Duration = Duration::from_secs(10);

/// Who produced a response, carried in the response's extensions for the probe record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AnsweredBy {
    /// The external endpoint answered; the observer passed its response through.
    Upstream,
    /// The observer answered itself because the endpoint could not be reached or did not reply.
    Observer,
}

impl AnsweredBy {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Upstream => "upstream",
            Self::Observer => "observer",
        }
    }
}

/// An endpoint the observer can forward to: `http://host:port`, nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Upstream {
    host: String,
    port: u16,
    authority: String,
}

impl Upstream {
    /// Parses `http://host:port`, with an optional trailing `/`.
    ///
    /// A path, a query, credentials, another scheme or a missing port are refused rather than
    /// guessed: each would forward requests somewhere other than where the operator pointed.
    ///
    /// # Errors
    ///
    /// An invalid-input error naming what the URL lacks or carries.
    pub(crate) fn parse(raw: &str) -> io::Result<Self> {
        let invalid = |why: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("--external {raw:?}: {why}"));
        let rest = raw
            .strip_prefix("http://")
            .ok_or_else(|| invalid("only an http:// endpoint can be observed; the observer dials it in plaintext"))?;
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        if authority.contains(['/', '?', '#']) {
            return Err(invalid("the endpoint must be http://host:port, with no path or query"));
        }
        if authority.contains('@') {
            return Err(invalid("credentials do not belong in the endpoint URL"));
        }
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| invalid("the endpoint needs an explicit port"))?;
        if host.is_empty() {
            return Err(invalid("the endpoint needs a host"));
        }
        let port: u16 = port
            .parse()
            .map_err(|_| invalid("the port is not a number from 1 to 65535"))?;
        if port == 0 {
            return Err(invalid("the port is not a number from 1 to 65535"));
        }
        Ok(Self {
            host: host.trim_start_matches('[').trim_end_matches(']').to_owned(),
            port,
            authority: authority.to_owned(),
        })
    }

    /// `host:port`, as given.
    pub(crate) fn authority(&self) -> &str {
        &self.authority
    }
}

/// The forwarding service the observer's listeners serve.
#[derive(Clone)]
pub(crate) struct Forward {
    upstream: Arc<Upstream>,
}

impl Forward {
    pub(crate) fn new(upstream: Upstream) -> Self {
        Self {
            upstream: Arc::new(upstream),
        }
    }
}

type ForwardFuture = Pin<Box<dyn Future<Output = Result<Response<ForwardBody>, Infallible>> + Send>>;

impl<B> tower::Service<Request<B>> for Forward
where
    B: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<ForwardBody>;
    type Error = Infallible;
    type Future = ForwardFuture;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let upstream = Arc::clone(&self.upstream);
        Box::pin(async move {
            Ok(match exchange(&upstream, request).await {
                Ok(response) => response,
                Err(reason) => refusal(&reason),
            })
        })
    }
}

/// Sends `request` to the endpoint on a fresh connection and returns its response, marked.
async fn exchange<B>(upstream: &Upstream, request: Request<B>) -> Result<Response<ForwardBody>, String>
where
    B: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let stream = tokio::time::timeout(CONNECT_DEADLINE, tokio::net::TcpStream::connect((upstream.host.as_str(), upstream.port)))
        .await
        .map_err(|_| {
            format!(
                "the endpoint {} did not accept a connection within {CONNECT_DEADLINE:?}",
                upstream.authority
            )
        })?
        .map_err(|error| format!("the endpoint {} refused the connection: {error}", upstream.authority))?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|error| format!("the HTTP handshake with {} failed: {error}", upstream.authority))?;
    tokio::spawn(async move {
        // The connection ends when the response body has been read or dropped; an error here
        // surfaces to the client as a truncated body, which is what the endpoint did.
        let _ = connection.await;
    });
    let (mut parts, body) = request.into_parts();
    // Origin-form, exactly the path and query the client sent. The `Host` header is forwarded as
    // the client sent it, which is the value its signature covers.
    parts.uri = parts
        .uri
        .path_and_query()
        .map_or_else(|| http::Uri::from_static("/"), |target| http::Uri::from(target.clone()));
    parts.version = http::Version::HTTP_11;
    parts.extensions = http::Extensions::new();
    let response = sender
        .send_request(Request::from_parts(parts, body))
        .await
        .map_err(|error| format!("the endpoint {} did not answer: {error}", upstream.authority))?;
    let mut response = response.map(|body| body.map_err(Into::into).boxed());
    response.extensions_mut().insert(AnsweredBy::Upstream);
    Ok(response)
}

/// The observer's own answer when the endpoint could not be asked: `502`, marked as its own.
///
/// No `Server` header, so nothing reading the answer can mistake it for the endpoint's.
fn refusal(reason: &str) -> Response<ForwardBody> {
    eprintln!("compat-sut: {reason}");
    let body = http_body_util::Full::new(Bytes::from(format!("compat-sut --external: {reason}\n")))
        .map_err(|never: Infallible| match never {})
        .boxed();
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::BAD_GATEWAY;
    response
        .headers_mut()
        .insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("text/plain"));
    response.extensions_mut().insert(AnsweredBy::Observer);
    response
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::Upstream;

    /// Positive — the accepted spellings, and the authority each one dials.
    #[test]
    fn an_http_endpoint_with_a_port_is_accepted() {
        for (raw, authority, host, port) in [
            ("http://127.0.0.1:9000", "127.0.0.1:9000", "127.0.0.1", 9000),
            ("http://127.0.0.1:9000/", "127.0.0.1:9000", "127.0.0.1", 9000),
            ("http://rustfs.local:9100", "rustfs.local:9100", "rustfs.local", 9100),
            ("http://[::1]:9000", "[::1]:9000", "::1", 9000),
        ] {
            let upstream = Upstream::parse(raw).expect("an observable endpoint");
            assert_eq!(
                (upstream.authority(), upstream.host.as_str(), upstream.port),
                (authority, host, port),
                "{raw}"
            );
        }
    }

    /// Negative — a port of zero names no endpoint.
    #[test]
    fn n_port_zero_is_refused() {
        assert!(Upstream::parse("http://127.0.0.1:0").is_err());
    }
}
