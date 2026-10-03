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

//! Server tuning values and their validation.
//!
//! Responsible for: one serializable configuration with fail-closed transport validation.
//! NOT responsible for: applying socket or Hyper settings; `listener` and `conn` do that.
//! Upstream: deployment configuration. Downstream: every runtime module in this crate.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Semaphore;

/// Hyper's measured macro-load budget per open connection.
const ESTIMATED_BYTES_PER_CONNECTION: usize = 408 * 1024;
/// Hyper's minimum accepted HTTP/1 parser buffer ceiling.
const H1_MINIMUM_MAX_BUFFER_SIZE: usize = 8 * 1024;
/// RFC 9113's largest flow-control window.
const HTTP2_MAX_WINDOW_SIZE: u32 = (1 << 31) - 1;

/// Returns the conservative resident-memory budget for `connections` open connections.
#[must_use]
pub const fn conn_memory_budget(connections: usize) -> usize {
    connections.saturating_mul(ESTIMATED_BYTES_PER_CONNECTION)
}

/// Whether HTTP/1 writes use vectored I/O.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteStrategy {
    /// Let Hyper choose for the concrete transport.
    #[default]
    Auto,
    /// Force vectored writes on.
    Enabled,
    /// Force vectored writes off.
    Disabled,
}

/// All listener, HTTP connection, timeout and admission tuning.
///
/// A timeout longer than thirty years is armed as thirty years, as far as the runtime's timer goes,
/// so `Duration::MAX` reads as "never" rather than overflowing a deadline.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Address to bind. Increasing scope exposes more interfaces; decreasing it limits reachability.
    pub bind_addr: SocketAddr,
    /// Explicitly permits cleartext HTTP. Enabling reduces confidentiality; disabling requires TLS.
    pub plaintext: bool,
    /// Accept IPv4-mapped connections on an IPv6 listener. Enabling broadens reach; disabling isolates IPv6.
    pub dual_stack: bool,
    /// TCP keepalive probe interval. Increasing tolerates longer outages; decreasing detects dead peers sooner. Zero is invalid.
    pub tcp_keepalive: Option<Duration>,
    /// Disable Nagle. Enabling lowers small-response latency; disabling may reduce packet count.
    pub tcp_nodelay: bool,
    /// Requested receive-buffer bytes. Increasing absorbs bursts; decreasing lowers per-socket kernel memory.
    pub so_rcvbuf: Option<usize>,
    /// Requested send-buffer bytes. Increasing absorbs slow readers; decreasing lowers per-socket kernel memory.
    pub so_sndbuf: Option<usize>,
    /// Kernel accept backlog. Increasing absorbs connection bursts; decreasing limits queued unauthenticated peers.
    pub backlog: u32,
    /// Allow local-address reuse. Enabling eases restarts; disabling narrows accidental duplicate binds.
    pub reuse_address: bool,
    /// Global open-connection ceiling. Increasing raises capacity and memory; decreasing applies earlier backpressure.
    /// Values above the runtime semaphore maximum are invalid.
    pub max_connections: usize,
    /// Global in-flight request ceiling across HTTP/1 and HTTP/2 connections.
    /// Increasing raises concurrent handler and response memory; decreasing pauses listener acceptance sooner.
    /// Values above the runtime semaphore maximum are invalid.
    pub max_global_inflight_requests: usize,
    /// Optional per-IP open-connection ceiling. Increasing permits more NAT fan-in; decreasing limits single-source load.
    /// The bounded default is 256; setting `None` explicitly disables this protection.
    pub max_connections_per_ip: Option<usize>,
    /// Time from accept to complete headers. Increasing admits slower headers; decreasing rejects slowloris peers sooner.
    pub header_read_timeout: Duration,
    /// Maximum gap between successful response writes. Increasing tolerates stalls; decreasing releases stuck writers sooner.
    pub write_progress_timeout: Duration,
    /// Maximum no-I/O gap between requests. Increasing preserves reuse; decreasing releases idle connections sooner.
    pub keep_alive_idle: Duration,
    /// Total time a closing connection spends reading and discarding what the peer is still
    /// sending, so that the drop is a close and not a reset. Increasing tolerates peers with more
    /// left to send; decreasing releases the connection slot sooner. Zero is invalid — a drain
    /// that cannot read is the abortive close RFC 9112 §9.6 warns about. See `src/io.rs` for why
    /// this is a duration rather than a byte budget.
    pub lingering_close_time: Duration,
    /// Optional total connection lifetime. Increasing permits longer sessions; decreasing bounds leaked connections sooner. Zero is invalid.
    pub connection_lifetime: Option<Duration>,
    /// HTTP/1 parser buffer ceiling. Increasing admits larger heads; decreasing caps connection memory more tightly. The minimum is 8192.
    pub h1_max_buf_size: usize,
    /// Permit HTTP/1 reuse. Enabling avoids handshakes; disabling releases connections after one request.
    pub h1_keep_alive: bool,
    /// Coalesce pipelined HTTP/1 flushes. Enabling raises throughput; disabling can reduce response latency.
    pub h1_pipeline_flush: bool,
    /// Vectored-write policy. Enabling can reduce syscalls; disabling helps transports with poor writev support.
    pub write_strategy: WriteStrategy,
    /// HTTP/2 concurrent-stream ceiling. Increasing raises multiplexing and memory; decreasing limits per-connection work. Zero is invalid.
    pub h2_max_concurrent_streams: u32,
    /// HTTP/2 initial stream window bytes. Increasing raises throughput and memory; decreasing applies stream backpressure sooner.
    /// Values above 2147483647 violate the protocol limit.
    pub h2_initial_stream_window_size: u32,
    /// HTTP/2 initial connection window bytes. Increasing raises aggregate throughput; decreasing bounds buffered connection data.
    /// Values above 2147483647 violate the protocol limit.
    pub h2_initial_connection_window_size: u32,
    /// HTTP/2 frame ceiling. Increasing reduces framing overhead; decreasing limits each allocation.
    pub h2_max_frame_size: u32,
    /// HTTP/2 ping interval. Increasing lowers ping traffic; decreasing detects dead peers sooner. Zero is invalid.
    pub h2_keep_alive_interval: Option<Duration>,
    /// HTTP/2 ping acknowledgement timeout. Increasing tolerates jitter; decreasing releases dead peers sooner.
    pub h2_keep_alive_timeout: Duration,
    /// HTTP/2 header-list byte ceiling. Increasing admits larger metadata; decreasing caps decoder memory.
    pub h2_max_header_list_size: u32,
}

/// # Security
///
/// The default refuses to start without TLS. Cleartext requires setting [`ServerConfig::plaintext`]
/// to `true`, so omitting a TLS handle cannot silently expose credentials.
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            plaintext: false,
            dual_stack: true,
            tcp_keepalive: Some(Duration::from_secs(60)),
            tcp_nodelay: true,
            so_rcvbuf: None,
            so_sndbuf: None,
            backlog: 1024,
            reuse_address: true,
            max_connections: 10_000,
            max_global_inflight_requests: 10_000,
            max_connections_per_ip: Some(256),
            header_read_timeout: Duration::from_secs(10),
            write_progress_timeout: Duration::from_secs(30),
            keep_alive_idle: Duration::from_secs(65),
            lingering_close_time: Duration::from_secs(2),
            connection_lifetime: None,
            h1_max_buf_size: 64 * 1024,
            h1_keep_alive: true,
            h1_pipeline_flush: false,
            write_strategy: WriteStrategy::Auto,
            h2_max_concurrent_streams: 256,
            h2_initial_stream_window_size: 1024 * 1024,
            h2_initial_connection_window_size: 2 * 1024 * 1024,
            h2_max_frame_size: 16 * 1024,
            h2_keep_alive_interval: Some(Duration::from_secs(30)),
            h2_keep_alive_timeout: Duration::from_secs(20),
            h2_max_header_list_size: 64 * 1024,
        }
    }
}

impl ServerConfig {
    /// Validates all settings that would otherwise fail after the listener starts.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for a zero ceiling, a dependency-invalid bound, an invalid HTTP/2
    /// frame size, or an implicit cleartext transport.
    pub fn validate(&self, tls_configured: bool) -> Result<(), ConfigError> {
        self.validate_transport(tls_configured)?;
        if self.backlog == 0 {
            return Err(ConfigError::Zero("backlog"));
        }
        if self.max_connections == 0 {
            return Err(ConfigError::Zero("max_connections"));
        }
        if self.max_connections > Semaphore::MAX_PERMITS {
            return Err(ConfigError::MaxConnections {
                configured: self.max_connections,
                maximum: Semaphore::MAX_PERMITS,
            });
        }
        if self.max_global_inflight_requests == 0 {
            return Err(ConfigError::Zero("max_global_inflight_requests"));
        }
        if self.max_global_inflight_requests > Semaphore::MAX_PERMITS {
            return Err(ConfigError::MaxGlobalInFlightRequests {
                configured: self.max_global_inflight_requests,
                maximum: Semaphore::MAX_PERMITS,
            });
        }
        if self.max_connections_per_ip == Some(0) {
            return Err(ConfigError::Zero("max_connections_per_ip"));
        }
        if self.h2_max_concurrent_streams == 0 {
            return Err(ConfigError::Zero("h2_max_concurrent_streams"));
        }
        for (name, duration) in [
            ("header_read_timeout", self.header_read_timeout),
            ("write_progress_timeout", self.write_progress_timeout),
            ("keep_alive_idle", self.keep_alive_idle),
            ("lingering_close_time", self.lingering_close_time),
            ("h2_keep_alive_timeout", self.h2_keep_alive_timeout),
        ] {
            if duration.is_zero() {
                return Err(ConfigError::Zero(name));
            }
        }
        for (name, duration) in [
            ("tcp_keepalive", self.tcp_keepalive),
            ("connection_lifetime", self.connection_lifetime),
            ("h2_keep_alive_interval", self.h2_keep_alive_interval),
        ] {
            if duration.is_some_and(|duration| duration.is_zero()) {
                return Err(ConfigError::Zero(name));
            }
        }
        if self.h1_max_buf_size < H1_MINIMUM_MAX_BUFFER_SIZE {
            return Err(ConfigError::Http1BufferSize(self.h1_max_buf_size));
        }
        for (field, configured) in [
            ("h2_initial_stream_window_size", self.h2_initial_stream_window_size),
            ("h2_initial_connection_window_size", self.h2_initial_connection_window_size),
        ] {
            if configured > HTTP2_MAX_WINDOW_SIZE {
                return Err(ConfigError::Http2WindowSize { field, configured });
            }
        }
        if !(16_384..=16_777_215).contains(&self.h2_max_frame_size) {
            return Err(ConfigError::Http2FrameSize(self.h2_max_frame_size));
        }
        Ok(())
    }

    /// Verifies that cleartext operation was explicitly requested.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::TlsRequired`] when no TLS handle is present and `plaintext` is false.
    pub fn validate_transport(&self, tls_configured: bool) -> Result<(), ConfigError> {
        if tls_configured || self.plaintext {
            Ok(())
        } else {
            Err(ConfigError::TlsRequired)
        }
    }
}

/// Invalid server configuration.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    /// TLS was omitted without explicit cleartext acknowledgement.
    #[error("TLS is required unless plaintext is explicitly enabled")]
    TlsRequired,
    /// A ceiling or timeout that must be positive was zero.
    #[error("{0} must be greater than zero")]
    Zero(&'static str),
    /// The global limit exceeds Tokio's semaphore representation.
    #[error("max_connections {configured} exceeds the supported maximum {maximum}")]
    MaxConnections {
        /// Configured connection ceiling.
        configured: usize,
        /// Largest ceiling Tokio's semaphore accepts.
        maximum: usize,
    },
    /// The global in-flight request limit exceeds Tokio's semaphore representation.
    #[error("max_global_inflight_requests {configured} exceeds the supported maximum {maximum}")]
    MaxGlobalInFlightRequests {
        /// Configured in-flight request ceiling.
        configured: usize,
        /// Largest ceiling Tokio's semaphore accepts.
        maximum: usize,
    },
    /// Hyper rejects HTTP/1 parser buffers below eight KiB.
    #[error("HTTP/1 max buffer size {0} is below 8192")]
    Http1BufferSize(usize),
    /// An HTTP/2 flow-control window exceeds the protocol maximum.
    #[error("HTTP/2 {field} {configured} exceeds 2147483647")]
    Http2WindowSize {
        /// Name of the invalid window setting.
        field: &'static str,
        /// Configured window size.
        configured: u32,
    },
    /// HTTP/2 permits frame sizes only in its defined range.
    #[error("HTTP/2 max frame size {0} is outside 16384..=16777215")]
    Http2FrameSize(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_request_limit_is_bounded_by_tokios_semaphore() {
        assert!(ServerConfig::default().max_global_inflight_requests > 0);
        let zero = ServerConfig {
            max_global_inflight_requests: 0,
            ..ServerConfig::default()
        };
        assert_eq!(zero.validate(true), Err(ConfigError::Zero("max_global_inflight_requests")));
        let maximum = ServerConfig {
            max_global_inflight_requests: Semaphore::MAX_PERMITS,
            ..ServerConfig::default()
        };
        assert!(maximum.validate(true).is_ok());
        let above_maximum = ServerConfig {
            max_global_inflight_requests: Semaphore::MAX_PERMITS + 1,
            ..ServerConfig::default()
        };
        assert_eq!(
            above_maximum.validate(true),
            Err(ConfigError::MaxGlobalInFlightRequests {
                configured: Semaphore::MAX_PERMITS + 1,
                maximum: Semaphore::MAX_PERMITS,
            })
        );
    }
}
