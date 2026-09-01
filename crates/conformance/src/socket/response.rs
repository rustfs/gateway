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

//! HTTP/1.1 response framing for the raw socket observer.
//!
//! Responsible for: decoding fixed-length and chunked response bodies without normalizing request
//! bytes. NOT responsible for: opening sockets or judging observations. Upstream: `super::Connection`.
//! Downstream: `crate::conn`.

use std::time::Duration;

use super::{Connection, RawResponse, ReadFailure, carries_a_body, find_head_end, parse_response_head};
use crate::sut::SutError;

impl Connection {
    /// Reads one HTTP/1.1 response: head, then its fixed or chunked body.
    ///
    /// # Errors
    ///
    /// Returns [`SutError::Environment`] when no complete response arrives. Callers that have to
    /// tell "nothing came" from "the peer hung up" apart use [`Connection::read_response_classified`].
    pub fn read_response(&mut self, timeout: Duration) -> Result<RawResponse, SutError> {
        self.read_response_classified("GET", timeout)
            .map_err(|failure| SutError::Environment(failure.to_string()))
    }

    /// Reads one response, naming how it failed to arrive when it did not.
    ///
    /// # Errors
    ///
    /// Returns the classification, which the caller turns into an [`crate::observation::Outcome`].
    pub fn read_response_classified(&mut self, method: &str, timeout: Duration) -> Result<RawResponse, ReadFailure> {
        let _ = self.stream.set_read_timeout(Some(timeout));
        let mut buffer = Vec::new();
        let head_end = loop {
            if let Some(end) = find_head_end(&buffer) {
                break end;
            }
            let read = match self.pull(&mut buffer) {
                Err(ReadFailure::TimedOut | ReadFailure::Reset) if !buffer.is_empty() => {
                    return Err(ReadFailure::Truncated);
                }
                result => result?,
            };
            if read == 0 {
                return Err(if buffer.is_empty() {
                    ReadFailure::ClosedBeforeHead
                } else {
                    ReadFailure::Truncated
                });
            }
        };
        let head = core::str::from_utf8(buffer.get(..head_end).unwrap_or_default())
            .map_err(|_| ReadFailure::Malformed("the response head is not UTF-8".to_owned()))?
            .to_owned();
        let (status, headers) = parse_response_head(&head)
            .ok_or_else(|| ReadFailure::Malformed("the response head is not a status line and headers".to_owned()))?;
        let mut body = buffer.split_off(head_end);
        let carries_body = carries_a_body(method, status);
        if carries_body && response_is_chunked(&headers)? {
            body = self.read_chunked_body(body)?;
            return Ok(RawResponse { status, headers, body });
        }
        let length = if carries_body {
            response_content_length(&headers)?
        } else {
            Some(0)
        };
        if let Some(length) = length {
            while body.len() < length {
                if self.pull_remainder(&mut body)? == 0 {
                    return Err(ReadFailure::Truncated);
                }
            }
            if body.len() > length {
                return Err(ReadFailure::Malformed("the response has bytes after the framed response body".to_owned()));
            }
            body.truncate(length);
        } else {
            body.clear();
        }
        Ok(RawResponse { status, headers, body })
    }

    fn read_chunked_body(&mut self, mut wire: Vec<u8>) -> Result<Vec<u8>, ReadFailure> {
        let mut body = Vec::new();
        loop {
            let line = self.read_crlf_line(&mut wire)?;
            let token = line.split(|byte| *byte == b';').next().unwrap_or_default();
            let token = core::str::from_utf8(token)
                .map_err(|_| ReadFailure::Malformed("the response chunk size is not ASCII".to_owned()))?;
            let size = usize::from_str_radix(token, 16)
                .map_err(|_| ReadFailure::Malformed("the response chunk size is invalid".to_owned()))?;
            if size == 0 {
                while !self.read_crlf_line(&mut wire)?.is_empty() {}
                if !wire.is_empty() {
                    return Err(ReadFailure::Malformed("the response has bytes after the framed response body".to_owned()));
                }
                return Ok(body);
            }
            let framed = size
                .checked_add(2)
                .ok_or_else(|| ReadFailure::Malformed("the response chunk size overflows".to_owned()))?;
            while wire.len() < framed {
                if self.pull_remainder(&mut wire)? == 0 {
                    return Err(ReadFailure::Truncated);
                }
            }
            body.extend(wire.drain(..size));
            if wire.get(..2) != Some(b"\r\n") {
                return Err(ReadFailure::Malformed("the response chunk has no CRLF terminator".to_owned()));
            }
            wire.drain(..2);
        }
    }

    fn read_crlf_line(&mut self, wire: &mut Vec<u8>) -> Result<Vec<u8>, ReadFailure> {
        loop {
            if let Some(end) = wire.windows(2).position(|window| window == b"\r\n") {
                if end > 16 * 1024 {
                    return Err(ReadFailure::Malformed("the response chunk line exceeds its limit".to_owned()));
                }
                let line = wire.drain(..end).collect();
                wire.drain(..2);
                return Ok(line);
            }
            if wire.len() > 16 * 1024 {
                return Err(ReadFailure::Malformed("the response chunk line exceeds its limit".to_owned()));
            }
            if self.pull_remainder(wire)? == 0 {
                return Err(ReadFailure::Truncated);
            }
        }
    }

    fn pull_remainder(&mut self, sink: &mut Vec<u8>) -> Result<usize, ReadFailure> {
        match self.pull(sink) {
            Err(ReadFailure::TimedOut | ReadFailure::Reset) => Err(ReadFailure::Truncated),
            result => result,
        }
    }
}

fn response_is_chunked(headers: &[(String, String)]) -> Result<bool, ReadFailure> {
    let tokens = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        return Ok(false);
    }
    if !tokens.last().is_some_and(|token| token.eq_ignore_ascii_case("chunked")) {
        return Err(ReadFailure::Malformed(
            "the response Transfer-Encoding is not terminated by chunked framing".to_owned(),
        ));
    }
    if tokens.len() != 1 {
        return Err(ReadFailure::Malformed(
            "only a single chunked coding is supported for response Transfer-Encoding".to_owned(),
        ));
    }
    Ok(true)
}

fn response_content_length(headers: &[(String, String)]) -> Result<Option<usize>, ReadFailure> {
    let mut length = None;
    for token in headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
    {
        let current = token
            .parse::<usize>()
            .map_err(|_| ReadFailure::Malformed("the response Content-Length is invalid".to_owned()))?;
        if length.is_some_and(|expected| expected != current) {
            return Err(ReadFailure::Malformed("the response has conflicting Content-Length values".to_owned()));
        }
        length = Some(current);
    }
    Ok(length)
}
