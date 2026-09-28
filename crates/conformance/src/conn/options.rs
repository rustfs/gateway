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

//! The `[connection]` block of a socket exchange.
//! Responsible for: reading `[connection]` and refusing, by name, every instruction the socket
//! transports cannot carry out; `reuse` is the one honoured.
//! NOT responsible for: `[connection.tls]` on an authored HTTP/2 script, which `super::h2` reads
//! and removes before this runs.
//! Upstream: `super::Conn::exchange`, the external endpoint. Downstream: none.

use crate::sut::SutError;
use crate::value::Value;

/// Reads `[connection]`, refusing every instruction this transport cannot carry out.
///
/// `reuse` is the one that is honoured rather than refused, in both directions, and it is honoured
/// by actually opening a socket or actually keeping one.
pub(super) fn read_connection(connection: Option<&Value>) -> Result<bool, SutError> {
    let empty = Value::empty_table();
    let connection = connection.unwrap_or(&empty);
    if connection.read("connection.pipeline").and_then(Value::as_bool) == Some(true) {
        return Err(SutError::Environment(
            "`connection.pipeline = true` asks for the next request to be written before the \
             previous response is read. This transport can do that — but the case that declares it \
             asserts that two conditional creates *race*, and writing both requests onto one \
             connection does not make them race: this server reads one request off a connection, \
             answers it, and only then reads the next, and the fixture evaluates a condition and \
             commits under it inside one lock. The loser therefore meets an object that is simply \
             there, and `412` is the honest answer to a question the case did not ask. Reaching the \
             race needs a server that dispatches pipelined requests concurrently and a store with a \
             window between the check and the commit; neither is approximated here"
                .to_owned(),
        ));
    }
    if connection.read("connection.tls").is_some() {
        return Err(SutError::Environment(
            "`[connection.tls]` needs a TLS implementation; this transport writes cleartext bytes \
             on a TCP socket and negotiates nothing"
                .to_owned(),
        ));
    }
    if connection.read("connection.read_window_bytes").is_some() {
        return Err(SutError::Environment(
            "`connection.read_window_bytes` induces backpressure by leaving response bytes unread; \
             this client reads a response to its end before it judges anything, and a window it \
             declared but did not apply would report a server that ignored flow control as one that \
             honoured it"
                .to_owned(),
        ));
    }
    if connection.read("connection.idle_timeout_ms").is_some() {
        return Err(SutError::Environment(
            "`connection.idle_timeout_ms` times out an idle connection; this server holds a \
             connection open until its own generous read timeout and has no per-case idle bound"
                .to_owned(),
        ));
    }
    Ok(connection.read("connection.reuse").and_then(Value::as_bool).unwrap_or(true))
}
