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

//! `shadow-proxy --listen ADDR --upstream ADDR [--log FILE] [--queue N] [--body-cap BYTES]`.
//!
//! Responsible for: the command line, binding, and starting the judging thread and the proxy
//! (`rustfs_gateway_difftest::shadow`). Prints the address it listens on, then serves until
//! killed; each copied request's verdict goes to `--log` (default: standard output).
//! NOT responsible for: forwarding or judging (`shadow.rs`).
//! Upstream: an operator pointing clients at it. Downstream: an upstream S3 server.

use std::fs::File;
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc::sync_channel;

use rustfs_gateway_difftest::shadow::{Counters, Judge, Proxy, judge, judge_all};

const USAGE: &str = "usage: shadow-proxy --listen ADDR --upstream ADDR [--log FILE] [--queue N] [--body-cap BYTES]";

struct Options {
    listen: SocketAddr,
    upstream: SocketAddr,
    log: Option<String>,
    queue: usize,
    body_cap: usize,
}

fn parse(arguments: Vec<String>) -> Result<Options, String> {
    let (mut listen, mut upstream, mut log) = (None, None, None);
    let (mut queue, mut body_cap) = (1024, 16 << 20);
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        let value = arguments.next().ok_or_else(|| format!("{argument} needs a value\n{USAGE}"))?;
        let bad = |what: &str| format!("{argument} {value:?} is not {what}\n{USAGE}");
        match argument.as_str() {
            "--listen" => listen = Some(value.parse().map_err(|_| bad("an address"))?),
            "--upstream" => upstream = Some(value.parse().map_err(|_| bad("an address"))?),
            "--log" => log = Some(value),
            "--queue" => queue = value.parse().map_err(|_| bad("a count"))?,
            "--body-cap" => body_cap = value.parse().map_err(|_| bad("a number of bytes"))?,
            _ => return Err(format!("unknown argument {argument:?}\n{USAGE}")),
        }
    }
    Ok(Options {
        listen: listen.ok_or_else(|| format!("--listen is required\n{USAGE}"))?,
        upstream: upstream.ok_or_else(|| format!("--upstream is required\n{USAGE}"))?,
        log,
        queue,
        body_cap,
    })
}

fn main() -> ExitCode {
    let options = match parse(std::env::args().skip(1).collect()) {
        Ok(options) => options,
        Err(usage) => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    };
    let mut log: Box<dyn Write + Send> = match &options.log {
        Some(path) => match File::create(path) {
            Ok(file) => Box::new(file),
            Err(error) => {
                eprintln!("shadow-proxy: {path}: {error}");
                return ExitCode::from(2);
            }
        },
        None => Box::new(std::io::stdout()),
    };
    let listener = match TcpListener::bind(options.listen) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("shadow-proxy: {}: {error}", options.listen);
            return ExitCode::from(2);
        }
    };
    let (sender, receiver) = sync_channel(options.queue);
    let judge: Judge = Arc::new(judge);
    std::thread::spawn(move || judge_all(&receiver, &judge, log.as_mut()));
    let proxy = Arc::new(Proxy::new(options.upstream, options.body_cap, sender, Arc::new(Counters::default())));
    match listener.local_addr() {
        Ok(address) => eprintln!("shadow-proxy: listening on {address}, forwarding to {}", options.upstream),
        Err(error) => eprintln!("shadow-proxy: {error}"),
    }
    match proxy.serve(&listener) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("shadow-proxy: {error}");
            ExitCode::from(1)
        }
    }
}
