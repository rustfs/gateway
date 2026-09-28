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

//! Responsible for: the `corpus` command line — `ingest`, `verify` and `to-case` — and
//! the process exit classes those verdicts map onto.
//! Not responsible for: any policy. Every refusal in this file comes from the library;
//! the binary only chooses what to print and which exit code to return.
//! Upstream: a shell, `scripts/check_corpus_*.sh`, and CI.
//! Downstream: `rustfs_gateway_corpus`.

use std::path::PathBuf;
use std::process::ExitCode;

use rustfs_gateway_corpus::case;
use rustfs_gateway_corpus::dedup;
use rustfs_gateway_corpus::redact;
use rustfs_gateway_corpus::schema;
use rustfs_gateway_corpus::store;

const USAGE: &str = "usage:
  corpus ingest <input.jsonl>... --into <corpus-dir> [--sanitize] [--cap N]
  corpus verify <corpus-dir> [--strict]
  corpus to-case <corpus-dir-or-file.jsonl> [--check-roundtrip]

`ingest` refuses any entry that still carries credential material. `--sanitize` first
rewrites the credential-bearing carriers it knows and records them in the entry's
`redacted` list; a body finding stays a refusal under either mode, except the
`chunk-signature` and `x-amz-trailer-signature` carriers of a request that declares
aws-chunked framing, which are rewritten in place.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("ingest") => ingest(&args[1..]),
        Some("verify") => verify(&args[1..]),
        Some("to-case") => to_case(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn positional(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--into" || arg == "--cap" {
            skip_next = true;
            continue;
        }
        if arg.starts_with("--") {
            continue;
        }
        out.push(arg.clone());
    }
    out
}

fn ingest(args: &[String]) -> ExitCode {
    let inputs = positional(args);
    let Some(into) = flag_value(args, "--into") else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    if inputs.is_empty() {
        eprintln!("corpus ingest: no input file given");
        return ExitCode::from(2);
    }
    let sanitize = args.iter().any(|arg| arg == "--sanitize");
    let cap = flag_value(args, "--cap")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(dedup::DEFAULT_BUCKET_CAP);

    let root = PathBuf::from(&into);
    let mut entries = match store::load_all(&root) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("corpus ingest: {error}");
            return ExitCode::FAILURE;
        }
    };
    let carried_over = entries.len();

    let mut refused = 0usize;
    let mut sanitized_fields = 0usize;
    for input in &inputs {
        let text = match std::fs::read_to_string(input) {
            Ok(text) => text,
            Err(error) => {
                eprintln!("corpus ingest: {input}: {error}");
                return ExitCode::FAILURE;
            }
        };
        let loaded = match schema::load_jsonl(&text) {
            Ok(loaded) => loaded,
            Err(error) => {
                eprintln!("corpus ingest: {input}:{error}");
                return ExitCode::FAILURE;
            }
        };
        for (index, mut entry) in loaded.into_iter().enumerate() {
            let line = index + 1;
            if let Err(reason) = store::check_source(&entry.src) {
                eprintln!("corpus ingest: {input}:{line}: {reason}");
                refused += 1;
                continue;
            }
            if sanitize {
                sanitized_fields += redact::sanitize(&mut entry).len();
            }
            match redact::admit(&entry) {
                Ok(()) => entries.push(entry),
                Err(refusal) => {
                    for finding in refusal.findings {
                        eprintln!("corpus ingest: {input}:{line}: {finding}");
                    }
                    refused += 1;
                }
            }
        }
    }

    if refused > 0 {
        eprintln!("corpus ingest: refused {refused} entry/entries; nothing was written");
        return ExitCode::FAILURE;
    }

    let (buckets, report) = dedup::bucketize(entries, cap);
    if let Err(error) = store::write(&root, &buckets) {
        eprintln!("corpus ingest: cannot write {into}: {error}");
        return ExitCode::FAILURE;
    }
    println!(
        "OK: {} bucket(s), {} entries retained ({carried_over} carried over, {} duplicates dropped, {} over cap, {sanitized_fields} field(s) sanitized)",
        buckets.iter().filter(|bucket| !bucket.entries.is_empty()).count(),
        report.retained,
        report.duplicates,
        report.over_cap,
    );
    ExitCode::SUCCESS
}

fn verify(args: &[String]) -> ExitCode {
    let Some(root) = positional(args).first().cloned() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let strict = args.iter().any(|arg| arg == "--strict");
    let root = PathBuf::from(root);
    match store::verify(&root) {
        Ok(report) => {
            if report.entries == 0 {
                println!("no corpus: {} holds no entries yet", root.display());
                return if strict { ExitCode::FAILURE } else { ExitCode::SUCCESS };
            }
            println!(
                "OK: {} bucket(s), {} entries, {} chunk-framed, {} source(s), {} bytes, schema v{}",
                report.buckets,
                report.entries,
                report.chunk_framed,
                report.sources,
                report.bytes,
                schema::CORPUS_SCHEMA_VERSION,
            );
            if report.bytes > store::SOFT_SIZE_LIMIT_BYTES {
                eprintln!(
                    "warning: {} bytes is over the {}-byte soft target",
                    report.bytes,
                    store::SOFT_SIZE_LIMIT_BYTES
                );
            }
            ExitCode::SUCCESS
        }
        Err(violations) => {
            for violation in &violations {
                eprintln!("corpus verify: {violation}");
            }
            eprintln!("corpus verify: {} violation(s)", violations.len());
            ExitCode::FAILURE
        }
    }
}

fn to_case(args: &[String]) -> ExitCode {
    let Some(target) = positional(args).first().cloned() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let check_roundtrip = args.iter().any(|arg| arg == "--check-roundtrip");
    let path = PathBuf::from(&target);
    let entries = if path.is_dir() {
        match store::load_all(&path) {
            Ok(entries) => entries,
            Err(error) => {
                eprintln!("corpus to-case: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        match std::fs::read_to_string(&path)
            .map_err(|error| error.to_string())
            .and_then(|text| schema::load_jsonl(&text).map_err(|error| error.to_string()))
        {
            Ok(entries) => entries,
            Err(error) => {
                eprintln!("corpus to-case: {target}: {error}");
                return ExitCode::FAILURE;
            }
        }
    };

    let mut converted = 0usize;
    let mut skipped = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        let id = format!("c-draft-{:04}", index + 1);
        match case::to_case(entry, &id) {
            Ok(draft) => {
                if check_roundtrip {
                    match case::roundtrips(entry) {
                        Ok(true) => {}
                        Ok(false) => {
                            eprintln!("corpus to-case: {id}: chunk sequence did not survive the round trip");
                            return ExitCode::FAILURE;
                        }
                        Err(error) => {
                            eprintln!("corpus to-case: {id}: {error}");
                            return ExitCode::FAILURE;
                        }
                    }
                } else {
                    print!("{}", draft.render());
                }
                converted += 1;
            }
            Err(error) => {
                eprintln!("corpus to-case: {id}: skipped: {error}");
                skipped += 1;
            }
        }
    }
    if check_roundtrip {
        println!("OK: lossless, {converted} draft(s), {skipped} skipped");
    } else {
        eprintln!("{converted} draft(s), {skipped} skipped");
    }
    ExitCode::SUCCESS
}
