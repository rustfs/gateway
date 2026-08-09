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

//! Offline rendering of the runtime route table's own explanation.
//!
//! Responsible for: accepting a request head, running the facade's host resolver and core route
//! table, then rendering their observations. NOT responsible for: reimplementing routing rules.
//! Upstream: the `route explain` command. Downstream: the public gateway diagnostic APIs.

#[cfg(test)]
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use http::Request;
use rustfs_gateway::{HostResolver, Limits, PathStyleOnly, VirtualHostStyle, WireRequest};
use rustfs_gateway_conformance::toml;
use rustfs_gateway_core::route::{
    Explanation, PROVISIONAL_SHADOWING, Predicate, RouteRequestParts, RouteTable, generated_entries,
};
#[cfg(test)]
use rustfs_gateway_core::route::{HostClass, TargetKind};

use crate::codegen::repo_root;

pub(crate) fn route(args: &[String]) -> ExitCode {
    let [subcommand, tail @ ..] = args else {
        return usage();
    };
    if subcommand != "explain" {
        return usage();
    }
    let (json, tail) = take_flag(tail, "--json");
    let Some(argument) = tail.first() else {
        return usage();
    };
    let mut input = if argument.contains(' ') {
        CaseRequest {
            head: argument.clone(),
            headers: Vec::new(),
        }
    } else {
        match request_from_case(argument) {
            Ok(request) => request,
            Err(error) => return fail_usage(&error),
        }
    };
    let options = match Options::parse(&tail[1..]) {
        Ok(options) => options,
        Err(error) => return fail_usage(error),
    };
    input.headers.extend(options.headers);
    let wire = match accepted_request(&input.head, &input.headers) {
        Ok(wire) => wire,
        Err(error) => return fail_usage(&error),
    };
    let resolved = if options.domains.is_empty() {
        PathStyleOnly.resolve(&rustfs_gateway::HostQuery {
            host: wire.host(),
            path: wire.raw_path().as_str(),
            method: wire.method(),
        })
    } else {
        let resolver = match VirtualHostStyle::new(&options.domains) {
            Ok(resolver) => resolver,
            Err(error) => return fail_usage(&error.to_string()),
        };
        resolver.resolve(&rustfs_gateway::HostQuery {
            host: wire.host(),
            path: wire.raw_path().as_str(),
            method: wire.method(),
        })
    };
    let table = match generated_entries()
        .map_err(|error| error.to_string())
        .and_then(|entries| RouteTable::build(entries, &PROVISIONAL_SHADOWING).map_err(|error| error.to_string()))
    {
        Ok(table) => table,
        Err(error) => return failure("runtime route table did not build", "generated route table", &error),
    };
    let path = wire.raw_path();
    let request = RouteRequestParts {
        method: wire.method(),
        path: path.as_str(),
        target: resolved.target,
        host_class: resolved.host_class,
        arn_form: resolved.arn_form,
        query: wire.query(),
        headers: wire.headers(),
    };
    let explanation = table.explain(&request);
    let candidates = candidates(&table, &request);
    if json {
        println!("{}", render_json(&explanation, &candidates));
    } else {
        print!("{}", explanation);
        print_candidates(&candidates);
    }
    if explanation.matched.is_some() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

struct Options {
    headers: Vec<(String, String)>,
    domains: Vec<String>,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self, &'static str> {
        let mut headers = Vec::new();
        let mut domains = Vec::new();
        for pair in args.chunks(2) {
            let [flag, value] = pair else {
                return Err("each route option needs a value");
            };
            match flag.as_str() {
                "--header" => {
                    let (name, value) = value.split_once(':').ok_or("header must be name:value")?;
                    headers.push((name.trim().to_owned(), value.trim().to_owned()));
                }
                "--domain" => domains.push(value.clone()),
                _ => return Err("expected --header name:value or --domain example.com"),
            }
        }
        Ok(Self { headers, domains })
    }
}

fn accepted_request(request: &str, headers: &[(String, String)]) -> Result<WireRequest<()>, String> {
    let (method, uri) = request.split_once(' ').ok_or("expected 'METHOD /path?query'")?;
    let mut builder = Request::builder().method(method).uri(uri);
    if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host")) {
        builder = builder.header("host", "localhost");
    }
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    let request = builder.body(()).map_err(|error| error.to_string())?;
    WireRequest::accept(request, &Limits::default()).map_err(|error| format!("{error:?}"))
}

struct Candidate {
    operation: &'static str,
    precedence: u16,
    predicates: Vec<(String, bool)>,
    matched: bool,
}

fn candidates(table: &RouteTable, request: &RouteRequestParts<'_>) -> Vec<Candidate> {
    table
        .entries()
        .iter()
        .filter_map(|entry| {
            let predicates: Vec<(String, bool)> = entry
                .selector
                .predicates()
                .iter()
                .map(|predicate| (predicate.to_string(), predicate.matches(request)))
                .collect();
            let same_route_family = entry
                .selector
                .predicates()
                .iter()
                .filter(|predicate| {
                    matches!(
                        predicate,
                        Predicate::Method(_) | Predicate::Target(_) | Predicate::HostClass(_) | Predicate::ArnForm(_)
                    )
                })
                .all(|predicate| predicate.matches(request));
            same_route_family.then_some(Candidate {
                operation: entry.op_name,
                precedence: entry.precedence,
                matched: predicates.iter().all(|(_, matched)| *matched),
                predicates,
            })
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn verify_operation_route(name: &str) -> Result<(), String> {
    let entries = generated_entries().map_err(|error| error.to_string())?;
    let entry = entries
        .iter()
        .find(|entry| entry.op_name == name)
        .ok_or_else(|| format!("the runtime table has no row for {name}"))?;
    let mut method = http::Method::GET;
    let mut target = TargetKind::Bucket;
    let mut host_class = HostClass::Standard;
    let mut arn_form = None;
    let mut path = None;
    let mut query = BTreeMap::new();
    let mut headers = BTreeMap::new();
    for predicate in entry.selector.predicates() {
        match predicate {
            Predicate::Method(value) => method = value.clone(),
            Predicate::Target(value) => target = *value,
            Predicate::QueryPresent(key) => {
                query.entry(*key).or_insert("");
            }
            Predicate::QueryEquals(key, value) => {
                query.insert(*key, *value);
            }
            Predicate::QueryAbsent(key) => {
                query.remove(key);
            }
            Predicate::HostClass(value) => host_class = *value,
            Predicate::PathLiteral(value) => path = Some(*value),
            Predicate::ArnForm(value) => arn_form = Some(*value),
            Predicate::HeaderPrefix(name, prefix) => {
                headers.insert(*name, format!("{prefix}x"));
            }
            Predicate::HeaderPresent { header, negated: false } => {
                headers.insert(*header, "x".to_owned());
            }
            Predicate::HeaderPresent { header, negated: true } => {
                headers.remove(header);
            }
        }
    }
    let path = path.unwrap_or(match target {
        TargetKind::Service => "/",
        TargetKind::Bucket => "/bucket",
        TargetKind::Object => "/bucket/key",
    });
    let query = query
        .into_iter()
        .map(|(key, value)| {
            if value.is_empty() {
                key.to_owned()
            } else {
                format!("{key}={value}")
            }
        })
        .collect::<Vec<_>>()
        .join("&");
    let uri = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    let head = format!("{method} {uri}");
    let headers: Vec<_> = headers.into_iter().map(|(name, value)| (name.to_owned(), value)).collect();
    let wire = accepted_request(&head, &headers)?;
    let raw_path = wire.raw_path();
    let request = RouteRequestParts {
        method: wire.method(),
        path: raw_path.as_str(),
        target,
        host_class,
        arn_form,
        query: wire.query(),
        headers: wire.headers(),
    };
    if !entry.selector.matches(&request) {
        return Err(format!("the generated witness does not satisfy {name}: {}", entry.selector));
    }
    let table = RouteTable::build(entries, &PROVISIONAL_SHADOWING).map_err(|error| error.to_string())?;
    match table.resolve(&request) {
        Some(selected) if selected.op_name == name => Ok(()),
        Some(selected) => Err(format!("the {name} witness selected {} instead", selected.op_name)),
        None => Err(format!("the {name} witness selected no operation")),
    }
}

fn render_json(explanation: &Explanation, candidates: &[Candidate]) -> String {
    let mut out = String::from("{");
    match &explanation.matched {
        Some(matched) => write!(out, "\"selected\":\"{}\",\"precedence\":{}", escape(matched.op_name), matched.precedence),
        None => write!(out, "\"selected\":null,\"precedence\":null"),
    }
    .expect("writing to String cannot fail"); // String's fmt::Write implementation is infallible.
    out.push_str(",\"conflict\":false,\"candidates\":[");
    for (index, candidate) in candidates.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        write!(
            out,
            "{{\"operation\":\"{}\",\"precedence\":{},\"matched\":{},\"predicates\":[",
            escape(candidate.operation),
            candidate.precedence,
            candidate.matched
        )
        .expect("writing to String cannot fail"); // String's fmt::Write implementation is infallible.
        for (predicate_index, (predicate, matched)) in candidate.predicates.iter().enumerate() {
            if predicate_index != 0 {
                out.push(',');
            }
            write!(out, "{{\"predicate\":\"{}\",\"matched\":{matched}}}", escape(predicate))
                .expect("writing to String cannot fail"); // String's fmt::Write implementation is infallible.
        }
        out.push_str("]}");
    }
    out.push_str("],\"shadowed\":[");
    for (index, shadowed) in explanation.shadowed.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        write!(
            out,
            "{{\"operation\":\"{}\",\"precedence\":{},\"reason\":\"{}\"}}",
            escape(shadowed.op_name),
            shadowed.precedence,
            escape(shadowed.reason.unwrap_or(""))
        )
        .expect("writing to String cannot fail"); // String's fmt::Write implementation is infallible.
    }
    out.push_str("]}");
    out
}

fn print_candidates(candidates: &[Candidate]) {
    for candidate in candidates {
        println!("candidate: {} (precedence={})", candidate.operation, candidate.precedence);
        for (predicate, matched) in &candidate.predicates {
            println!("  {matched:5} {predicate}");
        }
    }
}

fn take_flag(args: &[String], flag: &str) -> (bool, Vec<String>) {
    let mut args = args.to_vec();
    let index = args.iter().position(|argument| argument == flag);
    if let Some(index) = index {
        args.remove(index);
    }
    (index.is_some(), args)
}

struct CaseRequest {
    head: String,
    headers: Vec<(String, String)>,
}

fn request_from_case(id: &str) -> Result<CaseRequest, String> {
    let root = repo_root().join("conformance/cases");
    let mut files = Vec::new();
    collect_case_files(&root, &mut files)?;
    let path = files
        .into_iter()
        .find(|path| path.file_stem().and_then(|stem| stem.to_str()) == Some(id))
        .ok_or_else(|| format!("case `{id}` was not found"))?;
    let body = fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let document = toml::parse(&body).map_err(|error| format!("{}: {error}", path.display()))?;
    let request = document
        .path("request")
        .ok_or_else(|| format!("{} has no request table", path.display()))?;
    let method = request
        .get("method")
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("{} has no request method", path.display()))?;
    let target = request
        .get("target")
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("{} has no request target", path.display()))?;
    let headers = request
        .get("headers")
        .and_then(|value| value.as_table())
        .unwrap_or_default()
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|value| (name.clone(), value.to_owned()))
                .ok_or_else(|| format!("{} has a non-text request header `{name}`", path.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CaseRequest {
        head: format!("{method} {target}"),
        headers,
    })
}

fn collect_case_files(root: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(root).map_err(|error| format!("{}: {error}", root.display()))? {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path.is_dir() {
            collect_case_files(&path, files)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("toml") {
            files.push(path);
        }
    }
    Ok(())
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn fail_usage(error: &str) -> ExitCode {
    eprintln!("route explain: {error}");
    ExitCode::from(2)
}

fn failure(what: &str, where_: &str, rule: &str) -> ExitCode {
    eprintln!("what: {what}");
    eprintln!("where: {where_}");
    eprintln!("rule: a-xt-0023 runtime route table must reject ambiguous precedence; {rule}");
    ExitCode::FAILURE
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: cargo xtask route explain [--json] 'METHOD /path?query' \
         [--header name:value] [--domain example.com] | <case-id>"
    );
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use http::Method;
    use rustfs_gateway_core::{Predicate, RouteEntry, RouteSelector, RouteTable, ShadowingDecls, TargetKind};

    static SELECTOR: &[Predicate] = &[Predicate::Method(Method::GET), Predicate::Target(TargetKind::Bucket)];

    fn entry(name: &'static str) -> RouteEntry {
        RouteEntry {
            precedence: 7,
            selector: RouteSelector::new(SELECTOR),
            op_name: name,
            path_shape: "/{Bucket}",
        }
    }

    #[test]
    fn two_runtime_rows_at_one_precedence_are_a_conflict() {
        let error = RouteTable::build(vec![entry("One"), entry("Two")], &ShadowingDecls::NONE)
            .expect_err("the runtime table must reject equal-precedence overlap");
        assert!(error.to_string().contains("route conflict at precedence 7"));
    }
}
