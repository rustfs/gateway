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

//! `cargo xtask rustfs-admin-dialect`: the RustFS admin dialect's operations, generated from the
//! recorded route inventory (rustfs/backlog#1744).
//!
//! Responsible for: reading `crates/goldens/src/migration_inventory/rustfs_admin_routes.json`,
//! choosing the routes of the groups ADR-0024's plan has migrated, applying the rulings
//! (`rulings.rs`: ADR-0025's, ADR-0026's, ADR-0028's and ADR-0030's) to the custom-auth ones,
//! ADR-0027's to templates and overlaps, ADR-0030's bucket binding to `{bucket}` and `{warehouse}`
//! templates and the listed query parameters (`template.rs`), and ADR-0031's surfaces (the table
//! catalog's `/_iceberg/v1` with its `/iceberg/v1` compat rows as aliases), refusing any route it has no rule for and any rule
//! outside those ADRs' shapes, and writing one operation module per declared operation, the
//! module list and the dialect's table files, each through rustfmt.
//! `--check` compares instead, and fails on a stale, missing or extra file.
//! NOT responsible for: validating the inventory (goldens' strict reader does, and binds the
//! generated operations back to it), the claims or the shared shapes
//! (`crates/dialect-rustfs-admin/src/{dialect,admin}.rs`), or any handler.
//! Upstream: the recorded inventory. Downstream: `rustfs-gateway-dialect-rustfs-admin`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use serde::Deserialize;

use self::render::{render_mod, render_operation, render_tables};
use self::rule::{Rule, is_parameter};
use self::rulings::{QUERY_BUCKETS, RULINGS, Ruling, STAYS};
use self::template::{Shadow, Template, shadowing, snake, template_params, type_name};

use crate::repo_root::repo_root;

mod render;
mod rule;
mod rulings;
mod template;

const INVENTORY: &str = "crates/goldens/src/migration_inventory/rustfs_admin_routes.json";
const FORMAT: &str = "rustfs-admin-route-inventory/1";
/// Where the generated files go. `ops/` and `table/` are wholly generated; `table.rs` is the one
/// other file.
const OUTPUT: &str = "crates/dialect-rustfs-admin/src";
/// The directories under [`OUTPUT`] that hold nothing but generated files.
const GENERATED_DIRS: [&str; 2] = ["ops", "table"];
/// RustFS's admin router, whose `matchit` matcher tries a literal segment before a parameter.
const RUSTFS_ROUTER: &str = "rustfs/src/admin/router.rs";
/// One prefix RustFS serves admin routes under, its compat prefix, and how the inventory records
/// the compat spelling (ADR-0024 (c), ADR-0031 (b)).
struct Surface {
    /// The canonical prefix, with its trailing `/`.
    prefix: &'static str,
    /// The compat prefix RustFS serves the same routes under.
    alias: &'static str,
    /// The word after the method in an operation name, or nothing.
    tag: &'static str,
    /// Where the alias comes from.
    alias_from: AliasFrom,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AliasFrom {
    /// The route's own `minio_admin_alias` flag: RustFS registers the alias from the same row.
    Flag,
    /// A second inventory row under the compat prefix, identical in every other fact; it is the
    /// operation's alias row and is declared as no operation of its own.
    Twin,
}

/// The surfaces the dialect serves, each a pair of claims (`crate::dialect::CLAIMS`).
const SURFACES: &[Surface] = &[
    Surface {
        prefix: "/rustfs/admin/",
        alias: "/minio/admin/",
        tag: "",
        alias_from: AliasFrom::Flag,
    },
    Surface {
        prefix: "/_iceberg/v1/",
        alias: "/iceberg/v1/",
        tag: "Iceberg",
        alias_from: AliasFrom::Twin,
    },
    // The two profiling routes, each its own two-segment claim (ADR-0024, ADR-0032 (c)); RustFS
    // serves no compat spelling, so the flag is never set and the alias prefix is never used.
    Surface {
        prefix: "/profile/",
        alias: "/profile/",
        tag: "Profile",
        alias_from: AliasFrom::Flag,
    },
];
/// The dialect's vendor namespace: its operation names, and the only namespace an own-account
/// operation's label may be in (ADR-0025).
const VENDOR: &str = "rustfs";
const FIRST_PRECEDENCE: u16 = 100;

/// ADR-0024's migration plan: every registration group and its order. A group the inventory
/// gains is refused until it is placed here.
const PLAN: &[(&str, u8)] = &[
    ("system", 1),
    ("diagnostics", 2),
    ("profile_admin", 2),
    ("rebalance", 2),
    ("bucket_meta", 2),
    ("extensions", 2),
    ("module_switch", 2),
    ("object_data_cache", 2),
    ("cluster_snapshot", 2),
    ("gateway_key_inventory", 2),
    ("inspect_archive", 2),
    ("plugins_catalog", 2),
    ("tls_debug", 2),
    ("kms", 3),
    ("site_replication", 3),
    ("config_admin", 3),
    ("batch_job", 3),
    ("tier", 3),
    ("ilm_transition", 3),
    ("scanner", 3),
    ("audit", 3),
    ("plugins_instances", 3),
    ("pools", 3),
    ("user", 4),
    ("idp_compat", 4),
    ("mfa", 4),
    ("account", 4),
    ("replication_handler", 4),
    ("quota_handler", 5),
    ("on_demand_migration", 5),
    ("durability_handler", 5),
    ("heal", 5),
    ("usage_prefix", 5),
    ("table_catalog", 6),
    ("oidc", 7),
    ("sts", 7),
    ("object_zip_download", 7),
    ("health", 8),
];

/// The last migrated order: groups at or below it are declared, the rest are pending.
const MIGRATED_THROUGH: u8 = 8;

#[derive(Deserialize)]
struct Inventory {
    format: String,
    source: Source,
    routes: Vec<Route>,
}

#[derive(Deserialize)]
struct Source {
    commit: String,
}

#[derive(Clone, Deserialize)]
struct Route {
    method: String,
    path: String,
    group: String,
    path_params: Vec<String>,
    minio_admin_alias: bool,
    query_discriminators: Vec<serde_json::Value>,
    auth_mode: String,
    iam_action_wire: Option<String>,
    auth_detail: Option<String>,
    handler: String,
    handler_file: String,
    caller_secret_body: String,
    request_body: String,
    response_body: String,
}

/// One form a route is declared as: the query that selects it, its rule, and the custom-auth
/// class a ruling decided it for.
type Planned = (Option<(&'static str, &'static str)>, Rule, Option<String>);

/// One operation to generate.
struct Declared {
    type_name: String,
    stem: String,
    name: String,
    group: String,
    order: u8,
    method: String,
    path: String,
    alias: Option<String>,
    query: Option<(&'static str, &'static str)>,
    rule: Rule,
    ruled: Option<String>,
    handler: String,
    handler_url: String,
    router_url: String,
    caller_secret: bool,
    request_body: &'static str,
    response_body: &'static str,
    precedence: u16,
    /// The template's parameters, in path order, the bound bucket included (ADR-0027, ADR-0030).
    params: Vec<String>,
    /// The bucket the operation is authorised on, when it has one (ADR-0030).
    bucket: Option<Bound>,
    /// The later operations this one stands in front of (ADR-0027).
    shadows: Vec<Shadow>,
}

/// How an operation's bucket is named: a template parameter every row carries (ADR-0025 (c)) or a
/// query parameter read exactly once (ADR-0026 (e)).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Bound {
    Path(String),
    Query(&'static str),
}

impl Bound {
    /// The core value, as a Rust expression.
    fn expression(&self) -> String {
        match self {
            Self::Path(param) => format!("BucketParam::Path({param:?})"),
            Self::Query(param) => format!("BucketParam::Query({param:?})"),
        }
    }

    /// As `render_claimed_route` appends it to the rows.
    fn rendered(&self) -> String {
        match self {
            Self::Path(param) => format!(" ⇒ BucketParam({param:?})"),
            Self::Query(param) => format!(" ⇒ BucketQuery({param:?})"),
        }
    }
}

/// Every declared operation, and every pending group with its route count.
struct Plan {
    declared: Vec<Declared>,
    pending: Vec<(String, u8, usize)>,
    /// The routes that stay with RustFS: `(method, path, group, reason)` (ADR-0032 (b)).
    staying: Vec<(String, String, String, &'static str)>,
}

fn body_kind(recorded: &str, route: &Route) -> Result<&'static str, String> {
    match recorded {
        "not-read" => Ok("NotRead"),
        "buffered" => Ok("Buffered"),
        "streamed" => Ok("Streamed"),
        "handed-on" => Ok("HandedOn"),
        other => Err(format!("{} {}: unknown body kind {other:?}", route.method, route.path)),
    }
}

/// The forms `route` is declared as: its own action, or its ruling's forms.
fn forms(route: &Route, at: &str, rulings: &[Ruling], used: &mut BTreeSet<usize>) -> Result<Vec<Planned>, String> {
    let ruling = rulings
        .iter()
        .position(|ruling| ruling.method == route.method && ruling.path == route.path);
    match (route.auth_mode.as_str(), ruling) {
        ("sigv4-admin", None) => {
            let action = route
                .iam_action_wire
                .clone()
                .ok_or_else(|| format!("{at}: a sigv4-admin route records no action"))?;
            let rule = Rule::plain(action);
            match rule.fault(None) {
                Some(why) => Err(format!("{at}: {why}")),
                None => Ok(vec![(None, rule, None)]),
            }
        }
        (mode @ ("custom" | "anonymous"), Some(index)) => {
            let ruling = &rulings[index];
            used.insert(index);
            // Only a route the inventory records as anonymous opts in, and such a route never
            // stays privileged by a ruling's omission (ADR-0026 (f)).
            if ruling.forms.iter().any(|form| form.anonymous != (mode == "anonymous")) {
                return Err(format!(
                    "{at}: a ruling opts in to anonymous requests exactly when the inventory records an anonymous route"
                ));
            }
            if route.auth_detail.as_deref() != Some(ruling.auth_detail) {
                return Err(format!(
                    "{at}: ruled as {:?}, but the inventory now records {:?}",
                    ruling.auth_detail, route.auth_detail
                ));
            }
            ruling
                .forms
                .iter()
                .map(|form| {
                    let rule = Rule::ruled(form.rule, form.about, form.anonymous);
                    match rule.fault(form.query) {
                        Some(why) => Err(format!("{at}: {why}")),
                        None => Ok((form.query, rule, Some(ruling.auth_detail.to_owned()))),
                    }
                })
                .collect()
        }
        ("sigv4-admin", Some(_)) => Err(format!("{at}: a ruling for a route the inventory authorises itself")),
        (mode, None) => Err(format!("{at}: a {mode} route in a migrated group has no ruling")),
        (mode, Some(_)) => Err(format!("{at}: a {mode} route cannot be ruled by action alone")),
    }
}

/// The index of the route identical to `route` in every fact but its prefix, with `from` spelled
/// as `to`, or `None` (ADR-0031 (b)).
fn twin_of(inventory: &Inventory, route: &Route, from: &str, to: &str) -> Option<usize> {
    let rest = route.path.strip_prefix(from)?;
    let path = format!("{to}{rest}");
    inventory.routes.iter().position(|other| {
        other.method == route.method
            && other.path == path
            && other.group == route.group
            && other.path_params == route.path_params
            && other.query_discriminators == route.query_discriminators
            && other.auth_mode == route.auth_mode
            && other.iam_action_wire == route.iam_action_wire
            && other.auth_detail == route.auth_detail
            && other.handler == route.handler
            && other.caller_secret_body == route.caller_secret_body
            && other.request_body == route.request_body
            && other.response_body == route.response_body
            && !other.minio_admin_alias
    })
}

/// Chooses and rules the routes, refusing every one it has no rule for; `query_buckets` lists the
/// routes whose bucket is a query parameter (ADR-0030), and `stays` the routes that stay with
/// RustFS (ADR-0032).
fn plan(
    inventory: &Inventory,
    rulings: &[Ruling],
    query_buckets: &[(&str, &str, &'static str)],
    stays: &[(&str, &str, &'static str)],
) -> Result<Plan, String> {
    plan_through(MIGRATED_THROUGH, inventory, rulings, query_buckets, stays)
}

/// [`plan`] with the groups up to `through` migrated and the later ones pending. Every group of
/// ADR-0024's plan is migrated today, so only a group the inventory gains at a later order, or a
/// test, is pending.
fn plan_through(
    through: u8,
    inventory: &Inventory,
    rulings: &[Ruling],
    query_buckets: &[(&str, &str, &'static str)],
    stays: &[(&str, &str, &'static str)],
) -> Result<Plan, String> {
    if inventory.format != FORMAT {
        return Err(format!("the inventory is {:?}, not {FORMAT:?}", inventory.format));
    }
    let order_of = |group: &str| PLAN.iter().find(|(name, _)| *name == group).map(|(_, order)| *order);
    let mut used = BTreeSet::new();
    let mut used_query_buckets = BTreeSet::new();
    let mut declared = Vec::new();
    let mut pending: BTreeMap<String, (u8, usize)> = BTreeMap::new();
    let mut twins_used = BTreeSet::new();
    let mut staying = Vec::new();
    let mut stays_used = BTreeSet::new();
    for route in &inventory.routes {
        let at = format!("{} {}", route.method, route.path);
        let order = order_of(&route.group).ok_or_else(|| format!("{at}: group {:?} has no place in the plan", route.group))?;
        if order > through {
            pending.entry(route.group.clone()).or_insert((order, 0)).1 += 1;
            continue;
        }
        if let Some(index) = stays
            .iter()
            .position(|(method, path, _)| *method == route.method && *path == route.path)
        {
            stays_used.insert(index);
            staying.push((route.method.clone(), route.path.clone(), route.group.clone(), stays[index].2));
            continue;
        }
        let surface = SURFACES
            .iter()
            .find(|surface| route.path.starts_with(surface.prefix) || route.path.starts_with(surface.alias))
            .ok_or_else(|| format!("{at}: under no surface the dialect serves"))?;
        if surface.alias_from == AliasFrom::Twin && route.path.starts_with(surface.alias) {
            // The compat row of a canonical route: declared as that route's alias, below.
            let canonical = twin_of(inventory, route, surface.alias, surface.prefix)
                .ok_or_else(|| format!("{at}: a compat row whose canonical route the inventory does not record"))?;
            twins_used.insert(canonical);
            continue;
        }
        let Template { params, bucket } = template_params(route, &at)?;
        if !route.query_discriminators.is_empty() {
            return Err(format!("{at}: a query-discriminated route needs a ruling on its selector first"));
        }
        let query_bucket = query_buckets
            .iter()
            .position(|(method, path, _)| *method == route.method && *path == route.path)
            .map(|index| {
                used_query_buckets.insert(index);
                query_buckets[index].2
            });
        let bucket = match (bucket, query_bucket) {
            (Some(_), Some(_)) => return Err(format!("{at}: names its bucket twice, in the template and in the query")),
            (Some(param), None) => Some(Bound::Path(param)),
            (None, Some(param)) if !is_parameter(param) => {
                return Err(format!("{at}: a bucket query parameter is spelled in RFC 3986 unreserved characters"));
            }
            (None, Some(param)) => Some(Bound::Query(param)),
            (None, None) => None,
        };
        let forms = forms(route, &at, rulings, &mut used)?;
        let rest = route
            .path
            .strip_prefix(surface.prefix)
            .ok_or_else(|| format!("{at}: not under {}", surface.prefix))?;
        let alias = match surface.alias_from {
            AliasFrom::Flag if route.minio_admin_alias => Some(format!("{}{rest}", surface.alias)),
            AliasFrom::Flag => None,
            AliasFrom::Twin => {
                let twin = twin_of(inventory, route, surface.prefix, surface.alias)
                    .ok_or_else(|| format!("{at}: RustFS serves no identical route under {}", surface.alias))?;
                Some(inventory.routes[twin].path.clone())
            }
        };
        let caller_secret = match route.caller_secret_body.as_str() {
            "none" => false,
            "request-on-minio-alias" | "response-on-minio-alias" | "request-and-response-on-minio-alias" => true,
            other => return Err(format!("{at}: unknown caller-secret class {other:?}")),
        };
        for (query, rule, ruled) in forms {
            if let Some(Bound::Query(param)) = &bucket {
                if query.is_some_and(|(key, _)| key == *param) {
                    return Err(format!("{at}: a bucket query parameter is not the query key that selects the form"));
                }
                if rule.reads(param) {
                    return Err(format!("{at}: the bucket and the account are read from different query parameters"));
                }
            }
            let type_name =
                type_name(&route.method, surface, &route.path, query).ok_or_else(|| format!("{at}: no operation name"))?;
            let precedence = u16::try_from(declared.len())
                .ok()
                .and_then(|index| FIRST_PRECEDENCE.checked_add(index))
                .ok_or_else(|| format!("{at}: out of precedences"))?;
            declared.push(Declared {
                stem: snake(&type_name),
                name: format!("{VENDOR}:{type_name}"),
                type_name,
                group: route.group.clone(),
                order,
                method: route.method.clone(),
                path: route.path.clone(),
                alias: alias.clone(),
                query,
                rule,
                ruled,
                handler: route.handler.clone(),
                handler_url: format!("https://github.com/rustfs/rustfs/blob/{}/{}", inventory.source.commit, route.handler_file),
                router_url: format!("https://github.com/rustfs/rustfs/blob/{}/{RUSTFS_ROUTER}", inventory.source.commit),
                caller_secret,
                request_body: body_kind(&route.request_body, route)?,
                response_body: body_kind(&route.response_body, route)?,
                precedence,
                params: params.clone(),
                bucket: bucket.clone(),
                shadows: Vec::new(),
            });
        }
    }
    for (winner, _, shadow) in shadowing(&declared)? {
        declared[winner].shadows.push(shadow);
    }
    let _ = twins_used;
    // A staying route the inventory no longer records is refused only once every group is
    // migrated: until then its group may simply be pending.
    if pending.is_empty()
        && let Some(stale) = (0..stays.len()).find(|index| !stays_used.contains(index))
    {
        return Err(format!("the staying route {} {} is not in the inventory", stays[stale].0, stays[stale].1));
    }
    if let Some(stale) = (0..rulings.len()).find(|index| !used.contains(index)) {
        return Err(format!(
            "the ruling for {} {} names no custom-auth route of a migrated group",
            rulings[stale].method, rulings[stale].path
        ));
    }
    if let Some(stale) = (0..query_buckets.len()).find(|index| !used_query_buckets.contains(index)) {
        let (method, path, _) = query_buckets[stale];
        return Err(format!("the query bucket for {method} {path} names no route of a migrated group"));
    }
    let mut names = BTreeSet::new();
    if let Some(twice) = declared.iter().find(|declared| !names.insert(declared.stem.clone())) {
        return Err(format!("two routes derive the operation {}", twice.name));
    }
    Ok(Plan {
        staying,
        declared,
        pending: pending
            .into_iter()
            .map(|(group, (order, routes))| (group, order, routes))
            .collect(),
    })
}

/// `source` as the repository's rustfmt writes it.
fn rustfmt(root: &Path, source: &str) -> Result<String, String> {
    let mut child = Command::new("rustfmt")
        .current_dir(root)
        .args(["--edition", "2024", "--config-path"])
        .arg(root.join("rustfmt.toml"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot run rustfmt: {error}"))?;
    child
        .stdin
        .take()
        .ok_or("rustfmt has no stdin")?
        .write_all(source.as_bytes())
        .map_err(|error| format!("cannot write to rustfmt: {error}"))?;
    let output = child.wait_with_output().map_err(|error| format!("rustfmt failed: {error}"))?;
    if !output.status.success() {
        return Err(format!("rustfmt refused generated code: {}", String::from_utf8_lossy(&output.stderr)));
    }
    String::from_utf8(output.stdout).map_err(|_| "rustfmt wrote non-UTF-8".to_owned())
}

/// Every file through rustfmt, one rustfmt process per file, spread across the machine's cores:
/// one after another they cost the drift check most of its time.
fn format_all(root: &Path, files: BTreeMap<PathBuf, String>) -> Result<BTreeMap<PathBuf, String>, String> {
    let files: Vec<(PathBuf, String)> = files.into_iter().collect();
    let lanes = std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
    let per_lane = files.len().div_ceil(lanes).max(1);
    std::thread::scope(|scope| {
        let lanes: Vec<_> = files
            .chunks(per_lane)
            .map(|lane| {
                scope.spawn(move || {
                    lane.iter()
                        .map(|(path, source)| rustfmt(root, source).map(|formatted| (path.clone(), formatted)))
                        .collect::<Result<Vec<_>, String>>()
                })
            })
            .collect();
        let mut formatted = BTreeMap::new();
        for lane in lanes {
            formatted.extend(lane.join().map_err(|_| "a rustfmt lane panicked".to_owned())??);
        }
        Ok(formatted)
    })
}

/// Every generated file, by its path under the repository root.
fn generate(root: &Path) -> Result<BTreeMap<PathBuf, String>, String> {
    let recorded = std::fs::read_to_string(root.join(INVENTORY)).map_err(|error| format!("cannot read {INVENTORY}: {error}"))?;
    let inventory: Inventory = serde_json::from_str(&recorded).map_err(|error| format!("cannot parse {INVENTORY}: {error}"))?;
    let plan = plan(&inventory, RULINGS, QUERY_BUCKETS, STAYS)?;
    let output = Path::new(OUTPUT);
    let mut files = BTreeMap::new();
    for declared in &plan.declared {
        files.insert(output.join("ops").join(format!("{}.rs", declared.stem)), render_operation(declared));
    }
    files.insert(output.join("ops/mod.rs"), render_mod(&plan));
    for (path, source) in render_tables(&plan, &inventory.source.commit) {
        files.insert(output.join(path), source);
    }
    format_all(root, files)
}

/// Every generated file that differs from the committed one, is missing, or is committed without
/// being generated.
fn drift(root: &Path, files: &BTreeMap<PathBuf, String>) -> Vec<String> {
    let mut drifted = Vec::new();
    for (path, source) in files {
        match std::fs::read_to_string(root.join(path)) {
            Ok(committed) if committed == *source => {}
            Ok(_) => drifted.push(format!("{} is stale", path.display())),
            Err(_) => drifted.push(format!("{} is missing", path.display())),
        }
    }
    for dir in GENERATED_DIRS {
        let dir = Path::new(OUTPUT).join(dir);
        if let Ok(entries) = std::fs::read_dir(root.join(&dir)) {
            for entry in entries.flatten() {
                let path = dir.join(entry.file_name());
                if !files.contains_key(&path) {
                    drifted.push(format!("{} is not generated", path.display()));
                }
            }
        }
    }
    drifted.sort();
    drifted
}

/// `cargo xtask rustfs-admin-dialect [--check]`.
pub(crate) fn command(args: &[String]) -> ExitCode {
    let check = match args {
        [] => false,
        [flag] if flag == "--check" => true,
        _ => {
            eprintln!("usage: cargo xtask rustfs-admin-dialect [--check]");
            return ExitCode::from(2);
        }
    };
    let root = repo_root();
    let files = match generate(&root) {
        Ok(files) => files,
        Err(error) => {
            eprintln!("rustfs-admin-dialect: {error}");
            return ExitCode::FAILURE;
        }
    };
    let drifted = drift(&root, &files);
    if check {
        if drifted.is_empty() {
            println!("rustfs-admin-dialect: {} generated file(s) are current", files.len());
            return ExitCode::SUCCESS;
        }
        for line in drifted {
            eprintln!("rustfs-admin-dialect: {line}");
        }
        eprintln!("rustfs-admin-dialect: run `cargo xtask rustfs-admin-dialect` and commit the result");
        return ExitCode::FAILURE;
    }
    for line in drifted.iter().filter(|line| line.ends_with("is not generated")) {
        let stale = line.trim_end_matches(" is not generated");
        if let Err(error) = std::fs::remove_file(root.join(stale)) {
            eprintln!("rustfs-admin-dialect: cannot remove {stale}: {error}");
            return ExitCode::FAILURE;
        }
    }
    for (path, source) in &files {
        let target = root.join(path);
        let written = target
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| std::fs::write(&target, source));
        if let Err(error) = written {
            eprintln!("rustfs-admin-dialect: cannot write {}: {error}", path.display());
            return ExitCode::FAILURE;
        }
    }
    println!("rustfs-admin-dialect: wrote {} file(s)", files.len());
    ExitCode::SUCCESS
}

#[cfg(test)]
#[path = "rustfs_admin_dialect/bucket_tests.rs"]
mod bucket_tests;
#[cfg(test)]
#[path = "rustfs_admin_dialect/tests.rs"]
mod tests;
