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
//! (`rulings.rs`: ADR-0025's, ADR-0026's and ADR-0028's) to the custom-auth ones and ADR-0027's to
//! templates and overlaps, refusing any route it has no rule for and any rule outside those ADRs'
//! shapes, and writing one operation module per declared operation, the module list and the
//! dialect's table files, each through rustfmt.
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
use self::rulings::{About, Absent, RULINGS, Ruled, Ruling};
use crate::repo_root::repo_root;

mod render;
mod rulings;

const INVENTORY: &str = "crates/goldens/src/migration_inventory/rustfs_admin_routes.json";
const FORMAT: &str = "rustfs-admin-route-inventory/1";
/// Where the generated files go. `ops/` and `table/` are wholly generated; `table.rs` is the one
/// other file.
const OUTPUT: &str = "crates/dialect-rustfs-admin/src";
/// The directories under [`OUTPUT`] that hold nothing but generated files.
const GENERATED_DIRS: [&str; 2] = ["ops", "table"];
/// RustFS's admin router, whose `matchit` matcher tries a literal segment before a parameter.
const RUSTFS_ROUTER: &str = "rustfs/src/admin/router.rs";
const ADMIN_PREFIX: &str = "/rustfs/admin/";
const MINIO_PREFIX: &str = "/minio/admin/";
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
const MIGRATED_THROUGH: u8 = 4;

/// The template parameters ADR-0025 binds as the authorisation bucket. A route that carries one
/// waits for its group to take that binding; every other parameter is service-level (ADR-0027).
const BUCKET_PARAMS: &[&str] = &["bucket", "warehouse"];

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

/// The actions of a rule, owned.
enum Actions {
    One(String),
    AnyOf(Vec<String>),
}

/// An action rule, owned, and whose account it is about.
struct Rule {
    actions: Actions,
    about: Option<About>,
}

impl Rule {
    fn plain(action: String) -> Self {
        Self {
            actions: Actions::One(action),
            about: None,
        }
    }

    fn ruled(ruled: Ruled, about: Option<About>) -> Self {
        let actions = match ruled {
            Ruled::One(action) => Actions::One(action.to_owned()),
            Ruled::AnyOf(actions) => Actions::AnyOf(actions.iter().map(|action| (*action).to_owned()).collect()),
        };
        Self { actions, about }
    }

    /// Every action asked about a named account, in order.
    fn actions(&self) -> Vec<&str> {
        match &self.actions {
            Actions::One(action) => vec![action.as_str()],
            Actions::AnyOf(actions) => actions.iter().map(String::as_str).collect(),
        }
    }

    /// As the overlay records it, which is how `AuthRequirement::render` spells it.
    fn render(&self) -> String {
        let mut rendered = match &self.actions {
            Actions::One(action) => action.clone(),
            Actions::AnyOf(actions) => format!("anyOf({})", actions.join(", ")),
        };
        match self.about {
            Some(About::Caller) => rendered.push_str(" about caller"),
            Some(About::Query { param, aliases, absent }) => {
                let absent = match absent {
                    Absent::Caller => "caller",
                    Absent::Refuse => "refused",
                };
                let spellings: Vec<&str> = std::iter::once(param).chain(aliases.iter().copied()).collect();
                rendered.push_str(&format!(" about query({}, absent={absent})", spellings.join("|")));
            }
            Some(About::Set {
                param,
                everyone: Some((flag, action)),
            }) => rendered.push_str(&format!(" about each({param}, everyone={flag} ⇒ {action})")),
            Some(About::Set { param, everyone: None }) => rendered.push_str(&format!(" about each({param})")),
            None => {}
        }
        rendered
    }

    /// The subject rule as a Rust expression, when there is one.
    fn subject_expression(&self) -> Option<String> {
        self.about.map(|about| match about {
            About::Caller => "SubjectRule::Caller".to_owned(),
            About::Query { param, aliases, absent } => {
                let aliases: Vec<String> = aliases.iter().map(|alias| format!("{alias:?}")).collect();
                format!(
                    "SubjectRule::Query {{ param: {param:?}, aliases: &[{}], when_absent: WhenAbsent::{absent:?} }}",
                    aliases.join(", ")
                )
            }
            About::Set {
                param,
                everyone: Some((flag, action)),
            } => format!(
                "SubjectRule::Set {{ param: {param:?}, everyone: Some(Everyone {{ param: {flag:?}, action: {action:?} }}) }}"
            ),
            About::Set { param, everyone: None } => format!("SubjectRule::Set {{ param: {param:?}, everyone: None }}"),
        })
    }

    /// As a Rust expression; a subject rule is the module's `SUBJECT`.
    fn expression(&self) -> String {
        let requirement = match &self.actions {
            Actions::One(action) => format!("AuthRequirement::new({action:?}, ResourceShape::Service)"),
            Actions::AnyOf(actions) => {
                let listed: Vec<String> = actions.iter().map(|action| format!("{action:?}")).collect();
                format!("AuthRequirement::any_of(&[{}], ResourceShape::Service)", listed.join(", "))
            }
        };
        match self.about {
            Some(_) => format!("{requirement}.about_subject(SUBJECT)"),
            None => requirement,
        }
    }

    /// Why this rule is outside ADR-0025's and ADR-0026's shapes, or `None`. Registration refuses
    /// most of these too; refusing them here keeps a bad ruling from ever being generated.
    fn fault(&self, query: Option<(&str, &str)>) -> Option<&'static str> {
        let actions = self.actions();
        if !actions.iter().copied().all(is_action) {
            return Some("an action is spelled `service:Action`");
        }
        if let Actions::AnyOf(listed) = &self.actions
            && (listed.len() < 2
                || listed
                    .iter()
                    .enumerate()
                    .any(|(index, action)| listed[..index].contains(action)))
        {
            return Some("an any-of rule names at least two actions, each once");
        }
        let own = |action: &str| action.split_once(':').is_some_and(|(service, _)| service == VENDOR);
        match self.about {
            Some(About::Caller) => {
                return match &self.actions {
                    Actions::One(label) if own(label) => None,
                    _ => Some("an own-account operation names exactly one action, a label in the dialect's own namespace"),
                };
            }
            _ if actions.iter().copied().any(own) => {
                return Some("a label in the dialect's own namespace authorises only an own-account operation");
            }
            Some(About::Query { param, .. } | About::Set { param, .. }) if !is_parameter(param) => {
                return Some("a subject parameter is spelled in RFC 3986 unreserved characters");
            }
            Some(About::Query { param, .. } | About::Set { param, .. }) if query.is_some_and(|(key, _)| key == param) => {
                return Some("a subject parameter is not the query key that selects the form");
            }
            Some(About::Query { param, aliases, .. }) => {
                if !aliases.iter().copied().all(is_parameter) {
                    return Some("a subject parameter is spelled in RFC 3986 unreserved characters");
                }
                if aliases
                    .iter()
                    .enumerate()
                    .any(|(index, alias)| *alias == param || aliases[..index].contains(alias))
                {
                    return Some("a subject parameter's spellings are distinct from one another");
                }
                if query.is_some_and(|(key, _)| aliases.contains(&key)) {
                    return Some("a subject parameter is not the query key that selects the form");
                }
            }
            Some(About::Set {
                param,
                everyone: Some((flag, action)),
            }) => {
                if !is_parameter(flag) || flag == param {
                    return Some("a set rule's every-account flag is an unreserved parameter of its own");
                }
                if !is_action(action) || own(action) {
                    return Some("a set rule's every-account action is an IAM action spelled `service:Action`");
                }
                if matches!(self.actions, Actions::One(_)) && actions.contains(&action) {
                    return Some("a set rule's every-account action is one no named-account question already asks");
                }
            }
            _ => {}
        }
        None
    }
}

fn is_action(action: &str) -> bool {
    action
        .split_once(':')
        .is_some_and(|(service, name)| !service.is_empty() && !name.is_empty() && !name.contains(':'))
}

fn is_parameter(param: &str) -> bool {
    !param.is_empty()
        && param
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
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
    /// The template's parameters, in path order: service-level, never a bucket (ADR-0027).
    params: Vec<String>,
    /// The later operations this one stands in front of (ADR-0027).
    shadows: Vec<Shadow>,
}

/// A later operation whose parameter meets this operation's literal segment.
struct Shadow {
    shadowed: String,
    literal: String,
    param: String,
}

/// One segment of an inventory path: literal text, or a whole-segment `{parameter}`.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Segment<'a> {
    Literal(&'a str),
    Param(&'a str),
}

fn segments(path: &str) -> impl Iterator<Item = Segment<'_>> {
    path.split('/')
        .map(|segment| match segment.strip_prefix('{').and_then(|inner| inner.strip_suffix('}')) {
            Some(name) => Segment::Param(name),
            None => Segment::Literal(segment),
        })
}

/// Every declared operation, and every pending group with its route count.
struct Plan {
    declared: Vec<Declared>,
    pending: Vec<(String, u8, usize)>,
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

/// `Get` for `GET`, and each path word after `/rustfs/admin/` capitalised (a `{parameter}` as `By`
/// and its words), then the query value.
fn type_name(method: &str, path: &str, query: Option<(&str, &str)>) -> Option<String> {
    let rest = path.strip_prefix(ADMIN_PREFIX)?;
    let mut words = vec![method];
    for segment in segments(rest) {
        match segment {
            Segment::Param(param) => {
                words.push("By");
                words.extend(param.split('_'));
            }
            Segment::Literal(text) => words.extend(text.split(['-', '_', '.'])),
        }
    }
    words.extend(query.map(|(_, value)| value));
    let mut name = String::new();
    for word in words.into_iter().filter(|word| !word.is_empty()) {
        let mut chars = word.chars();
        let first = chars.next()?;
        if !first.is_ascii_alphanumeric() || !chars.as_str().chars().all(|c| c.is_ascii_alphanumeric()) {
            return None;
        }
        name.push(first.to_ascii_uppercase());
        name.push_str(&chars.as_str().to_ascii_lowercase());
    }
    name.starts_with(|c: char| c.is_ascii_uppercase()).then_some(name)
}

/// The file stem `check_op_file_shape.sh` expects: an underscore before every capital but the
/// first, then lowercase.
fn snake(name: &str) -> String {
    let mut stem = String::new();
    for (index, c) in name.chars().enumerate() {
        if index > 0 && c.is_ascii_uppercase() {
            stem.push('_');
        }
        stem.push(c.to_ascii_lowercase());
    }
    stem
}

/// A route's template parameters, in path order, under ADR-0027's rule: each is a whole segment
/// named by a lowercase identifier, the inventory lists exactly these, none repeats, and none is a
/// bucket, which waits for ADR-0025's binding.
fn template_params(route: &Route, at: &str) -> Result<Vec<String>, String> {
    let mut params: Vec<String> = Vec::new();
    for segment in segments(&route.path) {
        match segment {
            Segment::Literal(text) if text.contains(['{', '}']) => {
                return Err(format!("{at}: a parameter shares its segment with literal text"));
            }
            Segment::Literal(_) => {}
            Segment::Param(name) => {
                if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_') {
                    return Err(format!("{at}: the parameter {{{name}}} is not a lowercase identifier"));
                }
                if BUCKET_PARAMS.contains(&name) {
                    return Err(format!("{at}: {{{name}}} is a bucket, which waits for ADR-0025's bucket binding"));
                }
                if params.iter().any(|seen| seen == name) {
                    return Err(format!("{at}: the parameter {{{name}}} appears twice"));
                }
                params.push(name.to_owned());
            }
        }
    }
    if params != route.path_params {
        return Err(format!("{at}: the template names {params:?}, the inventory {:?}", route.path_params));
    }
    Ok(params)
}

/// Every pair of declared operations whose rows overlap, as `(winner, shadowed)` indices, under
/// ADR-0027's rule: a literal segment wins over a parameter, as in RustFS's router, and the
/// winner comes first in inventory order, so it has the lower precedence. An overlap that no
/// literal orders, or one whose literal comes later, is refused.
fn shadowing(declared: &[Declared]) -> Result<Vec<(usize, usize, Shadow)>, String> {
    let mut pairs = Vec::new();
    for (a, first) in declared.iter().enumerate() {
        for (b, second) in declared.iter().enumerate().skip(a + 1) {
            let queries_differ = matches!((first.query, second.query), (Some(x), Some(y)) if x != y);
            if first.method != second.method || queries_differ {
                continue;
            }
            let (x, y): (Vec<Segment<'_>>, Vec<Segment<'_>>) =
                (segments(&first.path).collect(), segments(&second.path).collect());
            if x.len() != y.len() {
                continue;
            }
            let (mut literal, mut first_wins, mut second_wins, mut disjoint) = (None, false, false, false);
            for pair in x.iter().zip(&y) {
                match pair {
                    (Segment::Literal(l), Segment::Literal(m)) if l != m => disjoint = true,
                    (Segment::Literal(l), Segment::Param(p)) => {
                        first_wins = true;
                        literal = literal.or(Some((*l, *p)));
                    }
                    (Segment::Param(_), Segment::Literal(_)) => second_wins = true,
                    _ => {}
                }
            }
            match (disjoint, first_wins, second_wins, literal) {
                (true, ..) => {}
                (false, true, false, Some((literal, param))) => pairs.push((
                    a,
                    b,
                    Shadow {
                        shadowed: second.name.clone(),
                        literal: literal.to_owned(),
                        param: param.to_owned(),
                    },
                )),
                (false, false, true, _) => {
                    return Err(format!(
                        "{} is shadowed by the later {}: a literal must come before the parameter it meets",
                        first.name, second.name
                    ));
                }
                _ => return Err(format!("{} and {} overlap, and no literal segment orders them", first.name, second.name)),
            }
        }
    }
    Ok(pairs)
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
        ("custom", Some(index)) => {
            let ruling = &rulings[index];
            used.insert(index);
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
                    let rule = Rule::ruled(form.rule, form.about);
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

/// Chooses and rules the routes, refusing every one it has no rule for.
fn plan(inventory: &Inventory, rulings: &[Ruling]) -> Result<Plan, String> {
    if inventory.format != FORMAT {
        return Err(format!("the inventory is {:?}, not {FORMAT:?}", inventory.format));
    }
    let order_of = |group: &str| PLAN.iter().find(|(name, _)| *name == group).map(|(_, order)| *order);
    let mut used = BTreeSet::new();
    let mut declared = Vec::new();
    let mut pending: BTreeMap<String, (u8, usize)> = BTreeMap::new();
    for route in &inventory.routes {
        let at = format!("{} {}", route.method, route.path);
        let order = order_of(&route.group).ok_or_else(|| format!("{at}: group {:?} has no place in the plan", route.group))?;
        if order > MIGRATED_THROUGH {
            pending.entry(route.group.clone()).or_insert((order, 0)).1 += 1;
            continue;
        }
        let params = template_params(route, &at)?;
        if !route.query_discriminators.is_empty() {
            return Err(format!("{at}: a query-discriminated route needs a ruling on its selector first"));
        }
        let forms = forms(route, &at, rulings, &mut used)?;
        let alias = match (route.minio_admin_alias, route.path.strip_prefix(ADMIN_PREFIX)) {
            (_, None) => return Err(format!("{at}: not under {ADMIN_PREFIX}")),
            (true, Some(rest)) => Some(format!("{MINIO_PREFIX}{rest}")),
            (false, Some(_)) => None,
        };
        let caller_secret = match route.caller_secret_body.as_str() {
            "none" => false,
            "request-on-minio-alias" | "response-on-minio-alias" | "request-and-response-on-minio-alias" => true,
            other => return Err(format!("{at}: unknown caller-secret class {other:?}")),
        };
        for (query, rule, ruled) in forms {
            let type_name = type_name(&route.method, &route.path, query).ok_or_else(|| format!("{at}: no operation name"))?;
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
                shadows: Vec::new(),
            });
        }
    }
    for (winner, _, shadow) in shadowing(&declared)? {
        declared[winner].shadows.push(shadow);
    }
    if let Some(stale) = (0..rulings.len()).find(|index| !used.contains(index)) {
        return Err(format!(
            "the ruling for {} {} names no custom-auth route of a migrated group",
            rulings[stale].method, rulings[stale].path
        ));
    }
    let mut names = BTreeSet::new();
    if let Some(twice) = declared.iter().find(|declared| !names.insert(declared.stem.clone())) {
        return Err(format!("two routes derive the operation {}", twice.name));
    }
    Ok(Plan {
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
    let plan = plan(&inventory, RULINGS)?;
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
#[path = "rustfs_admin_dialect/tests.rs"]
mod tests;
