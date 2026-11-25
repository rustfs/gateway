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

//! Generates an isolated host-native admin dialect from a v2 inventory.
//!
//! Responsible for: reading the v2 native inventory, checking native S3 and control-plane
//! extension rows against reviewed operation contracts, computing table-local shadowing, and
//! driving native dialect file generation or `--check` verification.
//! NOT responsible for: collecting the inventory JSON, validating the goldens census (`goldens`),
//! or rendering individual Rust source strings (`super::native_pack`, `super::render`).
//! Upstream: `crates/goldens/src/migration_inventory/rustfs_admin_routes_native.json` and `super`.
//! Downstream: `crates/dialect-rustfs-admin/src/native/`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Deserialize;

use super::extension::{Claimer, Extended, QueryDiscriminator, Shadowed};
use super::{
    FORMAT, FORMS, Inventory, OUTPUT, QUERY_BUCKETS, Route, STAYS, Source, format_all, legacy_plan, modules, plan, render,
    retain, rulings,
};
use rustfs_gateway_core::route::generated_entries;

#[derive(Deserialize)]
struct InventoryV2 {
    format: String,
    source: Source,
    routes: Vec<Route>,
    extension_tables: RecordedTables,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedTables {
    s3: Vec<Row>,
    control_plane: Vec<Row>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    name: String,
    method: String,
    target: String,
    precedence: u16,
    query_discriminator: QueryDiscriminator,
    query_requires: Vec<QueryDiscriminator>,
    iam_action_wire: String,
    version_iam_action_wire: Option<String>,
    floor: String,
    source: String,
}

pub(super) struct Tables {
    pub(super) s3: Vec<Extended>,
    pub(super) control_plane: Vec<Extended>,
}

pub(super) fn group_order(inventory: &Inventory, group: &str) -> Option<u8> {
    match (inventory.native, group) {
        (true, "account_permissions") => Some(4),
        (true, "etag_handler") => Some(5),
        _ => None,
    }
}

fn sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

impl Row {
    fn checked(&self, legacy: &[Extended], listing: bool) -> Result<Extended, String> {
        let op = legacy
            .iter()
            .find(|op| op.operation == self.name)
            .ok_or_else(|| format!("{}: no reviewed operation type", self.name))?;
        let floor = match (op.claimer, op.presigned.is_some(), op.type_name.as_str()) {
            (Claimer::MetadataRoute, _, _) => "listing_floor",
            (_, true, _) => "presigned_floor",
            (_, _, "ListenBucketNotification" | "ListenNotification") => "floor.with_signed_event_list()",
            _ => "floor",
        };
        let expected = op.requires.iter().map(|(key, rule, _)| (key, rule));
        if listing != (op.claimer == Claimer::MetadataRoute)
            || op.method != self.method
            || op.target.as_str().to_ascii_lowercase() != self.target
            || self.query_discriminator.key != op.key
            || self.query_discriminator.rule != op.rule
            || !self.query_requires.iter().map(|r| (&r.key, &r.rule)).eq(expected)
            || self.iam_action_wire != op.action
            || self.version_iam_action_wire != op.version_action
            || self.floor != floor
        {
            return Err(format!("{}: native binding differs from the reviewed operation", self.name));
        }
        let (pin, path) = self
            .source
            .split_once(':')
            .ok_or_else(|| format!("{}: missing pinned operation source", self.name))?;
        if !sha(pin) || path != format!("crates/dialect-rustfs-admin/src/ops/{}.rs", op.stem) {
            return Err(format!("{}: source does not identify the reviewed operation", self.name));
        }
        let mut op = op.clone();
        op.precedence = self.precedence;
        op.router_url = format!("https://github.com/rustfs/gateway/blob/{pin}/{path}");
        op.shadows.clear();
        Ok(op)
    }
}

impl RecordedTables {
    fn checked(&self, legacy: &[Extended]) -> Result<Tables, String> {
        let mut names = BTreeSet::new();
        let mut pins = BTreeSet::new();
        let mut table = |rows: &[Row], listing| {
            if rows.is_empty() || rows.windows(2).any(|pair| pair[0].precedence >= pair[1].precedence) {
                return Err("empty or unordered native extension table".to_owned());
            }
            let mut out = Vec::new();
            for row in rows {
                let op = row.checked(legacy, listing)?;
                if !names.insert(op.operation.clone()) {
                    return Err(format!("{}: repeated native operation", op.operation));
                }
                pins.insert(row.source[..40].to_owned());
                out.push(op);
            }
            table_shadows(
                &mut out,
                |op| format!("This service checks the {} discriminator before the overlapping standard route.", op.key),
                |first, second| format!("This service checks {} before {}.", first.operation, second.operation),
            )?;
            Ok(out)
        };
        let tables = Tables {
            s3: table(&self.s3, true)?,
            control_plane: table(&self.control_plane, false)?,
        };
        if pins.len() != 1 {
            return Err("native extension tables reference different gateway revisions".to_owned());
        }
        Ok(tables)
    }
}

pub(super) fn table_shadows(
    extended: &mut [Extended],
    claim: fn(&Extended) -> String,
    reason: fn(&Extended, &Extended) -> String,
) -> Result<(), String> {
    let entries = generated_entries().map_err(|error| format!("the generated route table cannot be read: {error}"))?;
    for index in 0..extended.len() {
        let mut standard: Vec<(u16, &str)> = entries
            .iter()
            .filter(|entry| extended[index].overlaps_standard(entry.selector.predicates()))
            .map(|entry| (entry.precedence, entry.op_name))
            .collect();
        standard.sort_unstable();
        let claim = claim(&extended[index]);
        for (precedence, op) in standard {
            if precedence <= extended[index].precedence {
                return Err(format!(
                    "{}: its row at {} is behind the standard row {op} at {precedence}; an extension row is ahead of every \
                     standard row of its method and target",
                    extended[index].operation, extended[index].precedence
                ));
            }
            extended[index].shadows.push(Shadowed {
                op: op.to_owned(),
                reason: claim.clone(),
            });
        }
        for later in index + 1..extended.len() {
            if extended[index].overlaps_extension(&extended[later]) {
                let reason = reason(&extended[index], &extended[later]);
                let op = extended[later].operation.clone();
                extended[index].shadows.push(Shadowed { op, reason });
            }
        }
    }
    Ok(())
}

fn remove_dispatch(routes: &mut Vec<Route>, table: &[Extended]) -> Result<(), String> {
    let mut registered = BTreeSet::new();
    for op in table {
        if op.operation == "rustfs:InvokeObjectLambda" {
            continue; // Dispatched by the object handler without a registered admin path.
        }
        let value = op
            .rule
            .strip_prefix("equals:")
            .filter(|v| !v.is_empty())
            .map_or_else(String::new, |v| format!("={v}"));
        let target = match op.target {
            rustfs_gateway_core::route::TargetKind::Service => "",
            rustfs_gateway_core::route::TargetKind::Bucket => "{bucket}",
            _ => return Err(format!("{}: unsupported internal admin registration", op.operation)),
        };
        if !registered.insert((op.method.clone(), format!("?{}{value}/{target}", op.key))) {
            return Err("duplicate native query registration".to_owned());
        }
    }
    for route in routes.iter().filter(|r| r.path.starts_with('?')) {
        if route.group != "s3_extension"
            || route.auth_mode != "custom"
            || route.auth_detail.as_deref() != Some("S3Action")
            || !registered.remove(&(route.method.clone(), route.path.clone()))
        {
            return Err(format!("{} {}: unmatched native query registration", route.method, route.path));
        }
    }
    if !registered.is_empty() {
        return Err(format!("missing native query registrations: {registered:?}"));
    }
    routes.retain(|r| !r.path.starts_with('?'));
    Ok(())
}

/// Project admin registrations into the shared planner only after binding internal dispatch
/// keys to this host's actual control-plane service.
pub(super) fn generate(root: &Path, text: &str, installed: bool) -> Result<BTreeMap<PathBuf, String>, String> {
    let input: InventoryV2 = serde_json::from_str(text).map_err(|e| e.to_string())?;
    if input.format != "rustfs-admin-route-inventory/2" || !sha(&input.source.commit) {
        return Err("expected a v2 host inventory with a full source revision".to_owned());
    }
    let (_, legacy) = legacy_plan(root)?;
    let tables = input.extension_tables.checked(&legacy.extensions)?;
    let mut routes = input.routes;
    remove_dispatch(&mut routes, &tables.control_plane)?;
    let admin = Inventory {
        native: true,
        format: FORMAT.to_owned(),
        source: input.source,
        routes,
        extension_routes: vec![],
    };
    let mut native = plan(&admin, &rulings::native_rulings(), QUERY_BUCKETS, STAYS, FORMS, &[])?;
    retain(&mut native.declared, &rulings::native_retained())?;
    // Keep the public combined tables backed by their independent v1 inventory.
    super::unique_operations(&native.declared, &legacy.extensions)?;
    if installed {
        return super::native_pack::files(&native, legacy, &tables.s3, &tables.control_plane, &admin.source.commit);
    }
    native.extensions = legacy.extensions;
    let mut files = modules(&native, &admin.source.commit, render::render_native_operation);
    let separate = render::render_native_extensions(&tables.s3, &tables.control_plane, &admin.source.commit);
    files.insert(Path::new(OUTPUT).join("native_extensions.rs"), separate);
    format_all(root, files)
}

pub(super) fn write(root: &Path, files: &BTreeMap<PathBuf, String>) -> Result<(), String> {
    for (name, data) in files {
        let path = root.join(name);
        let parent = path.parent().ok_or_else(|| format!("invalid output: {}", path.display()))?;
        std::fs::create_dir_all(parent)
            .and_then(|()| std::fs::write(&path, data))
            .map_err(|e| format!("cannot write {}: {e}", name.display()))?;
    }
    Ok(())
}

pub(super) fn command(root: &Path, args: &[String]) -> ExitCode {
    let [_, inventory, output_flag, output, rest @ ..] = args else { return ExitCode::from(2) };
    if output_flag != "--output" || !(rest.is_empty() || rest == ["--check"]) {
        eprintln!("usage: cargo xtask rustfs-admin-dialect --native-inventory FILE --output DIRECTORY [--check]");
        return ExitCode::from(2);
    }
    let result = (|| {
        let contents = std::fs::read_to_string(inventory).map_err(|e| e.to_string())?;
        let requested = Path::new(output);
        let output = if requested.exists() {
            requested.canonicalize().map_err(|e| e.to_string())?
        } else {
            let parent = requested
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            parent
                .canonicalize()
                .map_err(|e| e.to_string())?
                .join(requested.file_name().ok_or("missing native output directory")?)
        };
        if output.starts_with(root.canonicalize().map_err(|e| e.to_string())?) {
            return Err("native generation requires a separate output directory".to_owned());
        }
        let files = generate(root, &contents, false)?;
        // An existing side tree may itself reference the checked-in generated files.
        for name in files.keys() {
            if name.ancestors().any(|part| output.join(part).is_symlink()) {
                return Err(format!("native output contains a symbolic link: {}", name.display()));
            }
        }
        if !rest.is_empty() {
            let drift = super::drift(&output, &files);
            if !drift.is_empty() {
                return Err(drift.join("\n"));
            }
        } else {
            write(&output, &files)?;
        }
        println!("rustfs-admin-dialect: {} native output files", files.len());
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rustfs-admin-dialect: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RecordedTables, remove_dispatch};
    use crate::rustfs_admin_dialect::tests::{recorded_plan, route};
    use serde_json::{Value, json};

    fn tables() -> Value {
        let source = |stem| format!("{}:crates/dialect-rustfs-admin/src/ops/{stem}.rs", "1".repeat(40));
        json!({
            "s3": [{
                "name":"rustfs:ListObjectsV2WithMetadata","method":"GET","target":"bucket","precedence":78,
                "query_discriminator":{"key":"list-type","rule":"equals:2"},"query_requires":[{"key":"metadata","rule":"equals:true"}],
                "iam_action_wire":"s3:ListBucket","floor":"listing_floor","source":source("list_objects_v2_with_metadata")
            }],
            "control_plane": [{
                "name":"rustfs:CheckReplication","method":"GET","target":"bucket","precedence":78,
                "query_discriminator":{"key":"replication-check","rule":"equals:"},"query_requires":[],
                "iam_action_wire":"s3:PutReplicationConfiguration","floor":"floor","source":source("check_replication")
            }]
        })
    }

    #[test]
    fn equal_native_precedences_in_different_services_have_no_cross_table_shadows() {
        let recorded: RecordedTables = serde_json::from_value(tables()).unwrap();
        let plan = recorded_plan();
        let checked = recorded.checked(&plan.extensions).unwrap();
        for ops in [&checked.s3, &checked.control_plane] {
            assert_eq!(ops[0].precedence, 78);
            assert!(!ops[0].shadows.is_empty());
            assert!(ops[0].shadows.iter().all(|shadow| !shadow.op.starts_with("rustfs:")));
        }
        let mut dispatch = route("GET", "?replication-check/{bucket}", "s3_extension", "custom", None);
        dispatch.auth_detail = Some("S3Action".to_owned());
        let normal = route("GET", "/rustfs/admin/v3/info", "system", "sigv4-admin", Some("admin:ServerInfo"));
        let mut unknown = vec![normal.clone()];
        assert!(remove_dispatch(&mut unknown, &checked.control_plane).is_err());
        let mut duplicate = vec![dispatch.clone(), dispatch.clone()];
        assert!(remove_dispatch(&mut duplicate, &checked.control_plane).is_err());
        let mut routes = vec![dispatch, normal];
        remove_dispatch(&mut routes, &checked.control_plane).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].path, "/rustfs/admin/v3/info");
    }

    #[test]
    fn native_rows_cannot_borrow_a_different_selector_policy_floor_or_source() {
        let plan = recorded_plan();
        for (field, value) in [
            ("name", json!("rustfs:GetBucketAcl")),
            ("method", json!("PUT")),
            ("target", json!("object")),
            ("query_discriminator", json!({"key":"replication-check","rule":"present"})),
            ("query_requires", json!([{"key":"metadata","rule":"equals:true"}])),
            ("iam_action_wire", json!("s3:ListBucket")),
            ("version_iam_action_wire", json!("s3:GetObjectVersion")),
            ("floor", json!("presigned_floor")),
            (
                "source",
                json!(format!("{}:crates/dialect-rustfs-admin/src/ops/check_replication.rs", "2".repeat(40))),
            ),
        ] {
            let mut raw = tables();
            raw["control_plane"][0][field] = value;
            let recorded: RecordedTables = serde_json::from_value(raw).unwrap();
            assert!(recorded.checked(&plan.extensions).is_err(), "{field}");
        }
    }
}
