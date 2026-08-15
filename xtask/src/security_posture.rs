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

//! Standard security-posture preview.
//!
//! Responsible for: deriving the dry-run report from the real standard operation-floor sources.
//! NOT responsible for: observing a configured service; the runtime startup report owns that.
//! Upstream: core operation modules and the generated route-table operation names. Downstream:
//! release and deployment checks that inspect the standard, uncustomized posture.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Clone, Copy)]
struct ParsedFloor {
    presigned: bool,
}

pub(crate) fn command(args: &[String]) -> ExitCode {
    if args != ["--dry-run"] {
        eprintln!("security-posture accepts exactly --dry-run");
        return ExitCode::from(2);
    }

    match dry_run(repository_root()) {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("security-posture dry-run failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn dry_run(root: PathBuf) -> Result<String, String> {
    let floors = parse_standard_floors(&root.join("crates/core/src/ops"))?;
    let routed: BTreeSet<_> = rustfs_gateway_core::standard_operation_names()
        .into_iter()
        .map(str::to_owned)
        .collect();
    let parsed: BTreeSet<_> = floors.keys().cloned().collect();
    if parsed != routed {
        let missing: Vec<_> = routed.difference(&parsed).cloned().collect();
        let extra: Vec<_> = parsed.difference(&routed).cloned().collect();
        return Err(format!(
            "operation-floor inventory differs from the route table: missing={missing:?}, extra={extra:?}"
        ));
    }

    let presigned = floors
        .iter()
        .filter_map(|(name, floor)| floor.presigned.then_some(name.as_str()))
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "SECURITY_POSTURE anonymous_reachable_ops=[] custom_verifier=none sigv2=disabled presigned_allowed_ops=[{presigned}] aws_signature_verifier=built-in"
    ))
}

fn parse_standard_floors(directory: &Path) -> Result<BTreeMap<String, ParsedFloor>, String> {
    let entries = std::fs::read_dir(directory).map_err(|error| format!("cannot read {}: {error}", directory.display()))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read operation directory entry: {error}"))?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("rs")
            && path.file_name().and_then(|name| name.to_str()) != Some("mod.rs")
        {
            paths.push(path);
        }
    }
    paths.sort();

    let mut floors = BTreeMap::new();
    for path in paths {
        let source = std::fs::read_to_string(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let file = syn::parse_file(&source).map_err(|error| format!("cannot parse {}: {error}", path.display()))?;
        validate_operation_impl_uses_floor(&file, &path)?;
        let floor_items: Vec<_> = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Static(item) if item.ident == "FLOOR" => Some(item),
                _ => None,
            })
            .collect();
        if floor_items.len() != 1 {
            return Err(format!("{} must declare exactly one static FLOOR", path.display()));
        }
        let (name, floor) = parse_floor_expression(&floor_items[0].expr, &path)?;
        if floors.insert(name.clone(), floor).is_some() {
            return Err(format!("duplicate operation floor name {name}"));
        }
    }
    Ok(floors)
}

fn validate_operation_impl_uses_floor(file: &syn::File, path: &Path) -> Result<(), String> {
    let operation_impls: Vec<_> = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if item.trait_.as_ref().is_some_and(|(trait_path, _)| {
                    trait_path.segments.last().is_some_and(|segment| segment.ident == "Operation")
                }) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect();
    if operation_impls.len() != 1 || !operation_impls[0].attrs.is_empty() {
        return Err(format!("{} must contain one unconditional Operation impl", path.display()));
    }
    let floor_methods: Vec<_> = operation_impls[0]
        .items
        .iter()
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == "floor" => Some(method),
            _ => None,
        })
        .collect();
    if floor_methods.len() != 1 || !floor_methods[0].attrs.is_empty() {
        return Err(format!("{} Operation impl must contain one unconditional floor method", path.display()));
    }
    let [syn::Stmt::Expr(syn::Expr::Reference(reference), None)] = floor_methods[0].block.stmts.as_slice() else {
        return Err(format!("{} Operation::floor must directly return &FLOOR", path.display()));
    };
    let syn::Expr::Path(returned) = reference.expr.as_ref() else {
        return Err(format!("{} Operation::floor must directly return &FLOOR", path.display()));
    };
    if reference.mutability.is_some() || returned.path.segments.len() != 1 || returned.path.segments[0].ident != "FLOOR" {
        return Err(format!("{} Operation::floor must directly return &FLOOR", path.display()));
    }
    Ok(())
}

fn parse_floor_expression(expression: &syn::Expr, path: &Path) -> Result<(String, ParsedFloor), String> {
    let syn::Expr::Call(call) = expression else {
        return Err(unsupported_floor(path));
    };
    let syn::Expr::Path(function) = call.func.as_ref() else {
        return Err(unsupported_floor(path));
    };
    let segments: Vec<_> = function
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    if segments.len() != 2 || segments[0] != "OperationFloor" || call.args.len() != 2 {
        return Err(unsupported_floor(path));
    }
    let name = match call.args.first() {
        Some(syn::Expr::Lit(literal)) => match &literal.lit {
            syn::Lit::Str(value) => value.value(),
            _ => return Err(unsupported_floor(path)),
        },
        _ => return Err(unsupported_floor(path)),
    };
    let presigned = match segments[1].as_str() {
        "builtin" => false,
        "builtin_presigned" => true,
        _ => return Err(unsupported_floor(path)),
    };
    Ok((name, ParsedFloor { presigned }))
}

fn unsupported_floor(path: &Path) -> String {
    format!(
        "{} FLOOR must directly call OperationFloor::builtin or OperationFloor::builtin_presigned",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::validate_operation_impl_uses_floor;
    use std::path::Path;

    #[test]
    fn operation_impl_must_return_the_parsed_floor() {
        let file = syn::parse_file(
            r#"
                static FLOOR: OperationFloor = OperationFloor::builtin_presigned("GetObject", SigService::S3);
                static OTHER_FLOOR: OperationFloor = OperationFloor::builtin("GetObject", SigService::S3);
                impl Operation for GetObject {
                    fn floor() -> &'static OperationFloor { &OTHER_FLOOR }
                }
            "#,
        )
        .expect("fixture must parse");

        assert!(validate_operation_impl_uses_floor(&file, Path::new("get_object.rs")).is_err());
    }
}
