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

//! Optional overlay values distinguish omission from malformed declarations.
//!
//! Responsible for: exercising scalar types, numeric bounds and diagnostics through the loader.
//! NOT responsible for: protocol choices made by a valid overlay or the TOML grammar itself.
//! Upstream: overlay authoring and `Overlay::load`. Downstream: lowering and code generation.

use super::lower_tests::{MINI_OVERLAY, load, overlay_from};

fn refuses(text: &str, owner: &str, key: &str, expected: &str) {
    let error = overlay_from(text).expect_err("a present malformed optional value must not become absent");
    let message = error.to_string();
    assert!(
        message.contains(owner) && message.contains(key) && message.contains(expected),
        "{message}"
    );
}

#[test]
fn n_optional_operation_booleans_reject_other_types() {
    for key in [
        "auth_presigned",
        "http_checksum_required",
        "unwrapped_output",
        "body_literal",
        "allows_error_after_200",
    ] {
        for value in ["\"false\"", "0", "[]"] {
            refuses(&format!("{MINI_OVERLAY}\n{key} = {value}\n"), "op.GetThing", key, "boolean");
        }
    }
}

#[test]
fn n_optional_operation_strings_reject_other_types() {
    for key in [
        "method",
        "target",
        "path_shape",
        "host_class",
        "arn_form",
        "auth_requirement",
        "auth_service",
        "request_kind",
        "request_buffering",
        "response_kind",
        "response_buffering",
        "request_root",
        "response_root",
        "xmlns",
        "not_configured",
        "head_mirrors",
    ] {
        for value in ["false", "7", "[]"] {
            refuses(&format!("{MINI_OVERLAY}\n{key} = {value}\n"), "op.GetThing", key, "string");
        }
    }
    refuses(
        "include = [\"GetThing\"]\n[op.GetThing]\nprecedence = 100\nauth_action = false\n",
        "op.GetThing",
        "auth_action",
        "string",
    );
}

#[test]
fn n_optional_operation_integers_reject_other_types_and_out_of_range_values() {
    for (key, invalid) in [
        ("precedence", ["\"100\"", "false", "-1", "4294967296"]),
        ("success_status", ["\"200\"", "false", "-1", "65536"]),
        ("request_max_bytes", ["\"1024\"", "false", "-1", "[]"]),
        ("response_max_bytes", ["\"1024\"", "false", "-1", "[]"]),
    ] {
        for value in invalid {
            let text = if key == "precedence" {
                MINI_OVERLAY.replace("precedence = 100", &format!("precedence = {value}"))
            } else {
                format!("{MINI_OVERLAY}\n{key} = {value}\n")
            };
            refuses(&text, "op.GetThing", key, "integer");
        }
    }
}

#[test]
fn n_alternative_success_statuses_reject_non_arrays_and_invalid_entries() {
    for value in [
        "false",
        "200",
        "\"200\"",
        "[200, \"201\"]",
        "[200, false]",
        "[200, -1]",
        "[200, 65536]",
    ] {
        refuses(
            &format!("{MINI_OVERLAY}\nalt_success_statuses = {value}\n"),
            "op.GetThing",
            "alt_success_statuses",
            if value.starts_with('[') { "integer" } else { "array" },
        );
    }
}

#[test]
fn n_optional_shape_and_field_booleans_reject_other_types() {
    for owner in ["op.GetThing", "shape.Item"] {
        let side = if owner.starts_with("op.") { "side = \"input\"\n" } else { "" };
        for key in ["synthesize", "hot", "required", "default_bool"] {
            refuses(
                &format!("{MINI_OVERLAY}\n[[{owner}.field]]\nname = \"Marker\"\n{side}{key} = \"false\"\n"),
                &format!("{owner}.field `Marker`"),
                key,
                "boolean",
            );
        }
    }
    refuses(
        &format!("{MINI_OVERLAY}\n[shape.Item]\nsynthesize = \"false\"\n"),
        "shape.Item",
        "synthesize",
        "boolean",
    );
}

#[test]
fn n_optional_field_strings_and_signed_defaults_reject_other_types() {
    for owner in ["op.GetThing", "shape.Item"] {
        let side = if owner.starts_with("op.") { "side = \"input\"\n" } else { "" };
        for key in [
            "after",
            "wire_name",
            "binding",
            "type",
            "missing_error",
            "default_string",
            "omit_when",
            "omit_when_value",
            "omit_when_field",
            "omit_when_equals",
        ] {
            refuses(
                &format!("{MINI_OVERLAY}\n[[{owner}.field]]\nname = \"Marker\"\n{side}{key} = false\n"),
                &format!("{owner}.field `Marker`"),
                key,
                "string",
            );
        }
        refuses(
            &format!("{MINI_OVERLAY}\n[[{owner}.field]]\nname = \"Marker\"\n{side}default_int = \"-1\"\n"),
            &format!("{owner}.field `Marker`"),
            "default_int",
            "integer",
        );
    }
    refuses(
        &format!("{MINI_OVERLAY}\n[[shape.Item.field]]\nname = \"Key\"\nside = false\n"),
        "shape.Item.field `Key`",
        "side",
        "string",
    );
}

#[test]
fn n_optional_attribute_strings_reject_other_types() {
    for (key, extra) in [
        ("element", "value = \"constant\"\n"),
        ("field", "value = \"constant\"\n"),
        ("value", "field = \"Key\"\n"),
    ] {
        refuses(
            &format!("{MINI_OVERLAY}\n[[shape.Item.attribute]]\nname = \"mode\"\n{extra}{key} = false\n"),
            "shape.Item.attribute `mode`",
            key,
            "string",
        );
    }
}

#[test]
fn absent_optional_values_keep_the_declared_defaults() {
    let overlay = overlay_from(MINI_OVERLAY).expect("optional declarations may be absent");
    let operation = &overlay.ops["GetThing"];
    assert!(operation.auth_presigned.is_none() && operation.request.max_bytes.is_none());
    assert!(operation.success_status.is_none() && operation.alt_success_statuses.is_empty());
    assert!(
        load(MINI_OVERLAY).expect("omission remains valid").operations[0]
            .auth
            .presigned_allowed
    );
}

#[test]
fn valid_optional_values_keep_false_zero_and_numeric_boundaries() {
    let text = format!(
        "{}\nauth_presigned = false\nrequest_max_bytes = 0\nresponse_max_bytes = 9223372036854775807\n\
         success_status = 65535\nalt_success_statuses = [0, 65535]\nauth_service = \"sts\"\n\
         [[op.GetThing.field]]\nside = \"input\"\nname = \"Marker\"\nrequired = false\ndefault_int = -9223372036854775808\n\
         [shape.Item]\nsynthesize = false\n[[shape.Item.attribute]]\nname = \"mode\"\nvalue = \"constant\"\n",
        MINI_OVERLAY.replace("precedence = 100", "precedence = 4294967295")
    );
    let overlay = overlay_from(&text).expect("well-typed boundary values load");
    let operation = &overlay.ops["GetThing"];
    assert_eq!(operation.precedence, Some(u32::MAX));
    assert_eq!(operation.auth_presigned, Some(false));
    assert_eq!(operation.request.max_bytes, Some(0));
    assert_eq!(operation.response.max_bytes, Some(i64::MAX as u64));
    assert_eq!(operation.success_status, Some(u16::MAX));
    assert_eq!(operation.alt_success_statuses, [0, u16::MAX]);
    assert_eq!(operation.auth_service.as_deref(), Some("sts"));
    assert_eq!(operation.fields[0].required, Some(false));
    assert_eq!(operation.fields[0].default_int, Some(i64::MIN));
    assert!(!overlay.shapes["Item"].synthesize);
    assert_eq!(overlay.shapes["Item"].attributes[0].value.as_deref(), Some("constant"));
}
