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

//! The switch census of the RustFS profile on the seam diff (rustfs/backlog#2751): the seam's
//! gateway turns on every request-handling switch the RustFS profile does, so it never measures
//! another profile.
//!
//! Responsible for: reading the switches of the gateway's two `rustfs_profile` preset halves and of
//! the `compat/sut` launcher's builder chain from their source, holding the seam stack's chain to
//! every one of them, and the negative controls proving the reading names a missing switch and
//! stops where a chain or a preset body ends.
//! NOT responsible for: the seam rows and their judgement (`seam.rs`), or assembling the stacks.
//! Upstream: the preset source, the launcher source, `src/seam/stacks.rs`. Downstream: none.

use std::collections::BTreeSet;

/// Chained calls of an assembly that the seam diff replaces by design: its own recording backend
/// and authenticator, an allow-all authorizer, a fixture owner, unlimited framework rates, no CORS
/// (neither the gateway's own answers nor legacy RustFS's), none of the reference backend's own
/// operation layers (its bucket-name registry), the request
/// identifiers, and the final build. Every other call of the RustFS profile's builder chain is a
/// switch.
///
/// The identifiers (`trace_source`, `identify_requests_as_legacy_rustfs`) change nothing the seam
/// converts: only the headers and error-document elements the service stamps on every answer, which
/// this diff reads as placeholders held to the minted format (`normalize`) and registered once for
/// every operation (`kd-encode-0001`, `kd-encode-0002`). The RustFS profile's identifiers are pinned
/// where they are measured: against the legacy stack in `crates/goldens` (`error_parity`), through
/// `compat/sut`'s own assembly (`request_id_tests`), and through the facade (`host_request_id`).
const ASSEMBLY_CALLS: [&str; 13] = [
    "authenticator",
    "authorizer",
    "security_floor",
    "framework_governor_rates",
    "bucket_owner_source",
    "cors_source",
    "cors_cache",
    "answer_cors_as_legacy_rustfs",
    "register_cors",
    "op_layer",
    "trace_source",
    "identify_requests_as_legacy_rustfs",
    "build",
];

/// The name of every chained call in `text`: each line that starts with `.name`.
fn chained_calls(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|line| line.trim_start().strip_prefix('.'))
        .map(|call| {
            call.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .next()
                .unwrap_or_default()
        })
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Every switch a builder chain in `text` turns on: each chained call of the chain that starts at
/// `ServiceBuilder::new()` and ends at its `.build()` (the whole text when it holds no such chain),
/// the assembly calls the seam diff replaces by design left out. Switches nested in the chain (the
/// authenticator's, the security floor's) are read with it.
fn profile_switches(text: &str) -> BTreeSet<String> {
    let chain = text.find("ServiceBuilder::new()").map_or(text, |start| {
        let rest = &text[start..];
        let end = rest
            .match_indices('\n')
            .map(|(at, _)| at + 1)
            .find(|&at| rest[at..].trim_start().starts_with(".build()"))
            .map_or(rest.len(), |at| at + rest[at..].find('\n').unwrap_or(rest.len() - at));
        &rest[..end]
    });
    chained_calls(chain)
        .into_iter()
        .filter(|name| !ASSEMBLY_CALLS.contains(&name.as_str()))
        .collect()
}

/// Every switch the two preset halves of the RustFS profile turn on (rustfs/backlog#2751): each
/// chained call inside a `fn rustfs_profile(` body of `text` — the body ends at its method's
/// closing brace, so the file's tests and its other items are not read — the assembly calls the
/// seam diff replaces by design left out.
fn preset_switches(text: &str) -> BTreeSet<String> {
    text.match_indices("fn rustfs_profile(")
        .map(|(start, _)| {
            let body = &text[start..];
            let end = body
                .match_indices('\n')
                .map(|(at, _)| at + 1)
                .find(|&at| body[at..].lines().next().is_some_and(|line| line == "    }"))
                .unwrap_or(body.len());
            chained_calls(&body[..end])
        })
        .fold(BTreeSet::new(), |mut all, calls| {
            all.extend(calls);
            all
        })
        .into_iter()
        .filter(|name| !ASSEMBLY_CALLS.contains(&name.as_str()))
        .collect()
}

/// The seam diff measures what RustFS will be handed, so its gateway runs every request-handling
/// switch of the RustFS profile, which is spelled once, as the gateway's two preset halves
/// (rustfs/backlog#2751); `compat/sut` runs the preset, and what it chains beside the preset is
/// the host's. A switch added to the preset, or to the launcher beside it, and not here fails,
/// instead of the diff silently measuring another profile. The seam does not call the preset
/// itself: the preset also turns on the identifiers and the legacy CORS answers, which the seam
/// replaces by design and which have no switch back.
#[test]
fn the_seam_diff_runs_every_switch_of_the_rustfs_profile() {
    let read = |path: &str| {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
        std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
    };
    let launcher = read("../../compat/sut/src/service.rs");
    let beside_the_preset = profile_switches(&launcher);
    assert!(
        beside_the_preset.contains("rustfs_profile"),
        "the launcher no longer runs the preset: {beside_the_preset:?}"
    );
    assert_eq!(
        launcher.matches(".rustfs_profile()").count(),
        2,
        "the launcher runs one half of the preset, not both"
    );
    let preset = preset_switches(&read("../../crates/gateway/src/builder/rustfs_profile.rs"));
    assert!(preset.len() >= 12, "the RustFS profile's switches were not found: {preset:?}");
    let profile: BTreeSet<&String> = preset
        .iter()
        .chain(beside_the_preset.iter())
        .filter(|name| name.as_str() != "rustfs_profile")
        .collect();
    // The whole seam stack: its authenticator is built before its builder chain.
    let seam = chained_calls(&read("src/seam/stacks.rs"));
    let missing: Vec<&&String> = profile.iter().filter(|name| !seam.contains(name.as_str())).collect();
    assert!(missing.is_empty(), "RustFS profile switches the seam diff does not turn on: {missing:?}");
}

/// Negative — the preset reading takes each `fn rustfs_profile(` body and nothing after its
/// closing brace: a chain in the file's tests is not a switch, and a file without the preset
/// names none.
#[test]
fn n_only_the_preset_bodies_are_read_for_switches() {
    let preset = preset_switches(
        "impl B {\n    pub fn rustfs_profile(mut self) -> Self {\n        self.floor = floor\n            .enable_sigv2_presigned_compatibility();\n        self.framework_governor_rates(r)\n            .clamp_oversized_max_keys()\n    }\n}\nimpl A {\n    pub fn rustfs_profile(self) -> Self {\n        self\n            .accept_any_signing_region()\n    }\n}\nmod tests {\n    fn t() {\n        B::new()\n            .with_skew_window(s)\n            .rustfs_profile();\n    }\n}\n",
    );
    assert_eq!(
        preset.into_iter().collect::<Vec<_>>(),
        [
            "accept_any_signing_region",
            "clamp_oversized_max_keys",
            "enable_sigv2_presigned_compatibility"
        ]
    );
    assert!(preset_switches("fn other() {\n    x\n        .clamp_oversized_max_keys()\n}\n").is_empty());
}

/// Negative — the switch reading names a missing switch.
#[test]
fn n_a_switch_the_profile_turns_on_and_the_seam_does_not_is_named() {
    let profile = profile_switches(
        "    ServiceBuilder::new()\n        .accept_all_checksum_omissions()\n        .slash_policy(SlashPolicy::RustfsLegacy)\n        .authorizer(A)\n        .build()",
    );
    assert_eq!(profile.into_iter().collect::<Vec<_>>(), ["accept_all_checksum_omissions", "slash_policy"]);
    let seam = profile_switches("        .accept_all_checksum_omissions()\n");
    assert_eq!(profile_switches("        .slash_policy(x)").difference(&seam).count(), 1);
}

/// Negative — a switch is read whatever its name says, the authenticator's and the floor's nested
/// in the chain included; what follows the chain's build, and the assembly the seam diff replaces,
/// are not switches.
#[test]
fn n_every_call_of_the_profile_chain_but_the_assembly_is_a_switch() {
    let profile = profile_switches(
        "fn options() -> O {\n    O::new()\n        .with_region(r)\n}\n    ServiceBuilder::new()\n        .authenticator(\n            A::new()\n                .verify_raw_paths_only_with_unencoded_bytes(),\n        )\n        .security_floor(F::new().with_presigned_expiry_rule(R))\n        .url_encode_listings_like_rustfs()\n        .legacy_rustfs_post_forms()\n        .register_cors(x)\n        .build()?;\n    later()\n        .not_a_switch()\n",
    );
    assert_eq!(
        profile.into_iter().collect::<Vec<_>>(),
        [
            "legacy_rustfs_post_forms",
            "url_encode_listings_like_rustfs",
            "verify_raw_paths_only_with_unencoded_bytes"
        ]
    );
}
