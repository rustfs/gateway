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

//! The cases only the bundled in-process target can judge, as data.
//!
//! Responsible for: naming every case whose verdict reads a counter this target's own service
//! increments, or depends on a policy, provider or fault this target injects. Every case-id
//! literal in the in-process sources is in this table or in the census's list of cases configured
//! by id that an endpoint can still judge (`external_unavailable_tests` scans for them).
//! NOT responsible for: the hooks and configuration themselves (`super`, `super::security`,
//! `super::post_object`), or skipping (the external target asks [`unavailable_externally`]).
//! Upstream: the selected case id. Downstream: `crate::conn::external_fixture`.

/// Case id and why an external endpoint cannot answer for it.
pub(super) const IN_PROCESS_ONLY: &[(&str, &str)] = &[
    (
        "c-authz-0005",
        "judges that both authorization stages saw one snapshot, which only the in-process authorizer records",
    ),
    ("c-authz-0008", "counts ListObjectVersions dispatch under an in-process authorizer"),
    ("c-authz-1001", "counts copy-backend dispatch after an in-process authorization refusal"),
    ("c-authz-1009", "runs against a policy source the in-process target makes unreadable"),
    ("c-authz-1010", "runs against an in-process authorizer that answers Indeterminate"),
    ("c-authz-1011", "counts copy-backend dispatch after an in-process authorization refusal"),
    ("c-authz-1012", "counts copy-backend dispatch after an in-process authorization refusal"),
    ("c-authz-1014", "runs against an in-process policy source updated mid-request"),
    ("c-authz-1016", "counts ListObjectVersions dispatch under an in-process authorizer"),
    ("c-authz-1017", "counts ListObjectVersions dispatch under an in-process authorizer"),
    ("c-authz-1018", "counts copy-backend dispatch under an in-process Outposts decision"),
    ("c-cred-0002", "counts in-process credential-provider calls for an anonymous request"),
    (
        "c-cred-0005",
        "judges the closure credential-provider adapter the in-process target installs",
    ),
    ("c-cred-0006", "counts how many of 100 misses reach the in-process credential backend"),
    ("c-cred-0011", "runs against an in-process credential provider that fails"),
    (
        "c-cred-0012",
        "runs against an in-process credential provider that stalls past its deadline",
    ),
    (
        "c-cred-0023",
        "runs against an in-process credential provider that deletes the key after one lookup",
    ),
    ("c-cred-0024", "counts the in-process governor's credential-lookup classification"),
    ("c-cred-0028", "runs against an in-process credential provider that panics"),
    ("c-object-0049", "runs against an in-process bucket-owner source that is unavailable"),
    ("c-object-0050", "runs against an in-process bucket-owner source that is unavailable"),
    ("c-object-0052", "runs against an in-process policy that withholds ListBucket"),
    ("c-object-0053", "runs against an in-process HeadObject policy"),
    (
        "c-post-0020",
        "observes PostObjectInput::content_length at the in-process handler's entry",
    ),
    (
        "c-post-0026",
        "is refused because the reference fixture cannot provide KMS; an external host's managed encryption is not controlled by this case",
    ),
];

/// Why an external endpoint cannot answer for `case_id`; `None` for every other case.
pub(crate) fn unavailable_externally(case_id: &str) -> Option<String> {
    IN_PROCESS_ONLY
        .iter()
        .find(|(id, _)| *id == case_id)
        .map(|(id, why)| format!("{id} {why}; it is unavailable on an external endpoint, so the case is not run there"))
}
