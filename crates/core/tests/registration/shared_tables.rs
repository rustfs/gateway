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

use super::*;

/// Positive — the same process holds two routers over two backends, and they answer differently.
///
/// This is the arrangement a process-global registry cannot express, and the reason `inventory` is
/// banned (ADR-0003): RustFS runs a fake target beside the production backend in one process.
#[test]
fn two_backends_coexist_in_one_process() {
    let production = Fs::new("us-east-1");
    let fake = Fs::new("test-region");
    let one = RouterBuilder::new()
        .handle::<GetBucketLocation, _>(Arc::clone(&production))
        .build()
        .expect("one");
    let two = RouterBuilder::new()
        .handle::<GetBucketLocation, _>(Arc::clone(&fake))
        .build()
        .expect("two");

    assert!(
        std::ptr::eq(one.table(), two.table()),
        "fixed routes are shared across backend registrations"
    );
    assert!(
        std::ptr::eq(one.compiled(), two.compiled()),
        "fixed compiled routes are shared across backend registrations"
    );

    let region_of = |router: &rustfs_gateway_core::Router| {
        let invocation = router
            .registry()
            .authorize_and_invoke_no_derived::<GetBucketLocation>(GetBucketLocationInput::default(), sse_proof())
            .expect("input authorization succeeds")
            .expect("registered");
        block_on(invocation)
            .expect("answered")
            .output()
            .expect("a settled answer")
            .location_constraint
            .as_ref()
            .map(|region| region.as_str().to_owned())
    };

    assert_eq!(region_of(&one).as_deref(), Some("us-east-1"));
    assert_eq!(region_of(&two).as_deref(), Some("test-region"));
}
