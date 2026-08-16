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

//! A worked example: one dialect, one vendor operation, from the overlay row to the handler.
//!
//! Responsible for: showing every piece a third party has to write — the operation type, its spec
//! and floor, its overlay row, its route, its shadowing declaration, its handler and the two
//! registration calls — as one file somebody can copy.
//! NOT responsible for: asserting anything. `crates/core/tests/dialect.rs` owns the assertions,
//! including every refusal this example would hit if a field were changed.
//! Upstream: `rustfs-gateway-core`. Downstream: nothing; this is a leaf.
//!
//! Run it with `cargo run -p rustfs-gateway-core --example dialect_overlay`.
//!
//! # What this is the template for
//!
//! The admin, STS and metadata surfaces a deployment mounts beside S3 are all this shape: an
//! operation AWS does not define, on a request the ordinary router has to be able to tell apart
//! from every operation AWS does define. Historically they were mounted as side routes with their
//! own authentication, which is rustfs/rustfs#4845 — one of them forgot to call the authorisation
//! check, because nothing forced it to say what permission it needed. Here an operation that cannot
//! say is an operation that does not register.
//!
//! # The five facts, written twice on purpose
//!
//! The overlay row and the code state the same five things: the name, the precedence, the selector,
//! the spec and whether the operation is anonymously reachable. `DialectBuilder::build` refuses the
//! dialect when they disagree. That is what makes the row a review artefact rather than a comment:
//! a reviewer reads the overlay, and the overlay cannot drift from the behaviour.

use std::sync::Arc;

use http::Method;
use rustfs_gateway_core::dialect::{Dialect, DialectOverlay, DialectRoute, OverlayRow};
use rustfs_gateway_core::handler::{Handler, HandlerResult, Req, Resp};
use rustfs_gateway_core::op::{AuthRequirement, Operation, ResourceShape};
use rustfs_gateway_core::registry::{HandlerDeadlineClass, OperationSpec, RouterBuilder};
use rustfs_gateway_core::route::{Predicate, ShadowingDecl, TargetKind};
use rustfs_gateway_sig::{OperationFloor, SigService};

// ── 1. the operation, as a type ──────────────────────────────────────────────────────────────
//
// `OperationOrigin` defaults to `ThirdParty`, and the token the other answer needs has a private
// field inside `rustfs-gateway-core`. So this declaration cannot claim to be an AWS operation
// however it is written, and the registry holds it to the `vendor:Name` rule.

/// The vendor operation: a report about one object, asked for with a `HEAD`.
struct HeadObjectReport;

/// What it requires of a request once routing has chosen it.
///
/// `auth` is `Some` because it has to be: an operation with `None` is refused at registration, so
/// there is no path on which the authorisation question can be skipped.
static SPEC: OperationSpec = OperationSpec::builder("acme:HeadObjectReport", 200, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .required_params(&[])
    .auth(AuthRequirement::new("acme:HeadObjectReport", ResourceShape::Object))
    .build();

/// What it tells the security floor about itself.
///
/// `custom` rather than `builtin`: an operation a third party added is privileged by default, so it
/// refuses presigned URLs unless somebody says otherwise in as many words.
static FLOOR: OperationFloor = OperationFloor::custom("acme:HeadObjectReport", SigService::S3);

impl Operation for HeadObjectReport {
    const NAME: &'static str = "acme:HeadObjectReport";
    type Input = ();
    type Output = ();
    type DerivedResources = rustfs_gateway_core::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, rustfs_gateway_core::DerivedResourceError> {
        Ok(rustfs_gateway_core::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

// ── 2. where the row goes in the ordered table ───────────────────────────────────────────────

/// The routing conjunction: a `HEAD` on an object carrying the vendor's query key.
static SELECTOR: &[Predicate] = &[
    Predicate::Method(Method::HEAD),
    Predicate::Target(TargetKind::Object),
    Predicate::QueryPresent("acme-report"),
];

/// The one overlap this placement creates.
///
/// `HEAD` on an object target has exactly one standard row, `HeadObject` at precedence 950. Placing
/// this row at 505 puts it in front, which is the only way a request carrying the vendor key can
/// reach it — and the table refuses to build until that is written down with a reason and a source.
/// A row in a busier cell (`GET` on a bucket, say) overlaps every other row in the cell and needs
/// one declaration per pair; that cost is the reason to prefer a path literal for an admin surface.
static SHADOWS: &[ShadowingDecl] = &[ShadowingDecl {
    winner: "acme:HeadObjectReport",
    shadowed: "HeadObject",
    reason: "A HEAD carrying the vendor report key asks for the report, not for the object's \
             metadata; behind HeadObject the key would be ignored and the answer would be the \
             object's own metadata, which is the wrong answer rather than an error.",
    evidence: &["https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html"],
}];

// ── 3. the overlay: the reviewed record ──────────────────────────────────────────────────────

/// Everything this dialect adds, as a reviewer reads it.
static ACME: DialectOverlay = DialectOverlay {
    name: "acme",
    vendor: "acme",
    operations: &[OverlayRow {
        name: "acme:HeadObjectReport",
        precedence: 505,
        selector: "Method(HEAD) ∧ Target(Object) ∧ QueryPresent(\"acme-report\")",
        action: "acme:HeadObjectReport",
        resource: ResourceShape::Object,
        success_status: 200,
        anonymous: false,
        evidence: &[
            "https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html",
            "https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations_Amazon_Simple_Storage_Service.html",
        ],
    }],
};

// ── 4. the backend ───────────────────────────────────────────────────────────────────────────

/// A backend that answers the vendor operation.
#[derive(Debug)]
struct Acme;

impl Handler<HeadObjectReport> for Acme {
    async fn call(&self, request: Req<HeadObjectReport>) -> HandlerResult<HeadObjectReport> {
        let (_source, context) = rustfs_gateway_core::HandlerCancellationSource::pair();
        self.call_with_context(request, context).await
    }

    async fn call_with_context(
        &self,
        _request: Req<HeadObjectReport>,
        _context: rustfs_gateway_core::HandlerContext,
    ) -> HandlerResult<HeadObjectReport> {
        Ok(Resp::new(()))
    }
}

fn main() {
    let dialect = match Dialect::assemble(&ACME)
        .declare::<HeadObjectReport>(DialectRoute {
            precedence: 505,
            selector: SELECTOR,
            path_shape: "/{Bucket}/{Key+}",
            shadows: SHADOWS,
        })
        .build()
    {
        Ok(dialect) => dialect,
        Err(errors) => {
            for error in errors {
                println!("the acme dialect was refused: {error}");
            }
            return;
        }
    };

    // Two calls, not one. `dialect` installs the route row and the declaration; `handle_without_codec`
    // installs the implementation. Keeping them separate is what makes a route with no handler a
    // legitimate 501 rather than an assembly that silently did half of what it looked like it did.
    let router = RouterBuilder::new()
        .dialect(&dialect)
        .handle_without_codec::<HeadObjectReport, _>(Arc::new(Acme))
        .build();

    match router {
        Ok(router) => {
            println!("dialect {:?} installed", dialect.name());
            for name in dialect.operation_names() {
                println!("  operation {name}");
            }
            println!("  {} operation(s) registered in all", router.registry().len());
        }
        Err(error) => println!("the router was refused: {error}"),
    }
}
