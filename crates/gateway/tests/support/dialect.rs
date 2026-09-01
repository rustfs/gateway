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

//! Supplies the reviewed dialect proof for the integration suite's shared vendor codecs.
//!
//! Responsible for: the test overlay and its exact route declarations.
//! NOT responsible for: defining codecs or relaxing production dialect validation.
//! Upstream: the shared support operations.
//! Downstream: the common service-builder fixture.

use rustfs_gateway_core::{Dialect, DialectOverlay, DialectRoute, OverlayRow, ResourceShape};

use super::{CONTENT_PING_PREDICATES, ContentPing, HEAD_PING_PREDICATES, HeadPing, PING_PREDICATES, Ping};

static PING_OVERLAY: DialectOverlay = DialectOverlay {
    name: "example-test",
    vendor: "example",
    operations: &[OverlayRow {
        name: "example:Ping",
        precedence: 50,
        selector: "Method(POST) ∧ Target(Service)",
        action: "example:Ping",
        resource: ResourceShape::Service,
        success_status: 200,
        anonymous: true,
        evidence: &["https://github.com/rustfs/gateway/issues/37"],
    }],
};

static HEAD_PING_OVERLAY: DialectOverlay = DialectOverlay {
    name: "example-test",
    vendor: "example",
    operations: &[OverlayRow {
        name: "example:HeadPing",
        precedence: 51,
        selector: "Method(HEAD) ∧ Target(Service)",
        action: "example:HeadPing",
        resource: ResourceShape::Service,
        success_status: 200,
        anonymous: true,
        evidence: &["https://github.com/rustfs/gateway/issues/37"],
    }],
};

static CONTENT_PING_OVERLAY: DialectOverlay = DialectOverlay {
    name: "example-test",
    vendor: "example",
    operations: &[OverlayRow {
        name: "example:ContentPing",
        precedence: 52,
        selector: "Method(PUT) ∧ Target(Service)",
        action: "example:ContentPing",
        resource: ResourceShape::Service,
        success_status: 200,
        anonymous: true,
        evidence: &["https://github.com/rustfs/gateway/issues/37"],
    }],
};

pub fn ping() -> Dialect {
    Dialect::assemble(&PING_OVERLAY)
        .declare::<Ping>(DialectRoute {
            precedence: 50,
            selector: PING_PREDICATES,
            path_shape: "/",
            shadows: &[],
        })
        .build()
        .expect("the Ping test overlay and operation declaration must agree")
}

pub fn head_ping() -> Dialect {
    Dialect::assemble(&HEAD_PING_OVERLAY)
        .declare::<HeadPing>(DialectRoute {
            precedence: 51,
            selector: HEAD_PING_PREDICATES,
            path_shape: "/",
            shadows: &[],
        })
        .build()
        .expect("the HeadPing test overlay and operation declaration must agree")
}

pub fn content_ping() -> Dialect {
    Dialect::assemble(&CONTENT_PING_OVERLAY)
        .declare::<ContentPing>(DialectRoute {
            precedence: 52,
            selector: CONTENT_PING_PREDICATES,
            path_shape: "/",
            shadows: &[],
        })
        .build()
        .expect("the ContentPing test overlay and operation declaration must agree")
}
