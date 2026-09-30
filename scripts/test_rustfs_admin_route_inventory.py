#!/usr/bin/env python3
"""Check how the RustFS admin route inventory generator reads an enum-dispatched handler.

RustFS registers some admin routes from a loop whose rows carry one handler value per route
(`&Handler(Route::Readiness)`), and dispatches on the value's variant inside the handler. The
generator records each route's body facts from what that variant reaches, and refuses a shape it
cannot follow. Synthetic sources only; no RustFS checkout and no repository file is touched.
"""

import importlib.util
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("gen_inventory", HERE / "gen_rustfs_admin_route_inventory.py")
gen = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gen)

HANDLER = "rustfs/src/admin/handlers/integrity.rs"

PRELUDE = """
const ADMIN_PREFIX: &str = "/rustfs/admin";

#[derive(Clone, Copy)]
enum Route {
    Readiness,
    Inventory,
    Create,
    Status,
    Control,
}

struct Handler(Route);

fn permission(route: Route) -> AdminAction {
    match route {
        Route::Readiness => AdminAction::ServerInfoAdminAction,
        _ => AdminAction::StartBatchJobAction,
    }
}

pub fn register_integrity_routes(router: &mut S3Router<AdminOperation>) -> std::io::Result<()> {
    for (method, path, handler) in [
        (Method::GET, "/v3/integrity/readiness", &Handler(Route::Readiness)),
        (Method::GET, "/v3/integrity/{bucket}/inventory", &Handler(Route::Inventory)),
        (Method::POST, "/v3/integrity/{bucket}/jobs", &Handler(Route::Create)),
        (Method::GET, "/v3/integrity/{bucket}/jobs/{job_id}", &Handler(Route::Status)),
        (Method::POST, "/v3/integrity/{bucket}/jobs/{job_id}/control", &Handler(Route::Control)),
    ] {
        router.insert(method, &format!("{ADMIN_PREFIX}{path}"), AdminOperation(handler))?;
    }
    Ok(())
}
"""

# RustFS's shape at 3268c42e: an early return for one variant, a `match self.0`, and an
# `if matches!(self.0, ..) { .. } else { .. }` inside a shared arm.
CALL = """
#[async_trait::async_trait]
impl Operation for Handler {
    async fn call(&self, req: S3Request<Body>, params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        let credentials = authorize_admin_request(&req, vec![Action::AdminAction(permission(self.0))]).await?;
        if matches!(self.0, Route::Readiness) {
            return json_response(StatusCode::OK, &readiness());
        }
        match self.0 {
            Route::Inventory => json_response(StatusCode::OK, &inventory()),
            Route::Create => {
                let body = read_compatible_admin_body(req.input, 128, req.uri.path(), &credentials.secret_key).await?;
                json_response(StatusCode::CREATED, &body)
            }
            Route::Status | Route::Control => {
                let job = if matches!(self.0, Route::Status) {
                    get_job()
                } else {
                    let body = read_compatible_admin_body(req.input, 1024, req.uri.path(), &credentials.secret_key).await?;
                    control(body)
                };
                json_response(StatusCode::OK, &job)
            }
            Route::Readiness => json_response(StatusCode::OK, &readiness()),
        }
    }
}
"""


class FakeSource(gen.Source):
    """A `Source` over in-memory files, comments stripped as the real one strips them."""

    def __init__(self, files):
        self.root = pathlib.Path("/nonexistent")
        self.files = {relative: gen.strip_comments(text) for relative, text in files.items()}
        self.string_consts = self._string_consts()


def refused(action, needle):
    try:
        action()
    except gen.InventoryError as error:
        assert needle in str(error), f"refused for another reason: {error}"
        return
    raise AssertionError(f"accepted; expected a refusal naming {needle!r}")


def facts(call, variant):
    source = FakeSource({HANDLER: PRELUDE + call})
    _, body, streams = gen.handler_body(source, "Handler", variant)
    return gen.body_facts(body, streams)


# ── positive ──────────────────────────────────────────────────────────────────────────────────

sites = gen.insert_sites(FakeSource({HANDLER: PRELUDE + CALL}))
assert [(site["method"], site["path"], site["handler"], site["variant"]) for site in sites] == [
    ("GET", "/rustfs/admin/v3/integrity/readiness", "Handler", "Route::Readiness"),
    ("GET", "/rustfs/admin/v3/integrity/{bucket}/inventory", "Handler", "Route::Inventory"),
    ("POST", "/rustfs/admin/v3/integrity/{bucket}/jobs", "Handler", "Route::Create"),
    ("GET", "/rustfs/admin/v3/integrity/{bucket}/jobs/{job_id}", "Handler", "Route::Status"),
    ("POST", "/rustfs/admin/v3/integrity/{bucket}/jobs/{job_id}/control", "Handler", "Route::Control"),
], sites
assert all(site["function"] == "register_integrity_routes" for site in sites), sites

# Each variant's facts are what it reaches: only the two writes read and unseal a body.
for variant, expected in [
    ("Route::Readiness", ("none", "not-read", "buffered")),
    ("Route::Inventory", ("none", "not-read", "buffered")),
    ("Route::Create", ("request-on-minio-alias", "buffered", "buffered")),
    ("Route::Status", ("none", "not-read", "buffered")),
    ("Route::Control", ("request-on-minio-alias", "buffered", "buffered")),
]:
    assert facts(CALL, variant) == expected, (variant, facts(CALL, variant))

# The whole handler, read as one, would give every route the writes' facts: the view matters.
_, whole, streams = gen.handler_body(FakeSource({HANDLER: PRELUDE + CALL}), "Handler")
assert gen.body_facts(whole, streams) == ("request-on-minio-alias", "buffered", "buffered")

# A `_` arm is taken only by a variant no earlier arm took.
WILDCARD = CALL.replace("            Route::Readiness => json_response(StatusCode::OK, &readiness()),\n",
                        "            _ => json_response(StatusCode::OK, &readiness()),\n")
assert facts(WILDCARD, "Route::Readiness") == ("none", "not-read", "buffered")
assert facts(WILDCARD, "Route::Create") == ("request-on-minio-alias", "buffered", "buffered")

# A plain loop keeps its operation, with no variant.
PLAIN = """
pub fn register_plain(r: &mut S3Router<AdminOperation>) -> std::io::Result<()> {
    for (method, path, operation) in [
        (Method::PUT, "/v3/plain/add", AdminOperation(&PlainHandler {})),
    ] {
        r.insert(method, &format!("{ADMIN_PREFIX}{path}"), operation)?;
    }
    Ok(())
}
"""
plain = gen.insert_sites(FakeSource({HANDLER: PRELUDE.split("pub fn register")[0] + PLAIN}))
assert [(site["path"], site["handler"], site["variant"]) for site in plain] == [
    ("/rustfs/admin/v3/plain/add", "PlainHandler", None)
], plain

# ── negative ──────────────────────────────────────────────────────────────────────────────────

# A guarded arm, a pattern that is not the enum's, and a dispatch no arm of which takes the
# variant are refused rather than read.
refused(lambda: facts(CALL.replace("Route::Create => {", "Route::Create if big => {"), "Route::Create"),
        "a guarded pattern")
refused(lambda: facts(CALL.replace("Route::Inventory =>", "other =>"), "Route::Inventory"),
        "not Route variants")
refused(lambda: facts(CALL.replace("            Route::Readiness => json_response(StatusCode::OK, &readiness()),\n", ""),
                      "Route::Readiness"),
        "no arm of `match self.0` takes Route::Readiness")
# `matches!` inside a larger condition, and an `else if` after one, are not followed.
refused(lambda: facts(CALL.replace("if matches!(self.0, Route::Readiness) {", "if matches!(self.0, Route::Readiness) && ready {"),
                      "Route::Create"),
        "not the whole condition")
refused(lambda: facts(CALL.replace("                } else {\n                    let body", "                } else if other {\n                    let body"),
                      "Route::Control"),
        "an `else if`")
# Any other use of `self.0` is refused: bound to a name, or handed to a function of another file.
refused(lambda: facts(CALL.replace("        match self.0 {", "        let route = self.0;\n        match self.0 {"), "Route::Status"),
        "cannot tell which variant reaches it")
refused(lambda: facts(CALL.replace("permission(self.0)", "imported_permission(self.0)"), "Route::Status"),
        "not a function of this file")
# A wrapping loop whose row is not `&Type(Enum::Variant)`, or whose insert wraps something else.
refused(lambda: gen.insert_sites(FakeSource({HANDLER: PRELUDE.replace("&Handler(Route::Create)", "Handler(Route::Create)")})),
        "unreadable loop row")
refused(lambda: gen.insert_sites(FakeSource({HANDLER: PRELUDE.replace("&Handler(Route::Create)", "&Handler(Route::Create, 1)")})),
        "unreadable loop row")
refused(lambda: gen.insert_sites(FakeSource({HANDLER: PRELUDE.replace("&Handler(Route::Create)", "choose(&Handler(Route::Create))")})),
        "unreadable loop row")
refused(lambda: gen.insert_sites(FakeSource({HANDLER: PRELUDE.replace("&Handler(Route::Create)", "AdminOperation(&PlainHandler {})")})),
        "unreadable loop row")
refused(lambda: gen.insert_sites(FakeSource({HANDLER: PRELUDE.replace("AdminOperation(handler)", "AdminOperation(other)")})),
        "does not bind the loop's own names")

# A handler type implemented in two files: which one handles the route would be a guess.
refused(lambda: gen.handler_body(FakeSource({HANDLER: PRELUDE + CALL, "rustfs/src/admin/handlers/other.rs": CALL}),
                                 "Handler", "Route::Status"),
        "appears in")

print("OK: enum-dispatched admin handlers are read per variant, and every shape the generator cannot follow is refused")
