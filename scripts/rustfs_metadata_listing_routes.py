#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Read the legacy query extensions or the separate S3 and control-plane extension tables.

The legacy reader accepts exactly one shape:
a GET-only selector over a bucket, gated on the first `metadata` value being `true`, whose arms
each name one listing operation by one query rule, and an access check that maps each operation to
one `S3Action`. Anything else fails instead of producing a row. The inventory supplies its
literal-aware delimiter reader; no RustFS runtime is imported.
"""

import json
import os
import re
import subprocess
import tomllib

METADATA_ROUTE = "rustfs/src/app/metadata_route.rs"
SELECTOR = "metadata_operation"
ACCESS = "check_metadata_access"
ENUM = "MetadataOperation"
GATE = re.compile(r'if\s+query_value\(query,\s*"metadata"\)\.as_deref\(\)\s*!=\s*Some\("true"\)\s*\{\s*return\s+None;\s*\}')
ARM = re.compile(
    r'(?:if|else\s+if)\s+(?P<cond>[^{]*?)\s*\{\s*' + ENUM + r'::(?P<variant>\w+)\s*\}'
)
PRESENT = re.compile(r'^query_has\(query,\s*"([^"]+)"\)$')
EQUALS = re.compile(r'^query_value\(query,\s*"([^"]+)"\)\.as_deref\(\)\s*==\s*Some\("([^"]*)"\)$')


def body_of(text, function, relative, fail, close):
    match = re.search(rf"fn {function}\([^{{]*\{{", text)
    if not match:
        fail(f"{relative}: {function} not found")
    return text[match.end():close(text, match.end() - 1, "{", "}")]


def metadata_listing_routes(text, relative, fail, close):
    """The metadata listing rows, in the order the selector tries them."""
    body = body_of(text, SELECTOR, relative, fail, close)
    if not re.search(r"if\s+method\s*!=\s*Method::GET\s*\{\s*return\s+None;\s*\}", body):
        fail(f"{relative}: {SELECTOR} is not GET-only")
    if "bucket_from_request(" not in body:
        fail(f"{relative}: {SELECTOR} does not address a bucket through bucket_from_request")
    gate = GATE.search(body)
    if not gate:
        fail(f"{relative}: {SELECTOR} has no exact metadata=true gate")
    rows = []
    for arm in ARM.finditer(body, gate.end()):
        condition = re.sub(r"\s+", " ", arm.group("cond")).strip()
        present, equals = PRESENT.match(condition), EQUALS.match(condition)
        if present:
            discriminator = {"key": present.group(1), "rule": "present"}
        elif equals:
            discriminator = {"key": equals.group(1), "rule": f"equals:{equals.group(2)}"}
        else:
            fail(f"{relative}: unreadable {ENUM} arm condition {condition!r}")
        rows.append({
            "name": f"{ENUM}::{arm.group('variant')}",
            "method": "GET",
            "target": "bucket",
            "query_discriminator": discriminator,
            "query_requires": [{"key": "metadata", "rule": "equals:true"}],
            "claimed_by": METADATA_ROUTE,
            "auth_mode": "custom",
            "auth_detail": "SignedOrAnonymousThenBucketListing",
        })
    named = re.findall(rf"{ENUM}::(\w+)", body[gate.end():])
    if not rows or [row["name"] for row in rows] != [f"{ENUM}::{variant}" for variant in named]:
        fail(f"{relative}: unreadable {ENUM} arms {named}")
    access = body_of(text, ACCESS, relative, fail, close)
    actions = dict(re.findall(rf"{ENUM}::(\w+)\s*=>\s*S3Action::(\w+)", access))
    for row in rows:
        variant = row["name"].split("::", 1)[1]
        if variant not in actions:
            fail(f"{relative}: no authorisation action for {row['name']}")
        row["iam_action_enum"], row["iam_action"] = "S3Action", actions[variant]
    return rows


NATIVE_HANDLER = "rustfs/src/server/gateway_handlers/metadata_listing.rs"
NATIVE_STACK = "rustfs/src/server/gateway_stack.rs"
NATIVE_ACCESS = "rustfs/src/app/metadata_listing.rs"
DIALECT_PACKAGE = "rustfs-gateway-dialect-rustfs-admin"
DIALECT_DIR = "crates/dialect-rustfs-admin"


def locked_revision(text, fail):
    try:
        packages = [p for p in tomllib.loads(text).get("package", []) if p.get("name") == DIALECT_PACKAGE]
    except tomllib.TOMLDecodeError as error:
        fail(f"Cargo.lock: {error}")
    if len(packages) != 1:
        fail(f"Cargo.lock: expected one {DIALECT_PACKAGE}")
    pin = re.fullmatch(r"git\+https://github\.com/rustfs/gateway(?:\.git)?\?rev=([a-f0-9]{40})#\1",
                       packages[0].get("source", ""))
    if not pin:
        fail(f"Cargo.lock: {DIALECT_PACKAGE} must name one exact rustfs/gateway commit")
    return pin[1]


def one(pattern, text, label, fail):
    found = list(re.finditer(pattern, text, re.S))
    if len(found) != 1:
        fail(f"metadata listings: expected one {label}")
    return found[0]


def typed_route(text, kind, fail, split):
    """Read the executable route, checking its type bindings and its human-readable overlay."""
    def require(pattern, what):
        return one(pattern, text, f"{kind} {what}", fail)

    require(rf'pub const NAME: &str = "rustfs:{kind}";', "name")
    auth = require(r'pub const AUTH: AuthRequirement =\s*AuthRequirement::new\("([\w:-]+)", ResourceShape::(\w+)\)'
                   r'(?:\.with_version_requirement\(&([A-Z_]+)\))?;', "authorization")
    action, resource, version = auth.groups()
    version_action = None
    if version:
        version_action = require(rf'pub static {version}: AuthRequirement = AuthRequirement::new\("([\w:-]+)", '
                                 rf'ResourceShape::{resource}\);', "version authorization")[1]
    require(r"static SPEC: OperationSpec = admin::spec\(NAME, AUTH, false\);", "authorized spec")
    floor = require(r"static FLOOR: OperationFloor = admin::(listing_floor|floor|presigned_floor)\(NAME\)"
                    r"(\.with_signed_event_list\(\))?;", "operation floor")
    impl = require(rf"impl Operation for {kind}\s*\{{(.*?)\n\s*\}}\s*(?:impl|pub|$)", "operation implementation")[1]
    for pattern in (r"const NAME: &'static str = NAME;", r"fn spec\(\) -> &'static OperationSpec\s*\{\s*&SPEC\s*\}",
                    r"fn floor\(\) -> &'static OperationFloor\s*\{\s*&FLOOR\s*\}"):
        one(pattern, impl, f"{kind} operation binding", fail)
    require(rf"impl ExtensionOperation for {kind}\s*\{{\s*const ROUTE: DialectRoute = ROUTE;\s*\}}", "route binding")
    shapes = {"Service": "/", "Bucket": "/{Bucket}", "Object": "/{Bucket}/{Key+}"}
    if resource not in shapes:
        fail(f"{kind}: unsupported authorization target {resource}")
    route = require(r'pub const ROUTE: DialectRoute = DialectRoute\s*\{\s*precedence: (\d+),\s*'
                    rf'selector: SELECTOR,\s*path_shape: "{re.escape(shapes[resource])}",\s*shadows: SHADOWS,\s*\}};',
                    "route")
    precedence = int(route[1])
    overlay = require(r"pub const OVERLAY_ROW: OverlayRow = OverlayRow\s*\{(.*?)\};", "overlay")[1]
    displayed_action = action if version_action is None else f"{action}; versionId: {version_action}"
    for pattern in (r"\bname: NAME,", rf"\bprecedence: {precedence},", rf'\baction: "{re.escape(displayed_action)}",',
                    rf"\bresource: ResourceShape::{resource},", r"\banonymous: false,"):
        one(pattern, overlay, f"{kind} overlay binding", fail)
    preds = split(require(r"pub static SELECTOR: &\[Predicate\] = &\[(.*?)\];", "selector")[1])
    method = re.fullmatch(r"Predicate::Method\(http::Method::(GET|PUT)\)", preds[0]) if preds else None
    if len(preds) < 3 or not method or preds[1] != f"Predicate::Target(TargetKind::{resource})":
        fail(f"{kind}: unsupported route predicates")
    queries = []
    display = [f"Method({method[1]})", f"Target({resource})"]
    for pred in preds[2:]:
        rule = re.fullmatch(r'Predicate::QueryPresent\("([\w-]+)"\)|Predicate::QueryEquals\("([\w-]+)",\s*"([\w-]*)"\)', pred)
        if not rule:
            fail(f"{kind}: unsupported query predicate")
        key, verb = (rule[1], "present") if rule[1] else (rule[2], "equals:" + rule[3])
        queries.append({"key": key, "rule": verb})
        display.append(f'QueryPresent("{key}")' if verb == "present" else f'QueryEquals("{key}", "{verb[7:]}")')
    if f'selector: {json.dumps(" ∧ ".join(display), ensure_ascii=False)},' not in overlay:
        fail(f"{kind}: overlay and executable selector disagree")
    result = dict(name=f"rustfs:{kind}", method=method[1], target=resource.lower(), precedence=precedence,
                  query_discriminator=queries[0], query_requires=queries[1:], iam_action_wire=action,
                  floor=floor[1] + (floor[2] or ""))
    if version_action:
        result["version_iam_action_wire"] = version_action
    return result


def verify_listing(row, action, fail):
    if (row["method"], row["target"], row["floor"], row["iam_action_wire"]) != ("GET", "bucket", "listing_floor", action):
        fail(f"{row['name']}: route does not match the host's authorized bucket listing")
    if ("version_iam_action_wire" in row or row["query_requires"] != [{"key": "metadata", "rule": "equals:true"}]
            or row["query_discriminator"]["key"] == "metadata"):
        fail(f"{row['name']}: expected the additional metadata=true gate")


def direct_item(text, pattern, label, close, fail):
    """Locate one unconditional item in this Rust scope, ignoring the contents of nested items."""
    # Keep offsets intact so callers can recover the real body from the matched opening brace.
    top = list(text)
    for match in re.finditer(r'"(?:\\.|[^"\\])*"|\{', text):
        start = match.start()
        if top[start] == " ":
            continue
        if text[start] == '"':
            top[start:match.end()] = " " * (match.end() - start)
            continue
        end = close(text, start, "{", "}")
        top[start + 1:end] = " " * (end - start - 1)
    scope = "".join(top)
    item = one(pattern, scope, label, fail)
    if scope[:item.start()].rstrip().endswith("]"):
        fail(f"{label}: conditional or redirected Rust item")
    return item


def published_table(source, table, close, split, fail):
    """Read the executed typed fold, its parallel overlay and the placement of each operation."""
    def block(text, pattern, label):
        opening = direct_item(text, pattern, label, close, fail).end() - 1
        return text[opening + 1:close(text, opening, "{", "}")]

    reducer = block(source, r"\bimpl ExtensionRouteFold for Declare\s*\{", "native declare reducer")
    if not re.fullmatch(r"\s*type Carry = DialectBuilder;\s*fn step<O: ExtensionOperation>\("
                        r"&mut self, builder: DialectBuilder, route: DialectRoute\) -> DialectBuilder\s*\{"
                        r"\s*builder\.declare::<O>\(route\)\s*\}\s*", reducer):
        fail("native declare reducer does not install the operation and its route")
    listener = block(source, rf"\bpub mod {table}\s*\{{", table)
    declare = block(listener, r"\bpub fn declare\(builder: super::DialectBuilder\) -> super::DialectBuilder\s*\{", table + " declare")
    if not re.fullmatch(r"\s*fold\(&mut super::Declare, builder\)\s*", declare):
        fail(f"{table}: unsupported declare wrapper")
    fold = block(listener, r"\bpub fn fold<F: super::ExtensionRouteFold>\(fold: &mut F, carry: F::Carry\) -> F::Carry\s*\{",
                 table + " typed fold")
    names = split(direct_item(listener, r"\bpub static ROWS: &\[OverlayRow\] = &\[([^\]]+)\];",
                              table + " rows", close, fail)[1])
    direct_item(listener, r"\buse crate::ops;", table + " ops", close, fail)
    rows = []
    shadowed_extensions = []
    for i, name in enumerate(names):
        module = re.fullmatch(r"(\w+)::ROW", name)
        if not module:
            fail(f"{table}: unsupported overlay element")
        stem = module[1]
        # Consume each step from the front, including the final returned carry. Dead, repeated,
        # reordered or skipped steps therefore cannot contribute a declaration.
        step = (r"\s*let carry\s*=\s*" if i + 1 < len(names) else r"\s*") + (
            rf"fold\.step::<ops::{stem}::(\w+)>\(\s*carry,\s*{stem}::ROUTE,?\s*\)"
        ) + (";" if i + 1 < len(names) else "")
        call = re.match(step, fold)
        if not call:
            fail(f"{table}: typed fold disagrees with overlay at {stem}")
        fold = fold[call.end():]
        item = block(listener, rf"\bmod {stem}\s*\{{", table + "/" + stem)
        direct_item(item, r"\buse crate::ops;", stem + " ops", close, fail)
        row = block(item, r"pub\(super\) const ROW: OverlayRow = OverlayRow\s*\{", stem + " overlay row")
        route = block(item, r"pub\(super\) const ROUTE: DialectRoute = DialectRoute\s*\{", stem + " typed route")
        placement = re.fullmatch(r'\s*precedence: (\d+),\s*evidence: &\[\s*"[^"]+",?\s*\],\s*'
                                 + rf"\.\.ops::{stem}::OVERLAY_ROW\s*", row)
        overlap = r'shadows\("[^"]+",\s*REASON_\d+\)'
        if not placement or not re.fullmatch(r"\s*precedence: ROW\.precedence,\s*shadows: &\[\s*"
                                            + rf"(?:{overlap}(?:,\s*{overlap})*,?\s*)?\],\s*"
                                            + rf"\.\.ops::{stem}::ROUTE\s*", route):
            fail(f"{table}: {stem} does not inherit the matching typed route and row")
        targets = re.findall(r'shadows\("([^"]+)",', route)
        if targets:
            helper = block(item, r"const fn shadows\(shadowed: &'static str, reason: &'static str\) -> ShadowingDecl\s*\{",
                           stem + " shadow declaration")
            if " ".join(helper.split()) != "ShadowingDecl { winner: ROW.name, shadowed, reason, evidence: ROW.evidence, }":
                fail(f"{table}: {stem} does not declare its own shadows")
        shadowed_extensions.append({target for target in targets if target.startswith("rustfs:")})
        rows.append((stem, call[1], int(placement[1])))
    if fold.strip() or not rows or any(len({row[i] for row in rows}) != len(rows) for i in range(3)):
        fail(f"{table}: duplicate or unconsumed extension declarations")
    if [row[2] for row in rows] != sorted(row[2] for row in rows):
        fail(f"{table}: extension order disagrees with precedence")
    later = set()
    for (_, kind, _), shadows in zip(reversed(rows), reversed(shadowed_extensions)):
        if not shadows <= later:
            fail(f"{table}: {kind} shadows an extension outside or ahead of its own table")
        later.add(f"rustfs:{kind}")
    return rows


def top_block(text, pattern, label, close, fail):
    opening = direct_item(text, pattern, label, close, fail).end() - 1
    return " ".join(text[opening + 1:close(text, opening, "{", "}")].split())


def native_claimed_routes(routes_src, authority_src, blob, has_lambda_fallback, admin_actions, strip, close, split, fail):
    """Verify mounted native claimed control-plane routes and their pre-body IAM authority."""
    if split(top_block(routes_src, r"\buse super::\{", "native_routes host imports", close, fail)) != ["Host", "NAME", "ROUTER"]:
        fail("native routes: unsupported host imports")
    if split(top_block(routes_src, r"\buse rustfs_gateway_dialect_rustfs_admin::\{",
                       "native_routes dialect imports", close, fail)) != ["AdminOperation", "native::ops"]:
        fail("native routes: unsupported dialect imports")
    shadows_fn = top_block(routes_src, r"\bconst fn shadows_control_plane\(winner: &'static str\) -> ShadowingDecl\s*\{",
                           "shadows_control_plane", close, fail)
    if not re.fullmatch(r'ShadowingDecl \{ winner, shadowed: NAME, reason: "[^"]+", evidence: &\[ROUTER\],? \}', shadows_fn):
        fail("native routes: unsupported shadows_control_plane declaration")
    macro_body = top_block(routes_src, r"\bmacro_rules!\s+native_routes\s*\{", "native_routes macro", close, fail)
    expected_macro = " ".join("""
        ($($module:ident::$operation:ident),+ $(,)?) => {
            const ROWS: &[OverlayRow] = &[$(ops::$module::OVERLAY_ROW),+];
            pub(super) fn declare(builder: DialectBuilder) -> DialectBuilder {
                $(
                    let builder = builder.declare_claimed::<ops::$module::$operation>(ClaimedRoute {
                        precedence: ops::$module::$operation::PRECEDENCE,
                        rows: ops::$module::$operation::rows(),
                        shadows: const { &[shadows_control_plane(ops::$module::NAME)] },
                        bucket_param: ops::$module::$operation::BUCKET,
                    });
                )+
                builder
            }
            pub(super) fn register(builder: ServiceBuilder, host: &Arc<Host>) -> ServiceBuilder {
                builder$(.register::<ops::$module::$operation, _>(Arc::clone(host)))+
            }
        };
    """.split())
    if macro_body != expected_macro:
        fail("native routes: unsupported native_routes! macro expansion")
    if top_block(routes_src, r"\bpub\(super\) fn append_rows\(rows: &mut Vec<OverlayRow>\)\s*\{",
                 "native_routes append_rows", close, fail) != "rows.extend_from_slice(ROWS);":
        fail("native routes: unsupported append_rows")
    if top_block(routes_src, r"\bpub\(super\) fn contains\(name: &str\) -> bool\s*\{",
                 "native_routes contains", close, fail) != "ROWS.iter().any(|row| row.name == name)":
        fail("native routes: unsupported contains")
    invoc = direct_item(routes_src, r"\bnative_routes!\s*\(([^()]*)\)\s*;",
                        "native_routes invocation", close, fail)[1]
    items = split(invoc)
    if not items:
        fail("native routes: empty native_routes! invocation")
    pairs = []
    for item in items:
        pair = re.fullmatch(r"([a-z][a-z0-9_]*)::([A-Z][A-Za-z0-9]*)", item)
        if not pair:
            fail(f"native routes: unreadable operation entry {item!r}")
        pairs.append((pair[1], pair[2]))
    if len({m for m, _ in pairs}) != len(pairs) or len({k for _, k in pairs}) != len(pairs):
        fail("native routes: duplicate operation in native_routes!")

    direct_item(strip(blob(DIALECT_DIR + "/src/native.rs")), r"\bpub mod ops;", "native.rs/ops", close, fail)
    native_ops_mod = strip(blob(DIALECT_DIR + "/src/native/ops.rs"))
    op_specs = {}
    for module, kind in pairs:
        direct_item(native_ops_mod, rf"\bpub mod {module};", f"native/ops/{module}", close, fail)
        op_src = strip(blob(f"{DIALECT_DIR}/src/native/ops/{module}.rs"))
        one(rf'pub const NAME: &str = "rustfs:{kind}";', op_src, f"{kind} name", fail)
        one(rf"\bimpl Operation for {kind}\b", op_src, f"{kind} Operation impl", fail)
        one(rf"\bimpl AdminOperation for {kind}\b", op_src, f"{kind} AdminOperation impl", fail)
        one(r"\bstatic FLOOR: OperationFloor = admin::floor\(NAME\);", op_src, f"{kind} operation floor", fail)
        sel_method = one(r"static SELECTOR: &\[Predicate\] = &\[Predicate::Method\(http::Method::([A-Z]+)\)\];",
                         op_src, f"{kind} selector", fail)[1]
        rec_method = one(r'\bmethod:\s*"([A-Z]+)",', op_src, f"{kind} record method", fail)[1]
        if sel_method != rec_method:
            fail(f"{kind}: selector method {sel_method} disagrees with record method {rec_method}")
        if sel_method == "GET" and not has_lambda_fallback:
            fail(f"{kind}: GET native route requires GatewayStack Object Lambda fallback")
        auth = one(r'pub const AUTH: AuthRequirement =\s*AuthRequirement::new\("([\w:-]+)", ResourceShape::(\w+)\)'
                   r'(?:\.about_subject\(([A-Z_]+)\))?;', op_src, f"{kind} authorization", fail)
        action_wire, resource_shape, subject_const = auth.groups()
        if subject_const:
            one(rf"\bpub const {subject_const}: SubjectRule = SubjectRule::Caller;",
                op_src, f"{kind} caller subject", fail)
        op_specs[module] = (kind, action_wire, resource_shape, bool(subject_const))

    auth_fn = top_block(
        authority_src,
        r"\bpub\(super\) async fn authorize\(context: &RequestContext<'_>, request: &AuthzRequest<'_>, head: &ClaimedHead\) -> S3Result<\(\)>\s*\{",
        "native_authority::authorize",
        close,
        fail,
    )
    replicator_guard = (
        r"if request\.operation == ops::put_v3_site_replication_remove_v2::NAME \{ "
        r"reject_site_replicator_on_public_admin\(&credentials\)\?; \} "
        if "put_v3_site_replication_remove_v2" in op_specs
        else r""
    )
    auth_pattern = (
        r'let identity = request \.identity \.filter\(\|identity\| context\.auth_scheme\(\) == AuthSchemeRef::SigV4Header '
        r'&& identity\.origin\(\) == IdentityOrigin::AccessKey\) '
        r'\.ok_or_else\(\|\| s3_error!\(AccessDenied, "[^"]+"\)\)\?; '
        r'let accepted = context \.headers\(\) \.ok_or_else\(\|\| s3_error!\(InternalError, "[^"]+"\)\)\?; '
        r"let mut headers = HeaderMap::new\(\); "
        r"for \(name, value\) in accepted\.iter_raw\(\) \{ headers\.append\(name\.clone\(\), value\.clone\(\)\); \} "
        r"if !headers\.contains_key\(header::HOST\) && let Some\(authority\) = head\.uri\.authority\(\) \{ "
        r"headers\.insert\( header::HOST, HeaderValue::from_str\(authority\.as_str\(\)\) "
        r'\.map_err\(\|_\| s3_error!\(InternalError, "[^"]+"\)\)\?,? \); \} '
        r"let session = get_session_token\(&head\.uri, &headers\)\.map\(str::to_owned\); "
        r"let credentials = RequestCredentials::without_secret_key\(identity\.access_key_id\(\)\.to_owned\(\), session\); "
        r"let \(credentials, owner\) = authenticate_envelope_credentials\(&credentials\)\.await\?; "
        r"let Permission::Admin \{ action, bucket \} = permission\(request\)\? else \{ return Ok\(\(\)\); \}; "
        r"let extensions = context\.server_extensions\(\); "
        r"let peer = extensions\.get::<Option<RemoteAddr>>\(\)\.copied\(\)\.flatten\(\)\.map\(\|peer\| peer\.0\); "
        r"let source = RequestEnvelope::policy_source_addr_from\(peer, extensions\.get::<ClientInfo>\(\)\); "
        r"match bucket \{ "
        r"(?:Some\(bucket\) => \{ validate_admin_request_with_bucket\(&headers, &credentials, owner, false, vec!\[action\], source, bucket\)\.await\? \}"
        r"|Some\(bucket\) => validate_admin_request_with_bucket\(&headers, &credentials, owner, false, vec!\[action\], source, bucket\)\.await\?,) "
        r"None => validate_admin_request\(&headers, &credentials, owner, false, vec!\[action\], source\)\.await\?,? \} "
        + replicator_guard
        + r"Ok\(\(\)\)"
    )
    if not re.fullmatch(auth_pattern, auth_fn):
        fail("native authority: unsupported authorize implementation")

    perm_fn = top_block(
        authority_src,
        r"\bfn permission<'a>\(request: &AuthzRequest<'a>\) -> S3Result<Permission<'a>>\s*\{",
        "native_authority::permission",
        close,
        fail,
    )
    covered = set()
    if "post_v4_account_permissions" in op_specs:
        caller_match = re.match(
            r'if request\.operation == ops::post_v4_account_permissions::NAME \{ '
            r'if request\.action == ops::post_v4_account_permissions::AUTH\.action '
            r'&& request\.resource == ResourceShape::Service '
            r'&& matches!\(request\.subject, Some\(Subject::Caller\)\) \{ '
            r'return Ok\(Permission::Caller\); \} '
            r'return Err\(s3_error!\(AccessDenied, "[^"]+"\)\); \}\s*',
            perm_fn,
        )
        if not caller_match:
            fail("native authority: missing caller-subject check for post_v4_account_permissions")
        perm_fn = perm_fn[caller_match.end():]
        covered.add("post_v4_account_permissions")
    perm_match = re.fullmatch(
        r"let \(action, shape\) = match request\.operation \{ (.*?) "
        r'_ => return Err\(s3_error!\(InternalError, "[^"]+"\)\),? \}; '
        r"let action = Action::AdminAction\(action\); "
        r"if request\.action != <&str>::from\(&action\) \|\| request\.resource != shape \|\| request\.subject\.is_some\(\) \{ "
        r'return Err\(s3_error!\(AccessDenied, "[^"]+"\)\); \} '
        r"let bucket = if shape == ResourceShape::Bucket \{ "
        r'Some\( request \.bucket \.ok_or_else\(\|\| s3_error!\(AccessDenied, "[^"]+"\)\)\? \.as_str\(\),? \) '
        r"\} else \{ None \}; "
        r"Ok\(Permission::Admin \{ action, bucket \}\)",
        perm_fn,
    )
    if not perm_match:
        fail("native authority: unsupported permission match structure")
    arms_text = perm_match[1].strip()
    arm_pattern = re.compile(
        r"(ops::[a-z0-9_]+::NAME(?:\s*\|\s*ops::[a-z0-9_]+::NAME)*)\s*=>\s*"
        r"(?:\{\s*\(\s*AdminAction::(\w+),\s*ResourceShape::(\w+),?\s*\)\s*\}(?:\s*,)?"
        r"|\(\s*AdminAction::(\w+),\s*ResourceShape::(\w+),?\s*\)\s*,?)\s*"
    )
    cursor = 0
    while cursor < len(arms_text):
        parsed = arm_pattern.match(arms_text, cursor)
        if not parsed:
            fail(f"native authority: unreadable permission arm {arms_text[cursor:]!r}")
        cursor = parsed.end()
        ops_pat = parsed.group(1)
        admin_variant = parsed.group(2) or parsed.group(4)
        shape = parsed.group(3) or parsed.group(5)
        for mod_name in re.findall(r"ops::([a-z0-9_]+)::NAME", ops_pat):
            if mod_name in covered or mod_name not in op_specs:
                fail(f"native authority: duplicate or unmounted operation {mod_name} in permission")
            _, action_wire, expected_shape, has_caller_subject = op_specs[mod_name]
            if has_caller_subject or expected_shape != shape:
                fail(f"native authority: {mod_name} resource or subject disagrees with dialect")
            if admin_actions and admin_actions.get(admin_variant) != action_wire:
                fail(f"native authority: {mod_name} action {admin_variant} disagrees with {action_wire}")
            covered.add(mod_name)
    if covered != set(op_specs):
        fail("native authority: permission does not cover every mounted native operation")
    return set(op_specs)


FALLBACK_CALL_RE = (
    r"assemble_object_lambda_fallback\(\s*"
    r"&assembly,\s*"
    r"(?:Arc::clone\(&iam\)|iam),\s*"
    r"(?:Arc::clone\(&root\)|root),\s*"
    r"(?:Arc::clone\(&router\)|router),\s*"
    r"(?:Arc::clone\(&host\)|&?host),?\s*"
    r"\)\?"
)
FALLBACK_BIND_RE = r"let object_lambda_fallback = " + FALLBACK_CALL_RE + r";"


def _registration_pattern(registered, allow_cloned_last=False, allow_borrowed_host=False):
    host_ref = r"&?host" if allow_borrowed_host else r"&host"
    parts = [rf"\.register::<{t},\s*_>\(Arc::clone\({host_ref}\)\)" for t in registered[:-1]]
    last_arg = rf"(?:Arc::clone\({host_ref}\)|host)" if allow_cloned_last else r"host"
    parts.append(rf"\.register::<{registered[-1]},\s*_>\({last_arg}\)")
    return r"\s*".join(parts)


def gateway_stack_lambda_field(stack, close, split, fail):
    """Return True iff `struct GatewayStack` declares `object_lambda_fallback: Option<S3Service>`."""
    match = one(r"\bstruct\s+GatewayStack\s*\{", stack, "GatewayStack struct", fail)
    body = stack[match.end():close(stack, match.end() - 1, "{", "}")]
    fields = split(body)
    lambda_fields = [field for field in fields if re.search(r"\bobject_lambda_fallback\b", field)]
    if not lambda_fields:
        return False
    if len(lambda_fields) != 1:
        fail("gateway stack: duplicate object_lambda_fallback field")
    if not re.fullmatch(
        r"(?:pub(?:\([^)]*\))?\s+)?object_lambda_fallback\s*:\s*Option<\s*(?:rustfs_gateway::)?S3Service\s*>",
        " ".join(lambda_fields[0].split()),
    ):
        fail("gateway stack: unsupported object_lambda_fallback field declaration")
    return True


def verify_gateway_stack_call_lambda_fallback(stack, close, split, fail):
    """Verify `GatewayStack::call` selects `object_lambda_fallback` on `object_lambda_target`."""
    impl_match = direct_item(stack, r"\bimpl\s+GatewayStack\s*\{", "GatewayStack impl", close, fail)
    impl_body = stack[impl_match.end():close(stack, impl_match.end() - 1, "{", "}")]
    call_match = direct_item(
        impl_body,
        r"(?:pub(?:\([^)]*\))?\s+)?fn\s+call\b[^;{}]*\{",
        "GatewayStack::call",
        close,
        fail,
    )
    call_start = call_match.end()
    call_body = " ".join(impl_body[call_start:close(impl_body, call_start - 1, "{", "}")].split())
    if re.search(r"\bfn\s+object_lambda_target\b|\bas\s+object_lambda_target\b", stack):
        fail("gateway stack: local object_lambda_target shadows admin router classifier")
    attach_pattern = r"if\s+self\.control_plane\s*\{\s*control_plane::attach_head\(\s*&mut\s+request,?\s*\);\s*\}"
    attach = re.search(attach_pattern, call_body)
    if not attach:
        fail("gateway stack: GatewayStack::call must attach control-plane head before dispatch")
    dispatch_pattern = (
        r"let\s+service\s*=\s*match\s+self\s*\.object_lambda_fallback\s*\.as_ref\(\)\s*\{\s*"
        r"Some\(fallback\)\s+if\s+(?P<prefix>crate::admin::router::)?object_lambda_target\(\s*"
        r"request\s*\.method\(\),\s*request\s*\.uri\(\),?\s*\)\s*\.is_some\(\)\s*=>\s*"
        r"(?:\{\s*fallback\s*\.clone\(\)\s*\}\s*,?|fallback\s*\.clone\(\)\s*,)\s*"
        r"_\s*=>\s*(?:\{\s*self\s*\.service\s*\.clone\(\)\s*\}\s*,?|self\s*\.service\s*\.clone\(\)\s*,?)\s*"
        r"\};"
    )
    dispatches = list(re.finditer(dispatch_pattern, call_body))
    if len(dispatches) != 1:
        fail("gateway stack: GatewayStack::call must select object_lambda_fallback via object_lambda_target")
    dispatch = dispatches[0]
    if dispatch.start() < attach.end():
        fail("gateway stack: GatewayStack::call must attach control-plane head before selecting object_lambda_fallback")
    if not dispatch.group("prefix"):
        imported = bool(re.search(r"\buse\s+crate::admin::router::object_lambda_target\s*;", stack))
        if not imported:
            for use_match in re.finditer(r"\buse\s+crate::admin::router::\{([^{}]*)\}\s*;", stack):
                if "object_lambda_target" in split(use_match[1]):
                    imported = True
                    break
        if not imported:
            fail("gateway stack: unqualified object_lambda_target must be imported from crate::admin::router")
    after_dispatch = call_body[dispatch.end():]
    if re.search(r"\blet\s+service\b|\bservice\s*=|\bself\s*\.service\s*\.call\(", after_dispatch):
        fail("gateway stack: GatewayStack::call overwrites or bypasses selected service")
    if not re.search(r"(?<!\.)\bservice\s*\.call\(\s*request,?\s*\)\s*\.await\b", after_dispatch):
        fail("gateway stack: GatewayStack::call must invoke the selected service")


def verify_object_lambda_dialect(control, close, fail):
    """Verify `control_plane::object_lambda_dialect` builds the base control-plane dialect without `native_routes`."""
    match = direct_item(
        control,
        r"(?:pub(?:\([^)]*\))?\s+)?fn\s+object_lambda_dialect\s*\(\s*\)\s*->\s*Result<Dialect,\s*GatewayAssemblyError>\s*\{",
        "object_lambda_dialect",
        close,
        fail,
    )
    body = " ".join(control[match.end():close(control, match.end() - 1, "{", "}")].split())
    if re.search(r"\bnative_routes\b", body):
        fail("control plane: object_lambda_dialect must not include native_routes")
    cache_decl = re.compile(r"static (\w+): OnceLock<(Vec<OverlayRow>|String|DialectOverlay)> = OnceLock::new\(\); ")
    cursor = 0
    caches = {"Vec<OverlayRow>": set(), "String": set(), "DialectOverlay": set()}
    for _ in range(6):
        found = cache_decl.match(body, cursor)
        if not found:
            fail("control plane: unsupported object_lambda_dialect declaration caches")
        caches[found[2]].add(found[1])
        cursor = found.end()
    if (len(caches["Vec<OverlayRow>"]) != 1
            or len(caches["String"]) != 4
            or len(caches["DialectOverlay"]) != 1):
        fail("control plane: object_lambda_dialect requires six distinct OnceLock caches")
    rest = body[cursor:]
    claimed_chain = (
        r"Dialect::assemble\(record\)\s*"
        r"\.declare_claimed::<ControlPlane>\(ROUTE\)\s*"
        r"\.declare_claimed::<PostV3SpeedtestClientDevnull>\(ClaimedRoute \{\s*"
        r"precedence: PostV3SpeedtestClientDevnull::PRECEDENCE,\s*"
        r"rows: PostV3SpeedtestClientDevnull::rows\(\),\s*"
        r"shadows: SPEEDTEST_SHADOWS,\s*"
        r"bucket_param: PostV3SpeedtestClientDevnull::BUCKET,?\s*"
        r"\}\)\s*"
        r"\.declare_form::<StsForm>\(STS_ROUTE\)"
    )
    pattern = (
        r"let mut rows = vec!\[OverlayRow \{\s*"
        r"name: NAME,\s*"
        r"precedence: ROUTE\.precedence,\s*"
        r"selector: (\w+)\s*\.get_or_init\(\|\| render_claimed_route\(&ROUTE\)\),\s*"
        r"action: (\w+)\s*\.get_or_init\(\|\| SPEC\.auth\s*\.map\(\|auth\| auth\.render\(\)\)\s*\.unwrap_or_default\(\)\),\s*"
        r"resource: ResourceShape::Service,\s*"
        r"success_status: 200,\s*"
        r"anonymous: true,\s*"
        r"evidence: &\[ROUTER\],?\s*"
        r"\}\];\s*"
        r"rows\.push\(OverlayRow \{\s*"
        r"name: STS_NAME,\s*"
        r"precedence: STS_ROUTE\.precedence,\s*"
        r"selector: (\w+)\s*\.get_or_init\(\|\| STS_CLAIM\.render\(\)\),\s*"
        r"action: (\w+)\s*\.get_or_init\(\|\| STS_SPEC\.auth\s*\.map\(\|auth\| auth\.render\(\)\)\s*\.unwrap_or_default\(\)\),\s*"
        r"resource: ResourceShape::Service,\s*"
        r"success_status: 200,\s*"
        r"anonymous: true,\s*"
        r"evidence: &\[ROUTER\],?\s*"
        r"\}\);\s*"
        r"rows\.push\(\s*OVERLAY\s*\.row\(PostV3SpeedtestClientDevnull::NAME\)\s*\.copied\(\)\s*"
        r"\.ok_or\(GatewayAssemblyError::AdminOverlayMissing\)\?,?\s*\);\s*"
        r"rows\.extend_from_slice\(control_plane::ROWS\);\s*"
        r"let record = (\w+)\s*\.get_or_init\(\|\| DialectOverlay \{\s*"
        r'name: "[^"]+",\s*'
        r"vendor: OVERLAY\.vendor,\s*"
        r"claims: CLAIMS,\s*"
        r"operations: (\w+)\s*\.get_or_init\(\|\| rows\),?\s*"
        r"\}\);\s*"
        r"(?:"
        r"let builder = " + claimed_chain + r";\s*"
        r"(?:control_plane::declare\(builder\)|let builder = control_plane::declare\(builder\);\s*builder)"
        r"|"
        r"control_plane::declare\(\s*" + claimed_chain + r",?\s*\)"
        r")\s*\.build\(\)\s*\.map_err\(GatewayAssemblyError::AdminDialect\)"
    )
    matched = re.fullmatch(pattern, rest)
    if not matched:
        fail("control plane: unsupported object_lambda_dialect installation")
    s1, s2, s3, s4, rec_cache, rows_cache = matched.groups()
    if ({s1, s2, s3, s4} != caches["String"]
            or {rec_cache} != caches["DialectOverlay"]
            or {rows_cache} != caches["Vec<OverlayRow>"]):
        fail("control plane: object_lambda_dialect cache bindings disagree")


def verify_assemble_object_lambda_fallback(control, registered, close, fail):
    """Verify `control_plane::assemble_object_lambda_fallback` builds the fallback service without `native_routes`."""
    match = direct_item(
        control,
        r"(?:pub(?:\([^)]*\))?\s+)?fn\s+assemble_object_lambda_fallback\s*\(\s*"
        r"assembly:\s*&?GatewayAssembly,\s*"
        r"iam:\s*Arc<dyn IamKeyLookup>,\s*"
        r"root:\s*Arc<dyn RootSource>,\s*"
        r"router:\s*Arc<(?:crate::admin::router::)?S3Router<(?:crate::admin::router::)?AdminOperation>>,\s*"
        r"host:\s*&?Arc<Host>,?\s*"
        r"\)\s*->\s*Result<(?:rustfs_gateway::)?S3Service,\s*GatewayAssemblyError>\s*\{",
        "assemble_object_lambda_fallback",
        close,
        fail,
    )
    body = " ".join(control[match.end():close(control, match.end() - 1, "{", "}")].split())
    if re.search(r"\bnative_routes\b", body):
        fail("control plane: assemble_object_lambda_fallback must not include native_routes")
    regs_pat = _registration_pattern(registered, allow_cloned_last=True, allow_borrowed_host=True)
    chain = (
        r"builder\s*\.hand_caller_secret_to_every_operation_after_listing_in_the_posture_report\(\)\s*"
        r"\.dialect\(&object_lambda_dialect\(\)\?\)\s*"
        + regs_pat
        + r"\s*\.build\(\)\s*\.map_err\(GatewayAssemblyError::Service\)"
    )
    pattern = (
        r"let gate = Admission \{\s*(?:router:\s*Arc::clone\(&router\)|router),?\s*\};\s*"
        r"let authenticator = \|authenticator: SigV4Authenticator\| \{\s*"
        r"authenticator\s*\.hand_caller_secret_to_handlers\(\)\s*"
        r"\.verify_paths_double_encoded_under\(TABLE_CATALOG_PREFIXES\)\s*"
        r"\};\s*"
        r"let \(builder, _settings\) = GatewayStack::configured_builder\(\s*"
        r"&?assembly,\s*iam,\s*root,\s*gate,\s*authenticator,?\s*\)\?\s*"
        r"\.config\(\s*super::service_config\(\s*assembly\.body_read_timeout,\s*CLAIMED_ROUTE_BODY_BYTES,?\s*\),?\s*\);\s*"
        r"(?:" + chain + r"|let service = " + chain + r"\?;\s*Ok\(service\))"
    )
    if not re.fullmatch(pattern, body):
        fail("control plane: unsupported assemble_object_lambda_fallback implementation")


def verify_control_assemble_prefix(assembly, has_native_routes, has_lambda_fallback, fail):
    """Verify the control-plane assembly prefix; return True iff `object_lambda_fallback` is bound before `let service`."""
    prefix_part = assembly.split("let service = builder", 1)[0].strip()
    if not has_lambda_fallback:
        prefix = """let gate = Admission { router: Arc::clone(&router), }; let authenticator = |authenticator: SigV4Authenticator| {
            authenticator .hand_caller_secret_to_handlers() .verify_paths_double_encoded_under(TABLE_CATALOG_PREFIXES) };
            let host = Arc::new(Host { router, server_ctx: Arc::clone(&assembly.server_ctx), });
            let (builder, _settings) = GatewayStack::configured_builder(&assembly, iam, root, gate, authenticator)?
            .config(super::service_config(assembly.body_read_timeout, CLAIMED_ROUTE_BODY_BYTES));"""
        if has_native_routes:
            prefix += " let builder = native_routes::register(builder, &host);"
        if prefix_part != " ".join(prefix.split()):
            fail("control plane: service must install the host admission and handlers")
        return False

    gate_stmt = r"let gate = Admission \{\s*router: Arc::clone\(&router\),?\s*\};"
    auth_stmt = (
        r"let authenticator = \|authenticator: SigV4Authenticator\| \{\s*"
        r"authenticator\s*\.hand_caller_secret_to_handlers\(\)\s*"
        r"\.verify_paths_double_encoded_under\(TABLE_CATALOG_PREFIXES\)\s*"
        r"\};"
    )
    host_stmt = (
        r"let host = Arc::new\(\s*Host \{\s*"
        r"(?:router: Arc::clone\(&router\)|router),\s*"
        r"server_ctx: Arc::clone\(&assembly\.server_ctx\),?\s*"
        r"\},?\s*\);"
    )
    builder_stmt = (
        r"let \(builder, _settings\) = GatewayStack::configured_builder\(\s*"
        r"&assembly,\s*(?:Arc::clone\(&iam\)|iam),\s*(?:Arc::clone\(&root\)|root),\s*gate,\s*authenticator,?\s*\)\?\s*"
        r"\.config\(\s*super::service_config\(\s*assembly\.body_read_timeout,\s*CLAIMED_ROUTE_BODY_BYTES,?\s*\),?\s*\);"
    )
    stmts = [gate_stmt, auth_stmt, host_stmt, builder_stmt]
    if has_native_routes:
        stmts.append(r"let builder = native_routes::register\(\s*builder,\s*&host,?\s*\);")
    if re.fullmatch(r"\s*".join(stmts), prefix_part):
        return False
    for index in range(3, len(stmts) + 1):
        with_fallback = [*stmts[:index], FALLBACK_BIND_RE, *stmts[index:]]
        if re.fullmatch(r"\s*".join(with_fallback), prefix_part):
            return True
    fail("control plane: service must install the host admission and handlers")


def control_bindings(
    host, dialect, assemble, split, fail, published=None, has_native_routes=False, has_lambda_fallback=False, fallback_in_prefix=False
):
    """Match the extension types in the installed dialect, overlay, and returned service builder."""
    def exactly(pattern, text, label):
        return one(pattern, text, label, fail)

    imports = split(exactly(r"use rustfs_gateway_dialect_rustfs_admin::ops::\{([^{}]+)\};", host, "control imports")[1])
    modules = {}
    for item in imports:
        pair = re.fullmatch(r"(\w+)::(\w+)", item)
        if not pair or pair[2] in modules:
            fail("control plane: unsupported or duplicate operation import")
        modules[pair[2]] = pair[1]
    borrowed = exactly(r"const BORROWED: \[&str; (\d+)\] = \[([^\]]+)\];", host, "control overlay names")
    names = split(borrowed[2])
    if len(names) != int(borrowed[1]):
        fail("control plane: invalid overlay count")
    if published is not None:
        rows_tail = "rows.extend_from_slice(control_plane::ROWS);"
        declare_tail = "control_plane::declare(builder) .build() .map_err(GatewayAssemblyError::AdminDialect)"
        if has_native_routes:
            rows_tail += " native_routes::append_rows(&mut rows);"
            declare_tail = (
                "let builder = control_plane::declare(builder); "
                "native_routes::declare(builder) .build() .map_err(GatewayAssemblyError::AdminDialect)"
            )
        suffix = f"""rows.push( OVERLAY .row(PostV3SpeedtestClientDevnull::NAME) .copied()
            .ok_or(GatewayAssemblyError::AdminOverlayMissing)?, ); {rows_tail}
            let record = RECORD.get_or_init(|| DialectOverlay {{ name: "rustfs-control-plane", vendor: OVERLAY.vendor,
            claims: CLAIMS, operations: ROWS.get_or_init(|| rows), }}); let builder = Dialect::assemble(record)
            .declare_claimed::<ControlPlane>(ROUTE) .declare_claimed::<PostV3SpeedtestClientDevnull>(ClaimedRoute {{
            precedence: PostV3SpeedtestClientDevnull::PRECEDENCE, rows: PostV3SpeedtestClientDevnull::rows(),
            shadows: SPEEDTEST_SHADOWS, bucket_param: PostV3SpeedtestClientDevnull::BUCKET, }})
            .declare_form::<StsForm>(STS_ROUTE); {declare_tail}"""
        # Strip only the six declaration caches. Then account for every row added to the record.
        caches = r"(?:static \w+: OnceLock<(?:Vec<OverlayRow>|String|DialectOverlay)> = OnceLock::new\(\); ){6}"
        prefix = """let mut rows = vec![OverlayRow { name: NAME, precedence: ROUTE.precedence,
            selector: SELECTOR.get_or_init(|| render_claimed_route(&ROUTE)),
            action: ACTION.get_or_init(|| SPEC.auth.map(|auth| auth.render()).unwrap_or_default()),
            resource: ResourceShape::Service, success_status: 200, anonymous: true, evidence: &[ROUTER], }];
            rows.push(OverlayRow { name: STS_NAME, precedence: STS_ROUTE.precedence,
            selector: STS_SELECTOR.get_or_init(|| STS_CLAIM.render()),
            action: STS_ACTION.get_or_init(|| STS_SPEC.auth.map(|auth| auth.render()).unwrap_or_default()),
            resource: ResourceShape::Service, success_status: 200, anonymous: true, evidence: &[ROUTER], });"""
        installation = re.sub("^" + caches, "", dialect)
        if installation != " ".join((prefix + " " + suffix).split()):
            fail("control plane: unsupported published overlay installation")
        types = [kind for _, kind, _ in published]
        if any(modules.get(kind) != module for module, kind, _ in published):
            fail("control plane: imported types disagree with the published table")
    else:
        tail = exactly(r'for name in BORROWED \{ rows.push\(OVERLAY.row\(name\).copied\(\).ok_or\('
                       r'GatewayAssemblyError::AdminOverlayMissing\)\?\); \} let record = RECORD.get_or_init\(\|\| DialectOverlay \{ '
                       r'name: "rustfs-control-plane", vendor: OVERLAY.vendor, claims: CLAIMS, operations: ROWS.get_or_init\(\|\| rows\), '
                       r'\}\); Dialect::assemble\(record\) \.declare_claimed::<ControlPlane>\(ROUTE\) '
                       r'\.declare_claimed::<PostV3SpeedtestClientDevnull>\(ClaimedRoute \{ [^{}]+ \}\) '
                       r'\.declare_form::<StsForm>\(STS_ROUTE\) (.*?) \.build\(\) \.map_err\(GatewayAssemblyError::AdminDialect\)$',
                       dialect, "control dialect installation")[1]
        decl = r"\.declare::<(\w+)>\(\1::ROUTE\)"
        types = [m[1] for m in re.finditer(decl, tail)]
        if not types or " ".join(f".declare::<{t}>({t}::ROUTE)" for t in types) != tail or len(set(types)) != len(types):
            fail("control plane: unrecognized or duplicate extension declaration")
    all_borrowed = ["PostV3SpeedtestClientDevnull", *types]
    if names != [t + "::NAME" for t in all_borrowed] or set(all_borrowed) != modules.keys():
        fail("control plane: imported and borrowed operations disagree with the declarations")
    registered = ["ControlPlane", all_borrowed[0], "StsForm", *types]
    if has_lambda_fallback:
        if fallback_in_prefix:
            return_pat = (
                r"Ok\(GatewayStack \{\s*service,\s*keystone_auth: assembly\.keystone_auth,\s*control_plane: true,\s*"
                r"object_lambda_fallback: Some\(object_lambda_fallback\),?\s*\}\)$"
            )
        else:
            return_pat = (
                r"(?:"
                + FALLBACK_BIND_RE
                + r"\s*Ok\(GatewayStack \{\s*service,\s*keystone_auth: assembly\.keystone_auth,\s*control_plane: true,\s*"
                r"object_lambda_fallback: Some\(object_lambda_fallback\),?\s*\}\)"
                r"|Ok\(GatewayStack \{\s*service,\s*keystone_auth: assembly\.keystone_auth,\s*control_plane: true,\s*"
                r"object_lambda_fallback: Some\(\s*" + FALLBACK_CALL_RE + r"\s*\),?\s*\}\)"
                r")$"
            )
        regs = exactly(
            r"let service = builder\s*\.hand_caller_secret_to_every_operation_after_listing_in_the_posture_report\(\)\s*"
            r"\.dialect\(&dialect\(\)\?\)\s*(.*?)\s*\.build\(\)\s*\.map_err\(GatewayAssemblyError::Service\)\?;\s*"
            + return_pat,
            assemble,
            "returned control service",
        )[1]
        if not re.fullmatch(_registration_pattern(registered, allow_cloned_last=True, allow_borrowed_host=False), regs):
            fail("control plane: installed handlers disagree with the declarations")
    else:
        regs = exactly(r"let service = builder \.hand_caller_secret_to_every_operation_after_listing_in_the_posture_report\(\) "
                       r"\.dialect\(&dialect\(\)\?\) (.*?) \.build\(\) \.map_err\(GatewayAssemblyError::Service\)\?; "
                       r"Ok\(GatewayStack \{ service, keystone_auth: assembly.keystone_auth, control_plane: true, \}\)$",
                       assemble, "returned control service")[1]
        expected = [f".register::<{t}, _>(Arc::clone(&host))" for t in registered[:-1]]
        if regs != " ".join([*expected, f".register::<{registered[-1]}, _>(host)"]):
            fail("control plane: installed handlers disagree with the declarations")
    return [(modules[t], t) for t in types]


CONTROL_HOST = "rustfs/src/server/gateway_stack/control_plane.rs"
NATIVE_ROUTES = "rustfs/src/server/gateway_stack/control_plane/native_routes.rs"
NATIVE_AUTHORITY = "rustfs/src/server/gateway_stack/control_plane/native_authority.rs"
HTTP_HOST = "rustfs/src/server/http.rs"
STACK_DISPATCH = "rustfs/src/server/stack.rs"
ADMIN_ROUTER = "rustfs/src/admin/router.rs"


def native_tables(root, repository, actions, strip, close, split, fail, admin_actions=None):
    """Read each table from its host registrations and the dependency its Cargo.lock selects."""
    def read(path):
        if not (root / path).is_file():
            fail(f"RustFS source file {path} is missing")
        return strip((root / path).read_text(encoding="utf-8"))

    def function(text, name):
        start = one(rf"\bfn {name}\b[^;{{}}]*\{{", text, name, fail).end()
        return " ".join(text[start:close(text, start - 1, "{", "}")].split())

    def shapes(pattern, text, what):
        if not re.fullmatch(pattern, text):
            fail(f"metadata listings: unsupported {what}")

    if not (root / "Cargo.lock").is_file():
        fail("missing RustFS Cargo.lock for native metadata listings")
    pin = locked_revision((root / "Cargo.lock").read_text(encoding="utf-8"), fail)

    def git_object(*args):
        result = subprocess.run(["git", "--no-replace-objects", "-C", str(repository), "cat-file", *args],
                                env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": ""},
                                capture_output=True, text=True, check=False)
        if result.returncode:
            fail(f"local gateway repository lacks the Cargo.lock object {args[-1]}")
        return result.stdout

    if git_object("-t", pin).strip() != "commit":
        fail(f"Cargo.lock revision {pin} is not a commit")

    def blob(path):
        return git_object("blob", f"{pin}:{path}")

    package = tomllib.loads(blob(DIALECT_DIR + "/Cargo.toml"))["package"]
    if package["name"] != DIALECT_PACKAGE:
        fail(f"{pin}:{DIALECT_DIR} is not the locked dialect package")
    host = read(NATIVE_HANDLER)
    # Only the fully assembled, returned S3 service establishes that these declarations are enabled.
    stack = read(NATIVE_STACK)
    stack_declares_lambda_fallback = gateway_stack_lambda_field(stack, close, split, fail)
    assembly = function(stack, "assemble_with")
    wrappers = (("assemble", "Self::assemble_with(assembly, iam, root, early_gate(OPERATIONS, server_ctx))"),
                ("assemble_control_plane", "control_plane::assemble(assembly, iam, root, router)"))
    for entry, result in wrappers:
        if not function(stack, entry).endswith(result):
            fail(f"native tables: unsupported GatewayStack::{entry} return")
    edge = function(read(HTTP_HOST), "assemble_s3_stack")
    for assignment in ("let control_plane = GatewayEdgeService(GatewayStack::assemble_control_plane(assembly.clone(), Arc::new(router)).map_err(Error::other)?);",
                       "let s3 = GatewayEdgeService(GatewayStack::assemble(assembly).map_err(Error::other)?);"):
        if edge.count(assignment) != 1:
            fail("native tables: missing HTTP host assembly")
    one(r"Ok\(S3StackService::new\(s3\) [^;{}]*\.with_control_plane\(Some\(control_plane\)\)\)$",
        edge, "installed HTTP services", fail)
    dispatcher = " ".join(read(STACK_DISPATCH).split())
    one(r"let claimed = claims_route\(request.method\(\), request.uri\(\), request.headers\(\)\);",
        dispatcher, "edge claim", fail)
    one(r"if !claimed \{ let mut request = request; if let Some\(path\) = OriginalS3Path::from_uri\(request.uri\(\)\) \{ "
        r"request.extensions_mut\(\).insert\(path\); \} return Box::pin\(self.s3.call\(request\)\); \} "
        r"match &mut self.control_plane \{ Some\(control_plane\) => Box::pin\(control_plane.call\(request\)\), "
        r"None => bare\(http::StatusCode::NOT_IMPLEMENTED\), \}", dispatcher, "exclusive edge dispatch", fail)
    router_src = read(ADMIN_ROUTER)
    shapes(r"s3_extension::route_key\(method, uri\)\.is_some\(\) \|\| parse_object_lambda_request\(method, uri\)\.is_some\(\) "
           r"\|\| is_control_plane_route\(method, uri, headers\)", function(router_src, "claims_route"), "edge claims")
    assemble_with_return = (
        r"Ok\(Self \{ service, keystone_auth: assembly\.keystone_auth, control_plane: false, object_lambda_fallback: None,? \}\)"
        if stack_declares_lambda_fallback
        else r"Ok\(Self \{ service, keystone_auth: assembly\.keystone_auth, control_plane: false, \}\)"
    )
    shapes(r"let listings = metadata_listing::dialect\(\)\.map_err\(GatewayAssemblyError::MetadataListingDialect\)\?; "
           r"let builder = Self::configured_builder\(&assembly, iam, root, authorizer, std::convert::identity\)\? "
           r"\.answer_nul_torrent_keys_as_missing\(\) \.dialect\(&listings\); "
           r"let backend = Arc::new\(GatewayBackend::new\(Arc::clone\(&assembly.server_ctx\)\)\); "
           r"let builder = metadata_listing::register\(register\(OPERATIONS, builder, &backend\), &assembly.server_ctx\); "
           r"let service = builder.build\(\).map_err\(GatewayAssemblyError::Service\)\?; "
           + assemble_with_return, assembly, "S3 service assembly")
    bindings = re.findall(r"use rustfs_gateway_dialect_rustfs_admin::ops::(\w+)::\{\s*self as (\w+),\s*(\w+),?\s*\};", host)
    if len(bindings) != 2 or any(len({b[i] for b in bindings}) != 2 for i in range(3)):
        fail("metadata listings: expected two distinct typed dialect imports")
    modules = {alias: (module, kind) for module, alias, kind in bindings}
    def array(name, field):
        elems = split(one(rf"\b{name}: \[[^;]+; 2\] = \[([^\]]+)\];", host, name, fail)[1])
        aliases = [v.split("::")[0] for v in elems if re.fullmatch(rf"\w+::{field}", v)]
        if len(elems) != 2 or set(aliases) != modules.keys():
            fail(f"metadata listings: {name} does not bind both imports")
        return aliases
    def active_table(text, table):
        if "native::extensions::" not in text:
            return None
        direct_item(text, rf"\buse rustfs_gateway_dialect_rustfs_admin::native::extensions::{table};",
                    table + " host import", close, fail)
        base = DIALECT_DIR + "/src/"
        for path, name in (("lib.rs", "native"), ("lib.rs", "ops"), ("native.rs", "extensions")):
            direct_item(strip(blob(base + path)), rf"\bpub mod {name};", path + "/" + name, close, fail)
        rows = published_table(strip(blob(base + "native/extensions.rs")), table, close, split, fail)
        mods = strip(blob(base + "ops/mod.rs"))
        for stem, _, _ in rows:
            direct_item(mods, rf"\bpub mod {stem};", "ops/" + stem, close, fail)
        return rows

    s3_table = active_table(host, "s3")
    if s3_table is not None:
        order = array("NAMES", "NAME")
        kinds = [modules[a][1] for a in order]
        if [modules[a] for a in order] != [(module, kind) for module, kind, _ in s3_table]:
            fail("metadata listings: NAMES and published S3 table disagree")
        one(r'static RECORD: DialectOverlay = DialectOverlay\s*\{\s*name: "rustfs-metadata-listings",\s*'
            r'vendor: "rustfs",\s*operations: s3::ROWS,\s*claims: &\[\],\s*\};', host, "published S3 overlay", fail)
        shapes(r"s3::declare\(Dialect::assemble\(&RECORD\)\)\.build\(\)", function(host, "dialect"), "published S3 builder")
    else:
        order = array("ROWS", "OVERLAY_ROW")
        if array("NAMES", "NAME") != order:
            fail("metadata listings: ROWS and NAMES disagree")
        one(r"static RECORD: DialectOverlay = DialectOverlay\s*\{\s*name: \"[^\"]+\",\s*vendor: \"rustfs\",\s*"
            r"operations: &ROWS,\s*claims: &\[\],\s*\};", host, "typed overlay", fail)
        kinds = [modules[a][1] for a in order]
        dialect = function(host, "dialect")
        caches = re.findall(r"static (\w+): OnceLock<Vec<ShadowingDecl>>", dialect)
        if len(caches) != 2 or len(set(caches)) != 2 or set(re.findall(r"::ROUTE, &(\w+)\)", dialect)) != set(caches):
            fail("metadata listings: declarations must have independent shadow caches")
        shapes(r"(?:static \w+: OnceLock<Vec<ShadowingDecl>> = OnceLock::new\(\); ){2}Dialect::assemble\(&RECORD\) "
               + " ".join(rf"\.declare::<{k}>\(on_the_s3_table\({k}::ROUTE, &\w+\)\)" for k in kinds)
               + r" \.build\(\)", dialect, "typed declarations")
        shapes(r"let shadows = shadows.get_or_init\(\|\| \{ route \.shadows \.iter\(\) "
               r'\.filter\(\|decl\| !decl.shadowed.starts_with\("rustfs:"\) \|\| NAMES.contains\(&decl.shadowed\)\) '
               r"\.copied\(\) \.collect\(\) \}\); DialectRoute \{ shadows, \.\.route \}", function(host, "on_the_s3_table"),
               "S3-table shadow projection")
    shapes(r"let listings = Arc::new\(Listings \{ server_ctx: Arc::clone\(server_ctx\), \}\); builder "
           + rf"\.register::<{kinds[0]}, _>\(Arc::clone\(&listings\)\) \.register::<{kinds[1]}, _>\(listings\)",
           function(host, "register"), "registered listing handlers")
    one(r"impl<O: Listing> Handler<O> for Listings\s*\{\s*async fn call\([^{}]+\{\s*"
        r"self.serve\(request\).await.map_err\(handler_error\)\s*\}\s*\}", host, "active handler", fail)
    shapes(r"let mut envelope = access::admit\(&self.server_ctx, request.context\(\)\).await\?; "
           r"let bucket = request \.context\(\) \.bucket\(\) \.ok_or_else\(\|\| s3_error!\(InternalError, \"[^\"]*\"\)\)\? "
           r"\.as_str\(\) \.to_owned\(\); metadata_listing::authorize\(&mut envelope, O::LISTING, &bucket\).await\?; "
           r"let body = metadata_listing::answer\(&envelope, O::LISTING, bucket\).await\?; "
           r'Ok\(Resp::new\(AdminResponse::bytes\("application/xml", body\)\)\)', function(host, "serve"), "listing authorization order")
    app = read(NATIVE_ACCESS)
    shapes(r"authorize_bucket_listing\(req, bucket, listing.action\(\)\).await", function(app, "authorize"), "listing access")
    arms = re.fullmatch(r"match self \{ (.*?) \}", function(app, "action"))
    if not arms:
        fail("metadata listings: unreadable host S3 action match")
    mapping = {}
    for arm in split(arms[1]):
        row = re.fullmatch(r"Self::(\w+) => S3Action::(\w+)", arm)
        if not row or row[1] in mapping or row[2] not in actions:
            fail("metadata listings: unresolved host S3 action")
        mapping[row[1]] = row[2]
    rows = []
    variants = set()
    for index, alias in enumerate(order):
        module, kind = modules[alias]
        variant = one(rf"impl Listing for {kind}\s*\{{\s*const LISTING: MetadataListing = MetadataListing::(\w+);\s*\}}",
                      host, kind + " listing binding", fail)[1]
        if variant not in mapping or variant in variants:
            fail(f"metadata listings: no host action for {variant}")
        variants.add(variant)
        path = f"{DIALECT_DIR}/src/ops/{module}.rs"
        action = actions[mapping[variant]]
        row = typed_route(strip(blob(path)), kind, fail, split)
        if s3_table is not None:
            row["precedence"] = s3_table[index][2]
        verify_listing(row, action, fail)
        row["source"] = f"{pin}:{path}"
        rows.append(row)
    if len(mapping) != 2 or len(set(kinds)) != 2 or rows[0]["precedence"] >= rows[1]["precedence"]:
        fail("metadata listings: binding coverage or listing precedence disagrees")
    control = read(CONTROL_HOST)
    control_table = active_table(control, "control_plane")
    has_native_routes = (
        bool(re.search(r"\b(?:native_routes|native_authority)\b", control))
        or (root / NATIVE_ROUTES).is_file()
        or (root / NATIVE_AUTHORITY).is_file()
    )
    if has_native_routes and control_table is None:
        fail("control plane: native routes require the published control_plane table")
    control_dialect = function(control, "dialect")
    control_assemble = function(control, "assemble")
    if stack_declares_lambda_fallback:
        if control_table is None:
            fail("control plane: object_lambda_fallback requires the published control_plane table")
        verify_gateway_stack_call_lambda_fallback(stack, close, split, fail)
        verify_object_lambda_dialect(control, close, fail)
        fallback_in_prefix = verify_control_assemble_prefix(control_assemble, has_native_routes, True, fail)
        bindings = control_bindings(
            control,
            control_dialect,
            control_assemble,
            split,
            fail,
            control_table,
            has_native_routes,
            has_lambda_fallback=True,
            fallback_in_prefix=fallback_in_prefix,
        )
        registered = ["ControlPlane", "PostV3SpeedtestClientDevnull", "StsForm", *[kind for _, kind in bindings]]
        verify_assemble_object_lambda_fallback(control, registered, close, fail)
        has_lambda_fallback = True
    else:
        if re.search(r"\b(?:object_lambda_dialect|assemble_object_lambda_fallback)\b", control):
            fail("control plane: unexpected object_lambda_fallback helper without GatewayStack field")
        if control_table is not None:
            verify_control_assemble_prefix(control_assemble, has_native_routes, False, fail)
        bindings = control_bindings(control, control_dialect, control_assemble, split, fail, control_table, has_native_routes)
        has_lambda_fallback = False

    if has_native_routes:
        direct_item(control, r"\bmod\s+native_authority\s*;", "control native_authority module", close, fail)
        direct_item(control, r"\bmod\s+native_routes\s*;", "control native_routes module", close, fail)
        routes_src = read(NATIVE_ROUTES)
        authority_src = read(NATIVE_AUTHORITY)
        mounted_modules = native_claimed_routes(
            routes_src, authority_src, blob, has_lambda_fallback, admin_actions, strip, close, split, fail
        )
        if "delete_v3_target_by_target_type_by_target_name" in mounted_modules:
            shapes(
                r"let key = route_key_canonical\(method, uri\.path\(\)\); "
                r"let matched = self\.table\.at\(&key\)\.map_err\(\|_\| S3Error::new\(S3ErrorCode::NotImplemented\)\)\?; "
                r"super::handlers::event::extract_target_params\(&matched\.params\)\?; Ok\(\(\)\)",
                function(router_src, "validate_notification_target_params"),
                "notification target parameter check",
            )
    if control_table is not None:
        if has_native_routes:
            shapes(
                r"\[NAME, STS_NAME\]\.contains\(&operation\) \|\| BORROWED\.contains\(&operation\) "
                r"\|\| native_routes::contains\(operation\)",
                function(control, "served"),
                "admitted control operation set",
            )
            one(r"\basync fn route\b[^;{}]*\{", control, "async Admission::route", fail)
            target_check = (
                r"if request\.operation == rustfs_gateway_dialect_rustfs_admin::native::ops::delete_v3_target_by_target_type_by_target_name::NAME \{ "
                r"self\.router \.validate_notification_target_params\(&head\.method, &head\.uri\) \.map_err\(handler_error\)\?; \} "
                if "delete_v3_target_by_target_type_by_target_name" in mounted_modules
                else r""
            )
            shapes(
                r"if !served\(request\.operation\) \{ return Ok\(routed\(request\)\); \} "
                r"let head = context \.server_extensions\(\) \.get::<ClaimedHead>\(\) "
                r'\.ok_or_else\(\|\| handler_error\(s3_error!\(InternalError, "[^"]+"\)\)\)\?; '
                r"let signed = request\.identity\.is_some\(\) && !head\.repeated_authorization; "
                r"self\.router \.admit\(&head\.method, &head\.uri, &head\.headers, signed\) \.map_err\(handler_error\)\?; "
                r"if head\.repeated_authorization \{ return Ok\(Decision::Deny\); \} "
                r"if native_routes::contains\(request\.operation\) \{ "
                + target_check
                + r"if let Err\(error\) = native_authority::authorize\(context, request, head\)\.await \{ "
                r"if error\.code\(\) == &rustfs_s3_types::S3ErrorCode::AccessDenied \{ return Ok\(Decision::Deny\); \} "
                r"return Err\(handler_error\(error\)\); \} \} "
                r"Ok\(Decision::Allow\)",
                function(control, "route"),
                "host admission",
            )
            shapes(
                r"(?:Box::pin\(self\.route\(context, request\)\)|Box::pin\(async move \{ self\.route\(context, request\)\.await \}\))",
                function(control, "authorize_route_result"),
                "active control admission",
            )
            shapes(
                r"Box::pin\(async move \{ self\.route\(context, request\)\.await\.unwrap_or\(Decision::Deny\) \}\)",
                function(control, "authorize_route"),
                "control admission decision",
            )
        else:
            if re.search(r"\basync fn route\b", control):
                fail("control plane: unexpected async Admission::route without native_routes")
            shapes(r"\[NAME, STS_NAME\]\.contains\(&operation\) \|\| BORROWED\.contains\(&operation\)",
                   function(control, "served"), "admitted control operation set")
            admission = function(control, "route")
            shapes(r"if !served\(request.operation\) \{ return Ok\(routed\(request\)\); \} let head = context "
                   r"\.server_extensions\(\) \.get::<ClaimedHead>\(\) "
                   r'\.ok_or_else\(\|\| handler_error\(s3_error!\(InternalError, "[^"]+"\)\)\)\?; '
                   r"let signed = request.identity.is_some\(\) && !head.repeated_authorization; self.router "
                   r"\.admit\(&head.method, &head.uri, &head.headers, signed\) \.map_err\(handler_error\)\?; "
                   r"Ok\(if head.repeated_authorization \{ Decision::Deny \} else \{ Decision::Allow \}\)", admission, "host admission")
            shapes(r"let decision = self.route\(context, request\); Box::pin\(async move \{ decision \}\)",
                   function(control, "authorize_route_result"), "active control admission")
            shapes(r"let decision = self.route\(context, request\)\.unwrap_or\(Decision::Deny\); Box::pin\(async move \{ decision \}\)",
                   function(control, "authorize_route"), "control admission decision")
        shapes(r"if served\(request.operation\) \|\| request.identity.is_some\(\) \{ Decision::Allow \} else \{ Decision::Deny \}",
               function(control, "routed"), "admitted control inputs")
        shapes(r"let stage = routed\(request.route\(\)\); let decisions = request.decide_all\(stage, \|_\| stage\); "
               r"Box::pin\(async move \{ decisions \}\)", function(control, "authorize_input"), "control input decisions")
    control_rows = []
    for index, (module, kind) in enumerate(bindings):
        path = f"{DIALECT_DIR}/src/ops/{module}.rs"
        row = typed_route(strip(blob(path)), kind, fail, split)
        if control_table is not None:
            row["precedence"] = control_table[index][2]
        if row["query_requires"]:
            fail(f"{kind}: unexpected additional control-plane predicate")
        row["source"] = f"{pin}:{path}"
        control_rows.append(row)
    if len({row["precedence"] for row in control_rows}) != len(control_rows):
        fail("control plane: extension precedence is ambiguous")
    return {"s3": rows, "control_plane": sorted(control_rows, key=lambda row: row["precedence"])}


def legacy_admin_extensions(source, matching_close, fail):
    def squash(text):
        return re.sub(r"\s+", " ", text)

    relative = "rustfs/src/admin/router.rs"
    text = source.text(relative)
    rows = []
    for function, enum, target_rule in (
        ("parse_replication_extension_request", "ReplicationExtRoute", "bucket"),
        ("parse_misc_extension_request", "MiscExtRoute", None),
    ):
        match = re.search(rf"fn {function}\([^)]*\)\s*->[^{{]*\{{", text)
        if not match:
            fail(f"{relative}: {function} not found")
        body = text[match.end():matching_close(text, match.end() - 1, "{", "}")]
        methods = [(m.start(), m.group(1)) for m in re.finditer(r"method\s*[!=]=\s*Method::(\w+)", body)]
        for variant in re.finditer(rf"{enum}::(\w+)(\s*\{{[^}}]*\}})?", body):
            before = body[:variant.start()]
            keys = re.findall(r'query_value_exact\(uri,\s*"([^"]+)"\)', before)
            if not keys:
                fail(f"{relative}: {enum}::{variant.group(1)} has no preceding query key")
            key = keys[-1]
            conditions = [c for c in re.findall(r"\bif\s+(.*?)\{", before, re.S) if f'"{key}"' in c or "value" in c]
            if not conditions:
                fail(f"{relative}: {enum}::{variant.group(1)} has no condition naming {key}")
            condition = conditions[-1]
            equals = re.search(r'value\s*==\s*"([^"]*)"|as_deref\(\)\s*==\s*Some\("([^"]*)"\)', condition)
            if equals:
                value_rule = f"equals:{equals.group(1) if equals.group(1) is not None else equals.group(2)}"
            elif "value.is_empty()" in condition:
                value_rule = "equals:"
            elif ".is_some()" in condition:
                value_rule = "present"
            else:
                fail(f"{relative}: unreadable discriminator condition {squash(condition)!r}")
            method = [name for start, name in methods if start < variant.start() and "!=" not in body[start:start + 12]]
            negated = [name for start, name in methods if "!=" in body[start:start + 12]]
            method_name = (method[-1] if method else negated[0] if negated else None)
            if method_name is None:
                fail(f"{relative}: {enum}::{variant.group(1)} has no method")
            fields = variant.group(2) or ""
            if target_rule:
                target = target_rule
            elif "object" in fields:
                target = "object"
            elif "None" in fields:
                target = "service"
            else:
                target = "bucket"
            rows.append({
                "name": f"{enum}::{variant.group(1)}" + ("" if not fields else f"[{target}]"),
                "variant": variant.group(1),
                "fields": fields,
                "method": method_name,
                "target": target,
                "query_discriminator": {"key": key, "rule": value_rule},
                "auth_mode": "custom",
                "auth_detail": "SignatureRequiredThenHandlerCheck",
            })
    actions = {}
    for function in ("replication_extension_policy_action", "authorize_misc_extension_request"):
        match = re.search(rf"fn {function}\([^)]*\)[^{{]*\{{", text)
        if not match:
            fail(f"{relative}: {function} not found")
        body = text[match.end():matching_close(text, match.end() - 1, "{", "}")]
        for arm in re.finditer(r"((?:\w+Route::\w+(?:\s*\{[^}]*\})?\s*\|?\s*)+)=>(.*?)(?=\w+Route::\w+(?:\s*\{[^}]*\})?\s*(?:\||=>)|\Z)", body, re.S):
            action = re.search(r"Action::\w+\((\w+)::(\w+)\)", arm.group(2))
            if not action:
                continue
            for route in re.finditer(r"(\w+)Route::(\w+)(\s*\{[^}]*\})?", arm.group(1)):
                actions.setdefault((route.group(2), squash(route.group(3) or "")), (action.group(1), action.group(2)))
    for row in rows:
        variant, fields = row.pop("variant"), squash(row.pop("fields"))
        found = actions.get((variant, fields)) or actions.get((variant, ""))
        if found is None:
            candidates = [a for (v, f), a in actions.items() if v == variant and (("None" in f) == ("None" in fields))]
            found = candidates[0] if len(candidates) == 1 else None
        if found is None:
            fail(f"{relative}: no authorisation action for {row['name']}")
        row["iam_action_enum"], row["iam_action"] = found
    return rows

def extension_inventory(root, repository, source, names, strip, close, split, wire_name, fail):
    legacy = root / METADATA_ROUTE
    if (root / NATIVE_HANDLER).is_file():
        if legacy.is_file():
            fail("both legacy and native metadata listing selectors are present; cannot establish the active host")
        tables = native_tables(
            root, repository, names.get("S3Action", {}), strip, close, split, fail, names.get("AdminAction", {})
        )
        authorities = [HTTP_HOST, STACK_DISPATCH, ADMIN_ROUTER, NATIVE_STACK, NATIVE_HANDLER, NATIVE_ACCESS, CONTROL_HOST]
        if (root / NATIVE_ROUTES).is_file():
            authorities.extend([NATIVE_ROUTES, NATIVE_AUTHORITY])
        authorities.append("Cargo.lock")
        return {"extension_tables": tables}, authorities
    if not legacy.is_file():
        fail(f"RustFS source file {METADATA_ROUTE} is missing")
    rows = metadata_listing_routes(strip(legacy.read_text(encoding="utf-8")), METADATA_ROUTE, fail, close)
    rows.extend(legacy_admin_extensions(source, close, fail))
    for row in rows:
        row["iam_action_wire"] = wire_name(row["iam_action"], names, row.pop("iam_action_enum"))
    return {"extension_routes": rows}, ["rustfs/src/admin/router.rs extension parsers", f"{METADATA_ROUTE} metadata listing selector"]
