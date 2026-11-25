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


def control_bindings(host, dialect, assemble, split, fail, published=None):
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
        suffix = """rows.push( OVERLAY .row(PostV3SpeedtestClientDevnull::NAME) .copied()
            .ok_or(GatewayAssemblyError::AdminOverlayMissing)?, ); rows.extend_from_slice(control_plane::ROWS);
            let record = RECORD.get_or_init(|| DialectOverlay { name: "rustfs-control-plane", vendor: OVERLAY.vendor,
            claims: CLAIMS, operations: ROWS.get_or_init(|| rows), }); let builder = Dialect::assemble(record)
            .declare_claimed::<ControlPlane>(ROUTE) .declare_claimed::<PostV3SpeedtestClientDevnull>(ClaimedRoute {
            precedence: PostV3SpeedtestClientDevnull::PRECEDENCE, rows: PostV3SpeedtestClientDevnull::rows(),
            shadows: SPEEDTEST_SHADOWS, bucket_param: PostV3SpeedtestClientDevnull::BUCKET, })
            .declare_form::<StsForm>(STS_ROUTE); control_plane::declare(builder) .build()
            .map_err(GatewayAssemblyError::AdminDialect)"""
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
    regs = exactly(r"let service = builder \.hand_caller_secret_to_every_operation_after_listing_in_the_posture_report\(\) "
                   r"\.dialect\(&dialect\(\)\?\) (.*?) \.build\(\) \.map_err\(GatewayAssemblyError::Service\)\?; "
                   r"Ok\(GatewayStack \{ service, keystone_auth: assembly.keystone_auth, control_plane: true, \}\)$",
                   assemble, "returned control service")[1]
    registered = ["ControlPlane", all_borrowed[0], "StsForm", *types]
    expected = [f".register::<{t}, _>(Arc::clone(&host))" for t in registered[:-1]]
    if regs != " ".join([*expected, f".register::<{registered[-1]}, _>(host)"]):
        fail("control plane: installed handlers disagree with the declarations")
    return [(modules[t], t) for t in types]


CONTROL_HOST = "rustfs/src/server/gateway_stack/control_plane.rs"
HTTP_HOST = "rustfs/src/server/http.rs"
STACK_DISPATCH = "rustfs/src/server/stack.rs"
ADMIN_ROUTER = "rustfs/src/admin/router.rs"


def native_tables(root, repository, actions, strip, close, split, fail):
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
    shapes(r"s3_extension::route_key\(method, uri\)\.is_some\(\) \|\| parse_object_lambda_request\(method, uri\)\.is_some\(\) "
           r"\|\| is_control_plane_route\(method, uri, headers\)", function(read(ADMIN_ROUTER), "claims_route"), "edge claims")
    shapes(r"let listings = metadata_listing::dialect\(\)\.map_err\(GatewayAssemblyError::MetadataListingDialect\)\?; "
           r"let builder = Self::configured_builder\(&assembly, iam, root, authorizer, std::convert::identity\)\? "
           r"\.answer_nul_torrent_keys_as_missing\(\) \.dialect\(&listings\); "
           r"let backend = Arc::new\(GatewayBackend::new\(Arc::clone\(&assembly.server_ctx\)\)\); "
           r"let builder = metadata_listing::register\(register\(OPERATIONS, builder, &backend\), &assembly.server_ctx\); "
           r"let service = builder.build\(\).map_err\(GatewayAssemblyError::Service\)\?; "
           r"Ok\(Self \{ service, keystone_auth: assembly.keystone_auth, control_plane: false, \}\)", assembly, "S3 service assembly")
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
    if control_table is not None:
        assembly = function(control, "assemble")
        prefix = """let gate = Admission { router: Arc::clone(&router), }; let authenticator = |authenticator: SigV4Authenticator| {
            authenticator .hand_caller_secret_to_handlers() .verify_paths_double_encoded_under(TABLE_CATALOG_PREFIXES) };
            let host = Arc::new(Host { router, server_ctx: Arc::clone(&assembly.server_ctx), });
            let (builder, _settings) = GatewayStack::configured_builder(&assembly, iam, root, gate, authenticator)?
            .config(super::service_config(assembly.body_read_timeout, CLAIMED_ROUTE_BODY_BYTES));"""
        if assembly.split("let service = builder", 1)[0].strip() != " ".join(prefix.split()):
            fail("control plane: service must install the host admission and handlers")
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
    bindings = control_bindings(control, function(control, "dialect"), function(control, "assemble"), split, fail, control_table)
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
        tables = native_tables(root, repository, names.get("S3Action", {}), strip, close, split, fail)
        return {"extension_tables": tables}, [HTTP_HOST, STACK_DISPATCH, ADMIN_ROUTER, NATIVE_STACK, NATIVE_HANDLER, NATIVE_ACCESS, CONTROL_HOST, "Cargo.lock"]
    if not legacy.is_file():
        fail(f"RustFS source file {METADATA_ROUTE} is missing")
    rows = metadata_listing_routes(strip(legacy.read_text(encoding="utf-8")), METADATA_ROUTE, fail, close)
    rows.extend(legacy_admin_extensions(source, close, fail))
    for row in rows:
        row["iam_action_wire"] = wire_name(row["iam_action"], names, row.pop("iam_action_enum"))
    return {"extension_routes": rows}, ["rustfs/src/admin/router.rs extension parsers", f"{METADATA_ROUTE} metadata listing selector"]
