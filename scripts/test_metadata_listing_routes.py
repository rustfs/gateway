#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Read RustFS's metadata listing selector, and refuse every shape the reader cannot vouch for."""

import subprocess
import tempfile
import unittest
from pathlib import Path

import gen_rustfs_admin_route_inventory as inventory
import rustfs_metadata_listing_routes as metadata

# A self-written fixture with the shape the reader expects: a GET-only selector over a bucket, one
# `metadata=true` gate, then the versions and list-type arms, and the access check's action match.
FIXTURE = '''
fn metadata_operation(method: &Method, uri: &Uri, headers: &HeaderMap, host: Option<&MultiDomain>) -> Option<BucketTarget> {
    if method != Method::GET {
        return None;
    }
    let bucket = bucket_from_request(uri, headers, host).ok()?;
    let query = uri.query()?;
    if query_value(query, "metadata").as_deref() != Some("true") {
        return None;
    }
    let operation = if query_has(query, "versions") {
        MetadataOperation::ListObjectVersions
    } else if query_value(query, "list-type").as_deref() == Some("2") {
        MetadataOperation::ListObjectsV2
    } else {
        return None;
    };
    Some(BucketTarget { operation, bucket })
}
async fn check_metadata_access(req: &mut S3Request<Body>, target: BucketTarget) -> S3Result<()> {
    let action = match target.operation {
        MetadataOperation::ListObjectVersions => S3Action::ListBucketVersionsAction,
        MetadataOperation::ListObjectsV2 => S3Action::ListBucketAction,
    };
    authorize_bucket_listing(req, &target.bucket, action).await
}
'''


def read(text):
    return metadata.metadata_listing_routes(text, metadata.METADATA_ROUTE, inventory.fail, inventory.matching_close)


class MetadataListingRoutes(unittest.TestCase):
    def test_reads_both_shapes_in_the_order_rustfs_tries_them(self):
        rows = read(FIXTURE)
        self.assertEqual([row["name"] for row in rows], [
            "MetadataOperation::ListObjectVersions",
            "MetadataOperation::ListObjectsV2",
        ])
        versions, v2 = rows
        self.assertEqual(versions["query_discriminator"], {"key": "versions", "rule": "present"})
        self.assertEqual(v2["query_discriminator"], {"key": "list-type", "rule": "equals:2"})
        for row in rows:
            self.assertEqual(row["method"], "GET")
            self.assertEqual(row["target"], "bucket")
            self.assertEqual(row["query_requires"], [{"key": "metadata", "rule": "equals:true"}])
            self.assertEqual(row["claimed_by"], "rustfs/src/app/metadata_route.rs")
            self.assertEqual((row["auth_mode"], row["auth_detail"]), ("custom", "SignedOrAnonymousThenBucketListing"))
            self.assertEqual(row["iam_action_enum"], "S3Action")
        self.assertEqual(versions["iam_action"], "ListBucketVersionsAction")
        self.assertEqual(v2["iam_action"], "ListBucketAction")

    def refused(self, text, fragment):
        with self.assertRaises(inventory.InventoryError) as raised:
            read(text)
        self.assertIn(fragment, str(raised.exception))

    def test_n_a_missing_selector_is_refused(self):
        self.refused(FIXTURE.replace("fn metadata_operation(", "fn other_operation("), "metadata_operation not found")

    def test_n_a_selector_that_is_not_get_only_is_refused(self):
        self.refused(FIXTURE.replace("if method != Method::GET {", "if method == Method::PUT {"), "GET-only")

    def test_n_a_selector_that_names_no_bucket_is_refused(self):
        self.refused(FIXTURE.replace("bucket_from_request(uri, headers, host)", "object_from_request(uri)"), "bucket")

    def test_n_a_changed_gate_value_is_refused(self):
        self.refused(FIXTURE.replace('Some("true")', 'Some("1")'), "metadata=true gate")

    def test_n_a_case_insensitive_gate_is_refused(self):
        changed = FIXTURE.replace(
            'query_value(query, "metadata").as_deref() != Some("true")',
            '!query_value(query, "metadata").is_some_and(|v| v.eq_ignore_ascii_case("true"))',
        )
        self.refused(changed, "metadata=true gate")

    def test_n_an_unreadable_arm_is_refused(self):
        changed = FIXTURE.replace('query_has(query, "versions")', 'query_starts(query, "versions")')
        self.refused(changed, "unreadable")

    def test_n_a_third_operation_is_refused(self):
        changed = FIXTURE.replace(
            "    } else {\n        return None;",
            '    } else if query_has(query, "uploads") {\n        MetadataOperation::ListMultipartUploads\n'
            "    } else {\n        return None;",
        )
        self.refused(changed, "ListMultipartUploads")

    def test_n_an_operation_without_an_action_is_refused(self):
        changed = FIXTURE.replace("        MetadataOperation::ListObjectsV2 => S3Action::ListBucketAction,\n", "")
        self.refused(changed, "no authorisation action")

    def test_n_an_action_outside_s3_action_is_refused(self):
        changed = FIXTURE.replace("S3Action::ListBucketAction", "AdminAction::ListBucketAction")
        self.refused(changed, "no authorisation action")


class NativeMetadataTests(unittest.TestCase):
    def test_published_tables_trace_executed_steps_to_their_typed_overlay(self):
        path = Path(__file__).resolve().parents[1] / metadata.DIALECT_DIR / "src/native/extensions.rs"
        source = inventory.strip_comments(path.read_text(encoding="utf-8"))

        def read(text, table):
            return metadata.published_table(text, table, inventory.matching_close, inventory.split_args, inventory.fail)

        s3 = read(source, "s3")
        control = read(source, "control_plane")
        self.assertEqual([kind for _, kind, _ in s3], ["ListObjectVersionsWithMetadata", "ListObjectsV2WithMetadata"])
        self.assertEqual(len(control), 8)
        self.assertTrue({kind for _, kind, _ in s3}.isdisjoint(kind for _, kind, _ in control))
        a, b = (row[0] for row in s3)
        rows = f"&[{a}::ROW, {b}::ROW]"
        for before, after in [
            (rows, f"&[{b}::ROW, {a}::ROW]"),
            (rows, f"&[{a}::ROW]"),
            (rows, f"&[{a}::ROW, {b}::ROW, {a}::ROW]"),
            (f"{a}::ROUTE,", f"{b}::ROUTE,"),
            (f"..ops::{a}::OVERLAY_ROW", f"..ops::{b}::OVERLAY_ROW"),
            (f"..ops::{a}::ROUTE", f"..ops::{b}::ROUTE"),
            ("precedence: ROW.precedence", "precedence: 0"),
            ("fold(&mut super::Declare, builder)", "super::control_plane::declare(builder)"),
            ("builder.declare::<O>(route)", "builder"),
            ('shadows("rustfs:ListObjectsV2WithMetadata",', 'shadows("rustfs:CheckReplication",'),
            ("winner: ROW.name,", "winner: shadowed,"),
            ("pub mod s3 {", "#[cfg(test)] pub mod s3 {"),
            ("use crate::ops;", "use crate::native::ops;"),
            (f"mod {a} {{", f"#[path = \"other.rs\"] mod {a} {{"),
        ]:
            with self.subTest(change=(before, after)):
                self.assertIn(before, source)
                with self.assertRaises(inventory.InventoryError):
                    read(source.replace(before, after, 1), "s3")

    def test_published_modules_must_be_direct_unconditional_declarations(self):
        pattern = r"\bpub mod extensions;"
        for text in ('mod other { pub mod extensions; }', '#[path = "elsewhere.rs"] pub mod extensions;',
                     'pub mod extensions; pub mod extensions;'):
            with self.subTest(text=text), self.assertRaises(inventory.InventoryError):
                metadata.direct_item(text, pattern, "native extensions", inventory.matching_close, inventory.fail)

    def test_control_declarations_require_the_same_live_registrations_and_overlay(self):
        dialect = ("for name in BORROWED { rows.push(OVERLAY.row(name).copied().ok_or(GatewayAssemblyError::AdminOverlayMissing)?); } "
                   "let record = RECORD.get_or_init(|| DialectOverlay { name: \"rustfs-control-plane\", vendor: OVERLAY.vendor, "
                   "claims: CLAIMS, operations: ROWS.get_or_init(|| rows), }); "
                   "Dialect::assemble(record) .declare_claimed::<ControlPlane>(ROUTE) "
                   ".declare_claimed::<PostV3SpeedtestClientDevnull>(ClaimedRoute { rows: rows(), }) "
                   ".declare_form::<StsForm>(STS_ROUTE) .declare::<Example>(Example::ROUTE) .build() "
                   ".map_err(GatewayAssemblyError::AdminDialect)")
        assembly = ("let service = builder .hand_caller_secret_to_every_operation_after_listing_in_the_posture_report() "
                    ".dialect(&dialect()?) .register::<ControlPlane, _>(Arc::clone(&host)) "
                    ".register::<PostV3SpeedtestClientDevnull, _>(Arc::clone(&host)) "
                    ".register::<StsForm, _>(Arc::clone(&host)) .register::<Example, _>(host) "
                    ".build() .map_err(GatewayAssemblyError::Service)?; "
                    "Ok(GatewayStack { service, keystone_auth: assembly.keystone_auth, control_plane: true, })")
        source = ("use rustfs_gateway_dialect_rustfs_admin::ops::{"
                  "post_v3_speedtest_client_devnull::PostV3SpeedtestClientDevnull, example::Example}; "
                  "const BORROWED: [&str; 2] = [PostV3SpeedtestClientDevnull::NAME, Example::NAME];")
        def bindings(src, dec, reg):
            return metadata.control_bindings(src, dec, reg, inventory.split_args, inventory.fail)
        self.assertEqual(bindings(source, dialect, assembly), [("example", "Example")])
        for src, dec, reg in [
            (source, dialect, assembly.replace(".register::<Example, _>(host)", "")),
            (source, dialect.replace("Example::ROUTE", "Other::ROUTE"), assembly),
            (source.replace("Example::NAME", "Other::NAME"), dialect, assembly),
            (source, dialect, assembly.replace("control_plane: true", "control_plane: false")),
            (source, dialect.replace(".declare::<Example>", ".declare::<Other>"), assembly),
            (source, dialect, assembly.replace(".dialect(&dialect()?)", ".dialect(&other()?)")),
            (source, dialect.replace("operations: ROWS.get_or_init(|| rows)", "operations: OTHER"), assembly),
        ]:
            with self.subTest(src=src, dec=dec, reg=reg), self.assertRaises(inventory.InventoryError):
                bindings(src, dec, reg)

    def test_only_the_locked_dialect_commit_is_accepted(self):
        revision = "1" * 40
        lock = ('[[package]]\nname = "rustfs-gateway-dialect-rustfs-admin"\n'
                f'source = "git+https://github.com/rustfs/gateway.git?rev={revision}#{revision}"\n')
        self.assertEqual(metadata.locked_revision(lock, inventory.fail), revision)
        for other in ("", lock + lock, lock.replace("#" + revision, "#" + "2" * 40),
                      lock.replace("github.com/rustfs/", "github.com/other/")):
            with self.subTest(lock=other), self.assertRaises(inventory.InventoryError):
                metadata.locked_revision(other, inventory.fail)

    def test_runtime_predicates_and_host_authority_must_agree(self):
        source = r'''
            pub const NAME: &str = "rustfs:Example";
            pub const AUTH: AuthRequirement = AuthRequirement::new("s3:Read", ResourceShape::Bucket);
            static SPEC: OperationSpec = admin::spec(NAME, AUTH, false);
            static FLOOR: OperationFloor = admin::listing_floor(NAME);
            impl Operation for Example {
                const NAME: &'static str = NAME;
                fn spec() -> &'static OperationSpec { &SPEC }
                fn floor() -> &'static OperationFloor { &FLOOR }
            }
            pub static SELECTOR: &[Predicate] = &[Predicate::Method(http::Method::GET),
                Predicate::Target(TargetKind::Bucket), Predicate::QueryPresent("flag"),
                Predicate::QueryEquals("metadata", "true")];
            pub const ROUTE: DialectRoute = DialectRoute {
                precedence: 70, selector: SELECTOR, path_shape: "/{Bucket}", shadows: SHADOWS,
            };
            impl ExtensionOperation for Example { const ROUTE: DialectRoute = ROUTE; }
            pub const OVERLAY_ROW: OverlayRow = OverlayRow {
                name: NAME, precedence: 70, selector: "Method(GET) ∧ Target(Bucket) ∧ QueryPresent(\"flag\") ∧ QueryEquals(\"metadata\", \"true\")", action: "s3:Read",
                resource: ResourceShape::Bucket, success_status: 200, anonymous: false, evidence: &[],
            };
        '''
        def read(text):
            row = metadata.typed_route(text, "Example", inventory.fail, inventory.split_args)
            metadata.verify_listing(row, "s3:Read", inventory.fail)
            return row
        row = read(source)
        self.assertEqual((row["precedence"], row["query_discriminator"], row["query_requires"]),
                         (70, {"key": "flag", "rule": "present"}, [{"key": "metadata", "rule": "equals:true"}]))
        for old, new in (('Method::GET', 'Method::POST'), ('TargetKind::Bucket', 'TargetKind::Object'),
                         ('"s3:Read"', '"s3:Write"'), ('"metadata", "true"', '"metadata", "false"'),
                         ('selector: SELECTOR', 'selector: OTHER'), ('Method(GET) ∧', 'Method(HEAD) ∧'), (' = ROUTE;', ' = OTHER;'),
                         ('admin::listing_floor', 'admin::floor'), ('{ &SPEC }', '{ &OTHER }')):
            with self.subTest(change=new), self.assertRaises(inventory.InventoryError):
                read(source.replace(old, new))

    @staticmethod
    def _host_fixture_files(pin, with_native_routes=False, with_get_native_routes=False, with_lambda_fallback=False):
        if with_get_native_routes:
            with_native_routes = True
        http_host = """
            fn assemble_s3_stack() -> Result<S3StackService, Error> {
                let control_plane = GatewayEdgeService(GatewayStack::assemble_control_plane(assembly.clone(), Arc::new(router)).map_err(Error::other)?);
                let s3 = GatewayEdgeService(GatewayStack::assemble(assembly).map_err(Error::other)?);
                Ok(S3StackService::new(s3)
                    .with_control_plane(Some(control_plane)))
            }
        """
        stack_dispatch = """
            fn call(&mut self, request: Request<B>) -> Self::Future {
                let claimed = claims_route(request.method(), request.uri(), request.headers());
                if !claimed {
                    let mut request = request;
                    if let Some(path) = OriginalS3Path::from_uri(request.uri()) {
                        request.extensions_mut().insert(path);
                    }
                    return Box::pin(self.s3.call(request));
                }
                match &mut self.control_plane {
                    Some(control_plane) => Box::pin(control_plane.call(request)),
                    None => bare(http::StatusCode::NOT_IMPLEMENTED),
                }
            }
        """
        admin_router = """
            fn claims_route(method: &Method, uri: &Uri, headers: &HeaderMap) -> bool {
                s3_extension::route_key(method, uri).is_some()
                    || parse_object_lambda_request(method, uri).is_some()
                    || is_control_plane_route(method, uri, headers)
            }
            pub(crate) fn validate_notification_target_params(&self, method: &Method, uri: &Uri) -> S3Result<()> {
                let key = route_key_canonical(method, uri.path());
                let matched = self.table.at(&key).map_err(|_| S3Error::new(S3ErrorCode::NotImplemented))?;
                super::handlers::event::extract_target_params(&matched.params)?;
                Ok(())
            }
        """
        lambda_field = "\n                object_lambda_fallback: Option<rustfs_gateway::S3Service>," if with_lambda_fallback else ""
        assemble_with_lambda = "\n                        object_lambda_fallback: None," if with_lambda_fallback else ""
        stack_call = (
            """
                pub(crate) fn call<B>(&self, mut request: Request<B>) -> impl Future<Output = Response<rustfs_gateway::Body>> + Send + 'static
                where
                    B: http_body::Body + Send + 'static,
                {
                    if self.control_plane {
                        control_plane::attach_head(&mut request);
                    }
                    let service = match self.object_lambda_fallback.as_ref() {
                        Some(fallback) if crate::admin::router::object_lambda_target(request.method(), request.uri()).is_some() => {
                            fallback.clone()
                        }
                        _ => self.service.clone(),
                    };
                    async move {
                        let response = service.call(request).await;
                        response
                    }
                }
            """
            if with_lambda_fallback
            else ""
        )
        native_stack = f"""
            #[derive(Clone)]
            pub(crate) struct GatewayStack {{
                service: S3Service,
                keystone_auth: Option<Arc<KeystoneAuth>>,
                control_plane: bool,{lambda_field}
            }}
            impl GatewayStack {{
                fn assemble(assembly: GatewayAssembly) -> Result<Self, GatewayAssemblyError> {{
                    Self::assemble_with(assembly, iam, root, early_gate(OPERATIONS, server_ctx))
                }}
                fn assemble_control_plane(assembly: GatewayAssembly, router: Arc<S3Router<AdminOperation>>) -> Result<Self, GatewayAssemblyError> {{
                    control_plane::assemble(assembly, iam, root, router)
                }}
                fn assemble_with() -> Result<Self, GatewayAssemblyError> {{
                    let listings = metadata_listing::dialect().map_err(GatewayAssemblyError::MetadataListingDialect)?;
                    let builder = Self::configured_builder(&assembly, iam, root, authorizer, std::convert::identity)?
                        .answer_nul_torrent_keys_as_missing()
                        .dialect(&listings);
                    let backend = Arc::new(GatewayBackend::new(Arc::clone(&assembly.server_ctx)));
                    let builder = metadata_listing::register(register(OPERATIONS, builder, &backend), &assembly.server_ctx);
                    let service = builder.build().map_err(GatewayAssemblyError::Service)?;
                    Ok(Self {{
                        service,
                        keystone_auth: assembly.keystone_auth,
                        control_plane: false,{assemble_with_lambda}
                    }})
                }}{stack_call}
            }}
        """
        native_handler = """
            use rustfs_gateway_dialect_rustfs_admin::native::extensions::s3;
            use rustfs_gateway_dialect_rustfs_admin::ops::list_object_versions_with_metadata::{
                self as versions, ListObjectVersionsWithMetadata,
            };
            use rustfs_gateway_dialect_rustfs_admin::ops::list_objects_v2_with_metadata::{
                self as objects_v2, ListObjectsV2WithMetadata,
            };
            const NAMES: [&str; 2] = [versions::NAME, objects_v2::NAME];
            static RECORD: DialectOverlay = DialectOverlay {
                name: "rustfs-metadata-listings",
                vendor: "rustfs",
                operations: s3::ROWS,
                claims: &[],
            };
            fn dialect() -> Result<Dialect, DialectBuildError> {
                s3::declare(Dialect::assemble(&RECORD)).build()
            }
            fn register(builder: ServiceBuilder, server_ctx: &Arc<ServerContextSlot>) -> ServiceBuilder {
                let listings = Arc::new(Listings {
                    server_ctx: Arc::clone(server_ctx),
                });
                builder
                    .register::<ListObjectVersionsWithMetadata, _>(Arc::clone(&listings))
                    .register::<ListObjectsV2WithMetadata, _>(listings)
            }
            impl Listing for ListObjectVersionsWithMetadata {
                const LISTING: MetadataListing = MetadataListing::Versions;
            }
            impl Listing for ListObjectsV2WithMetadata {
                const LISTING: MetadataListing = MetadataListing::ObjectsV2;
            }
            impl<O: Listing> Handler<O> for Listings {
                async fn call(&self, request: Req<O>) -> HandlerResult<O> {
                    self.serve(request).await.map_err(handler_error)
                }
            }
            async fn serve(&self, request: Req<O>) -> S3Result<Resp<AdminResponse>> {
                let mut envelope = access::admit(&self.server_ctx, request.context()).await?;
                let bucket = request
                    .context()
                    .bucket()
                    .ok_or_else(|| s3_error!(InternalError, "missing bucket"))?
                    .as_str()
                    .to_owned();
                metadata_listing::authorize(&mut envelope, O::LISTING, &bucket).await?;
                let body = metadata_listing::answer(&envelope, O::LISTING, bucket).await?;
                Ok(Resp::new(AdminResponse::bytes("application/xml", body)))
            }
        """
        native_access = """
            impl MetadataListing {
                fn action(self) -> S3Action {
                    match self {
                        Self::Versions => S3Action::ListBucketVersionsAction,
                        Self::ObjectsV2 => S3Action::ListBucketAction,
                    }
                }
            }
            async fn authorize(req: &mut RequestEnvelope, listing: MetadataListing, bucket: &str) -> S3Result<()> {
                authorize_bucket_listing(req, bucket, listing.action()).await
            }
        """
        mod_header = "mod native_authority;\nmod native_routes;\n" if with_native_routes else ""
        append_rows = "\n    native_routes::append_rows(&mut rows);" if with_native_routes else ""
        declare_tail = (
            "let builder = control_plane::declare(builder);\n    native_routes::declare(builder)\n        .build()\n        .map_err(GatewayAssemblyError::AdminDialect)"
            if with_native_routes
            else "control_plane::declare(builder)\n        .build()\n        .map_err(GatewayAssemblyError::AdminDialect)"
        )
        register_native = "\n    let builder = native_routes::register(builder, &host);" if with_native_routes else ""
        served_body = (
            "[NAME, STS_NAME].contains(&operation) || BORROWED.contains(&operation) || native_routes::contains(operation)"
            if with_native_routes
            else "[NAME, STS_NAME].contains(&operation) || BORROWED.contains(&operation)"
        )
        if with_native_routes:
            admission_impl = """
                impl Admission {
                    async fn route(&self, context: &AuthzContext<'_>, request: &AuthzRequest<'_>) -> Result<Decision, HandlerError> {
                        if !served(request.operation) {
                            return Ok(routed(request));
                        }
                        let head = context
                            .server_extensions()
                            .get::<ClaimedHead>()
                            .ok_or_else(|| handler_error(s3_error!(InternalError, "the claimed request head was not attached")))?;
                        let signed = request.identity.is_some() && !head.repeated_authorization;
                        self.router
                            .admit(&head.method, &head.uri, &head.headers, signed)
                            .map_err(handler_error)?;
                        if head.repeated_authorization {
                            return Ok(Decision::Deny);
                        }
                        if native_routes::contains(request.operation) {
                            if request.operation
                                == rustfs_gateway_dialect_rustfs_admin::native::ops::delete_v3_target_by_target_type_by_target_name::NAME
                            {
                                self.router
                                    .validate_notification_target_params(&head.method, &head.uri)
                                    .map_err(handler_error)?;
                            }
                            if let Err(error) = native_authority::authorize(context, request, head).await {
                                if error.code() == &rustfs_s3_types::S3ErrorCode::AccessDenied {
                                    return Ok(Decision::Deny);
                                }
                                return Err(handler_error(error));
                            }
                        }
                        Ok(Decision::Allow)
                    }
                }
                impl Authorizer for Admission {
                    fn authorize_route<'a>(&'a self, context: &'a AuthzContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
                        Box::pin(async move { self.route(context, request).await.unwrap_or(Decision::Deny) })
                    }
                    fn authorize_route_result<'a>(&'a self, context: &'a AuthzContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Result<Decision, HandlerError>> {
                        Box::pin(self.route(context, request))
                    }
                    fn authorize_input<'a>(&'a self, _context: &'a AuthzContext<'a>, request: &'a InputAuthzRequest<'a>) -> BoxFuture<'a, InputDecisions> {
                        let stage = routed(request.route());
                        let decisions = request.decide_all(stage, |_| stage);
                        Box::pin(async move { decisions })
                    }
                }
            """
        else:
            admission_impl = """
                impl Admission {
                    fn route(&self, context: &AuthzContext<'_>, request: &AuthzRequest<'_>) -> Result<Decision, HandlerError> {
                        if !served(request.operation) {
                            return Ok(routed(request));
                        }
                        let head = context
                            .server_extensions()
                            .get::<ClaimedHead>()
                            .ok_or_else(|| handler_error(s3_error!(InternalError, "the claimed request head was not attached")))?;
                        let signed = request.identity.is_some() && !head.repeated_authorization;
                        self.router
                            .admit(&head.method, &head.uri, &head.headers, signed)
                            .map_err(handler_error)?;
                        Ok(if head.repeated_authorization { Decision::Deny } else { Decision::Allow })
                    }
                }
                impl Authorizer for Admission {
                    fn authorize_route<'a>(&'a self, context: &'a AuthzContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
                        let decision = self.route(context, request).unwrap_or(Decision::Deny);
                        Box::pin(async move { decision })
                    }
                    fn authorize_route_result<'a>(&'a self, context: &'a AuthzContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Result<Decision, HandlerError>> {
                        let decision = self.route(context, request);
                        Box::pin(async move { decision })
                    }
                    fn authorize_input<'a>(&'a self, _context: &'a AuthzContext<'a>, request: &'a InputAuthzRequest<'a>) -> BoxFuture<'a, InputDecisions> {
                        let stage = routed(request.route());
                        let decisions = request.decide_all(stage, |_| stage);
                        Box::pin(async move { decisions })
                    }
                }
            """
        lambda_helpers = (
            """
            fn object_lambda_dialect() -> Result<Dialect, GatewayAssemblyError> {
                static ROWS: OnceLock<Vec<OverlayRow>> = OnceLock::new();
                static SELECTOR: OnceLock<String> = OnceLock::new();
                static ACTION: OnceLock<String> = OnceLock::new();
                static STS_SELECTOR: OnceLock<String> = OnceLock::new();
                static STS_ACTION: OnceLock<String> = OnceLock::new();
                static RECORD: OnceLock<DialectOverlay> = OnceLock::new();
                let mut rows = vec![OverlayRow {
                    name: NAME,
                    precedence: ROUTE.precedence,
                    selector: SELECTOR.get_or_init(|| render_claimed_route(&ROUTE)),
                    action: ACTION.get_or_init(|| SPEC.auth.map(|auth| auth.render()).unwrap_or_default()),
                    resource: ResourceShape::Service,
                    success_status: 200,
                    anonymous: true,
                    evidence: &[ROUTER],
                }];
                rows.push(OverlayRow {
                    name: STS_NAME,
                    precedence: STS_ROUTE.precedence,
                    selector: STS_SELECTOR.get_or_init(|| STS_CLAIM.render()),
                    action: STS_ACTION.get_or_init(|| STS_SPEC.auth.map(|auth| auth.render()).unwrap_or_default()),
                    resource: ResourceShape::Service,
                    success_status: 200,
                    anonymous: true,
                    evidence: &[ROUTER],
                });
                rows.push(
                    OVERLAY
                        .row(PostV3SpeedtestClientDevnull::NAME)
                        .copied()
                        .ok_or(GatewayAssemblyError::AdminOverlayMissing)?,
                );
                rows.extend_from_slice(control_plane::ROWS);
                let record = RECORD.get_or_init(|| DialectOverlay {
                    name: "rustfs-control-plane-object-lambda",
                    vendor: OVERLAY.vendor,
                    claims: CLAIMS,
                    operations: ROWS.get_or_init(|| rows),
                });
                let builder = Dialect::assemble(record)
                    .declare_claimed::<ControlPlane>(ROUTE)
                    .declare_claimed::<PostV3SpeedtestClientDevnull>(ClaimedRoute {
                        precedence: PostV3SpeedtestClientDevnull::PRECEDENCE,
                        rows: PostV3SpeedtestClientDevnull::rows(),
                        shadows: SPEEDTEST_SHADOWS,
                        bucket_param: PostV3SpeedtestClientDevnull::BUCKET,
                    })
                    .declare_form::<StsForm>(STS_ROUTE);
                control_plane::declare(builder)
                    .build()
                    .map_err(GatewayAssemblyError::AdminDialect)
            }
            fn assemble_object_lambda_fallback(
                assembly: &GatewayAssembly,
                iam: Arc<dyn IamKeyLookup>,
                root: Arc<dyn RootSource>,
                router: Arc<S3Router<AdminOperation>>,
                host: Arc<Host>,
            ) -> Result<rustfs_gateway::S3Service, GatewayAssemblyError> {
                let gate = Admission { router };
                let authenticator = |authenticator: SigV4Authenticator| {
                    authenticator
                        .hand_caller_secret_to_handlers()
                        .verify_paths_double_encoded_under(TABLE_CATALOG_PREFIXES)
                };
                let (builder, _settings) = GatewayStack::configured_builder(assembly, iam, root, gate, authenticator)?
                    .config(super::service_config(assembly.body_read_timeout, CLAIMED_ROUTE_BODY_BYTES));
                builder
                    .hand_caller_secret_to_every_operation_after_listing_in_the_posture_report()
                    .dialect(&object_lambda_dialect()?)
                    .register::<ControlPlane, _>(Arc::clone(&host))
                    .register::<PostV3SpeedtestClientDevnull, _>(Arc::clone(&host))
                    .register::<StsForm, _>(Arc::clone(&host))
                    .register::<ResetBucketReplication, _>(Arc::clone(&host))
                    .register::<GetReplicationResetStatus, _>(Arc::clone(&host))
                    .register::<GetReplicationMetricsV2, _>(Arc::clone(&host))
                    .register::<GetReplicationMetrics, _>(Arc::clone(&host))
                    .register::<CheckReplication, _>(Arc::clone(&host))
                    .register::<InvokeObjectLambda, _>(Arc::clone(&host))
                    .register::<ListenNotification, _>(Arc::clone(&host))
                    .register::<ListenBucketNotification, _>(host)
                    .build()
                    .map_err(GatewayAssemblyError::Service)
            }
            """
            if with_lambda_fallback
            else ""
        )
        host_router_field = "router: Arc::clone(&router)" if with_lambda_fallback else "router"
        iam_arg = "Arc::clone(&iam)" if with_lambda_fallback else "iam"
        root_arg = "Arc::clone(&root)" if with_lambda_fallback else "root"
        last_host_arg = "Arc::clone(&host)" if with_lambda_fallback else "host"
        lambda_construct = (
            "\n                let object_lambda_fallback = assemble_object_lambda_fallback("
            "&assembly, Arc::clone(&iam), Arc::clone(&root), Arc::clone(&router), Arc::clone(&host))?;"
            if with_lambda_fallback
            else ""
        )
        control_return_lambda = "\n                    object_lambda_fallback: Some(object_lambda_fallback)," if with_lambda_fallback else ""
        control_host = f"""
            {mod_header}
            use rustfs_gateway_dialect_rustfs_admin::native::extensions::control_plane;
            use rustfs_gateway_dialect_rustfs_admin::ops::{{
                check_replication::CheckReplication, get_replication_metrics::GetReplicationMetrics,
                get_replication_metrics_v2::GetReplicationMetricsV2, get_replication_reset_status::GetReplicationResetStatus,
                invoke_object_lambda::InvokeObjectLambda, listen_bucket_notification::ListenBucketNotification,
                listen_notification::ListenNotification, post_v3_speedtest_client_devnull::PostV3SpeedtestClientDevnull,
                reset_bucket_replication::ResetBucketReplication,
            }};
            const BORROWED: [&str; 9] = [
                PostV3SpeedtestClientDevnull::NAME,
                ResetBucketReplication::NAME,
                GetReplicationResetStatus::NAME,
                GetReplicationMetricsV2::NAME,
                GetReplicationMetrics::NAME,
                CheckReplication::NAME,
                InvokeObjectLambda::NAME,
                ListenNotification::NAME,
                ListenBucketNotification::NAME,
            ];
            fn dialect() -> Result<Dialect, GatewayAssemblyError> {{
                static ROWS: OnceLock<Vec<OverlayRow>> = OnceLock::new();
                static SELECTOR: OnceLock<String> = OnceLock::new();
                static ACTION: OnceLock<String> = OnceLock::new();
                static STS_SELECTOR: OnceLock<String> = OnceLock::new();
                static STS_ACTION: OnceLock<String> = OnceLock::new();
                static RECORD: OnceLock<DialectOverlay> = OnceLock::new();
                let mut rows = vec![OverlayRow {{
                    name: NAME,
                    precedence: ROUTE.precedence,
                    selector: SELECTOR.get_or_init(|| render_claimed_route(&ROUTE)),
                    action: ACTION.get_or_init(|| SPEC.auth.map(|auth| auth.render()).unwrap_or_default()),
                    resource: ResourceShape::Service,
                    success_status: 200,
                    anonymous: true,
                    evidence: &[ROUTER],
                }}];
                rows.push(OverlayRow {{
                    name: STS_NAME,
                    precedence: STS_ROUTE.precedence,
                    selector: STS_SELECTOR.get_or_init(|| STS_CLAIM.render()),
                    action: STS_ACTION.get_or_init(|| STS_SPEC.auth.map(|auth| auth.render()).unwrap_or_default()),
                    resource: ResourceShape::Service,
                    success_status: 200,
                    anonymous: true,
                    evidence: &[ROUTER],
                }});
                rows.push(
                    OVERLAY
                        .row(PostV3SpeedtestClientDevnull::NAME)
                        .copied()
                        .ok_or(GatewayAssemblyError::AdminOverlayMissing)?,
                );
                rows.extend_from_slice(control_plane::ROWS);{append_rows}
                let record = RECORD.get_or_init(|| DialectOverlay {{
                    name: "rustfs-control-plane",
                    vendor: OVERLAY.vendor,
                    claims: CLAIMS,
                    operations: ROWS.get_or_init(|| rows),
                }});
                let builder = Dialect::assemble(record)
                    .declare_claimed::<ControlPlane>(ROUTE)
                    .declare_claimed::<PostV3SpeedtestClientDevnull>(ClaimedRoute {{
                        precedence: PostV3SpeedtestClientDevnull::PRECEDENCE,
                        rows: PostV3SpeedtestClientDevnull::rows(),
                        shadows: SPEEDTEST_SHADOWS,
                        bucket_param: PostV3SpeedtestClientDevnull::BUCKET,
                    }})
                    .declare_form::<StsForm>(STS_ROUTE);
                {declare_tail}
            }}{lambda_helpers}
            pub(super) fn assemble(
                assembly: GatewayAssembly,
                iam: Arc<dyn IamKeyLookup>,
                root: Arc<dyn RootSource>,
                router: Arc<S3Router<AdminOperation>>,
            ) -> Result<GatewayStack, GatewayAssemblyError> {{
                let gate = Admission {{
                    router: Arc::clone(&router),
                }};
                let authenticator = |authenticator: SigV4Authenticator| {{
                    authenticator
                        .hand_caller_secret_to_handlers()
                        .verify_paths_double_encoded_under(TABLE_CATALOG_PREFIXES)
                }};
                let host = Arc::new(Host {{
                    {host_router_field},
                    server_ctx: Arc::clone(&assembly.server_ctx),
                }});
                let (builder, _settings) = GatewayStack::configured_builder(&assembly, {iam_arg}, {root_arg}, gate, authenticator)?
                    .config(super::service_config(assembly.body_read_timeout, CLAIMED_ROUTE_BODY_BYTES));{register_native}
                let service = builder
                    .hand_caller_secret_to_every_operation_after_listing_in_the_posture_report()
                    .dialect(&dialect()?)
                    .register::<ControlPlane, _>(Arc::clone(&host))
                    .register::<PostV3SpeedtestClientDevnull, _>(Arc::clone(&host))
                    .register::<StsForm, _>(Arc::clone(&host))
                    .register::<ResetBucketReplication, _>(Arc::clone(&host))
                    .register::<GetReplicationResetStatus, _>(Arc::clone(&host))
                    .register::<GetReplicationMetricsV2, _>(Arc::clone(&host))
                    .register::<GetReplicationMetrics, _>(Arc::clone(&host))
                    .register::<CheckReplication, _>(Arc::clone(&host))
                    .register::<InvokeObjectLambda, _>(Arc::clone(&host))
                    .register::<ListenNotification, _>(Arc::clone(&host))
                    .register::<ListenBucketNotification, _>({last_host_arg})
                    .build()
                    .map_err(GatewayAssemblyError::Service)?;{lambda_construct}
                Ok(GatewayStack {{
                    service,
                    keystone_auth: assembly.keystone_auth,
                    control_plane: true,{control_return_lambda}
                }})
            }}
            fn served(operation: &str) -> bool {{
                {served_body}
            }}
            fn routed(request: &AuthzRequest<'_>) -> Decision {{
                if served(request.operation) || request.identity.is_some() {{ Decision::Allow }} else {{ Decision::Deny }}
            }}
            {admission_impl}
        """
        files = {
            "Cargo.lock": (
                '[[package]]\nname = "rustfs-gateway-dialect-rustfs-admin"\n'
                f'source = "git+https://github.com/rustfs/gateway.git?rev={pin}#{pin}"\n'
            ),
            metadata.HTTP_HOST: http_host,
            metadata.STACK_DISPATCH: stack_dispatch,
            metadata.ADMIN_ROUTER: admin_router,
            metadata.NATIVE_STACK: native_stack,
            metadata.NATIVE_HANDLER: native_handler,
            metadata.NATIVE_ACCESS: native_access,
            metadata.CONTROL_HOST: control_host,
        }
        if with_native_routes:
            if with_get_native_routes:
                native_route_entries = """
                    delete_v3_bucket_etag_by_bucket::DeleteV3BucketEtagByBucket,
                    delete_v3_target_by_target_type_by_target_name::DeleteV3TargetByTargetTypeByTargetName,
                    get_v3_bucket_etag_by_bucket::GetV3BucketEtagByBucket,
                    get_v3_site_replication_remove_v2_capabilities::GetV3SiteReplicationRemoveV2Capabilities,
                    get_v4_heal_mrf_cluster::GetV4HealMrfCluster,
                    get_v4_heal_mrf_cluster_responsibilities::GetV4HealMrfClusterResponsibilities,
                    get_v4_heal_mrf_cluster_responsibilities_by_node_id_by_id::GetV4HealMrfClusterResponsibilitiesByNodeIdById,
                    post_v4_account_permissions::PostV4AccountPermissions,
                    post_v4_heal_mrf_cluster_responsibilities_actions::PostV4HealMrfClusterResponsibilitiesActions,
                    put_v3_bucket_etag_by_bucket::PutV3BucketEtagByBucket,
                    put_v3_site_replication_peer_remove_v2::PutV3SiteReplicationPeerRemoveV2,
                    put_v3_site_replication_remove_v2::PutV3SiteReplicationRemoveV2,
                """
                permission_arms = """
                        ops::delete_v3_bucket_etag_by_bucket::NAME
                        | ops::get_v3_bucket_etag_by_bucket::NAME
                        | ops::put_v3_bucket_etag_by_bucket::NAME => (AdminAction::ConfigUpdateAdminAction, ResourceShape::Bucket),
                        ops::get_v3_site_replication_remove_v2_capabilities::NAME
                        | ops::put_v3_site_replication_peer_remove_v2::NAME
                        | ops::put_v3_site_replication_remove_v2::NAME => (AdminAction::SiteReplicationRemoveAction, ResourceShape::Service),
                        ops::delete_v3_target_by_target_type_by_target_name::NAME => (AdminAction::SetBucketTargetAction, ResourceShape::Service),
                        ops::get_v4_heal_mrf_cluster::NAME
                        | ops::get_v4_heal_mrf_cluster_responsibilities::NAME
                        | ops::get_v4_heal_mrf_cluster_responsibilities_by_node_id_by_id::NAME
                        | ops::post_v4_heal_mrf_cluster_responsibilities_actions::NAME => (AdminAction::HealAdminAction, ResourceShape::Service),
                """
            else:
                native_route_entries = """
                    delete_v3_bucket_etag_by_bucket::DeleteV3BucketEtagByBucket,
                    delete_v3_target_by_target_type_by_target_name::DeleteV3TargetByTargetTypeByTargetName,
                    post_v4_account_permissions::PostV4AccountPermissions,
                    post_v4_heal_mrf_cluster_responsibilities_actions::PostV4HealMrfClusterResponsibilitiesActions,
                    put_v3_bucket_etag_by_bucket::PutV3BucketEtagByBucket,
                    put_v3_site_replication_peer_remove_v2::PutV3SiteReplicationPeerRemoveV2,
                    put_v3_site_replication_remove_v2::PutV3SiteReplicationRemoveV2,
                """
                permission_arms = """
                        ops::delete_v3_bucket_etag_by_bucket::NAME
                        | ops::put_v3_bucket_etag_by_bucket::NAME => (AdminAction::ConfigUpdateAdminAction, ResourceShape::Bucket),
                        ops::put_v3_site_replication_peer_remove_v2::NAME
                        | ops::put_v3_site_replication_remove_v2::NAME => (AdminAction::SiteReplicationRemoveAction, ResourceShape::Service),
                        ops::delete_v3_target_by_target_type_by_target_name::NAME => (AdminAction::SetBucketTargetAction, ResourceShape::Service),
                        ops::post_v4_heal_mrf_cluster_responsibilities_actions::NAME => (AdminAction::HealAdminAction, ResourceShape::Service),
                """
            files[metadata.NATIVE_ROUTES] = f"""
                use super::{{Host, NAME, ROUTER}};
                use rustfs_gateway::ServiceBuilder;
                use rustfs_gateway_core::dialect::{{ClaimedRoute, DialectBuilder, OverlayRow}};
                use rustfs_gateway_core::route::ShadowingDecl;
                use rustfs_gateway_dialect_rustfs_admin::{{AdminOperation, native::ops}};
                use std::sync::Arc;

                const fn shadows_control_plane(winner: &'static str) -> ShadowingDecl {{
                    ShadowingDecl {{
                        winner,
                        shadowed: NAME,
                        reason: "The registered admin handler precedes the control-plane catch-all.",
                        evidence: &[ROUTER],
                    }}
                }}

                macro_rules! native_routes {{
                    ($($module:ident::$operation:ident),+ $(,)?) => {{
                        const ROWS: &[OverlayRow] = &[$(ops::$module::OVERLAY_ROW),+];

                        pub(super) fn declare(builder: DialectBuilder) -> DialectBuilder {{
                            $(
                                let builder = builder.declare_claimed::<ops::$module::$operation>(ClaimedRoute {{
                                    precedence: ops::$module::$operation::PRECEDENCE,
                                    rows: ops::$module::$operation::rows(),
                                    shadows: const {{ &[shadows_control_plane(ops::$module::NAME)] }},
                                    bucket_param: ops::$module::$operation::BUCKET,
                                }});
                            )+
                            builder
                        }}

                        pub(super) fn register(builder: ServiceBuilder, host: &Arc<Host>) -> ServiceBuilder {{
                            builder$(.register::<ops::$module::$operation, _>(Arc::clone(host)))+
                        }}
                    }};
                }}

                native_routes!({native_route_entries});

                pub(super) fn append_rows(rows: &mut Vec<OverlayRow>) {{
                    rows.extend_from_slice(ROWS);
                }}

                pub(super) fn contains(name: &str) -> bool {{
                    ROWS.iter().any(|row| row.name == name)
                }}
            """
            files[metadata.NATIVE_AUTHORITY] = f"""
                use super::ClaimedHead;
                use rustfs_gateway_dialect_rustfs_admin::native::ops;

                pub(super) async fn authorize(context: &RequestContext<'_>, request: &AuthzRequest<'_>, head: &ClaimedHead) -> S3Result<()> {{
                    let identity = request
                        .identity
                        .filter(|identity| context.auth_scheme() == AuthSchemeRef::SigV4Header && identity.origin() == IdentityOrigin::AccessKey)
                        .ok_or_else(|| s3_error!(AccessDenied, "header-signed admin identity required"))?;
                    let accepted = context
                        .headers()
                        .ok_or_else(|| s3_error!(InternalError, "accepted admin headers are unavailable"))?;
                    let mut headers = HeaderMap::new();
                    for (name, value) in accepted.iter_raw() {{
                        headers.append(name.clone(), value.clone());
                    }}
                    if !headers.contains_key(header::HOST)
                        && let Some(authority) = head.uri.authority()
                    {{
                        headers.insert(
                            header::HOST,
                            HeaderValue::from_str(authority.as_str())
                                .map_err(|_| s3_error!(InternalError, "invalid accepted admin authority"))?,
                        );
                    }}
                    let session = get_session_token(&head.uri, &headers).map(str::to_owned);
                    let credentials = RequestCredentials::without_secret_key(identity.access_key_id().to_owned(), session);
                    let (credentials, owner) = authenticate_envelope_credentials(&credentials).await?;
                    let Permission::Admin {{ action, bucket }} = permission(request)? else {{
                        return Ok(());
                    }};
                    let extensions = context.server_extensions();
                    let peer = extensions.get::<Option<RemoteAddr>>().copied().flatten().map(|peer| peer.0);
                    let source = RequestEnvelope::policy_source_addr_from(peer, extensions.get::<ClientInfo>());
                    match bucket {{
                        Some(bucket) => {{
                            validate_admin_request_with_bucket(&headers, &credentials, owner, false, vec![action], source, bucket).await?
                        }}
                        None => validate_admin_request(&headers, &credentials, owner, false, vec![action], source).await?,
                    }}
                    if request.operation == ops::put_v3_site_replication_remove_v2::NAME {{
                        reject_site_replicator_on_public_admin(&credentials)?;
                    }}
                    Ok(())
                }}

                fn permission<'a>(request: &AuthzRequest<'a>) -> S3Result<Permission<'a>> {{
                    if request.operation == ops::post_v4_account_permissions::NAME {{
                        if request.action == ops::post_v4_account_permissions::AUTH.action
                            && request.resource == ResourceShape::Service
                            && matches!(request.subject, Some(Subject::Caller))
                        {{
                            return Ok(Permission::Caller);
                        }}
                        return Err(s3_error!(AccessDenied, "permission queries require the caller subject"));
                    }}
                    let (action, shape) = match request.operation {{{permission_arms}
                        _ => return Err(s3_error!(InternalError, "unregistered native admin operation")),
                    }};
                    let action = Action::AdminAction(action);
                    if request.action != <&str>::from(&action) || request.resource != shape || request.subject.is_some() {{
                        return Err(s3_error!(AccessDenied, "unexpected admin authorization requirement"));
                    }}
                    let bucket = if shape == ResourceShape::Bucket {{
                        Some(
                            request
                                .bucket
                                .ok_or_else(|| s3_error!(AccessDenied, "admin bucket is unavailable"))?
                                .as_str(),
                        )
                    }} else {{
                        None
                    }};
                    Ok(Permission::Admin {{ action, bucket }})
                }}
            """
        return files

    @staticmethod
    def _run_extension_inventory(files):
        repo = Path(__file__).resolve().parents[1]
        names = {
            "S3Action": {
                "ListBucketVersionsAction": "s3:ListBucketVersions",
                "ListBucketAction": "s3:ListBucket",
            },
            "AdminAction": {
                "ConfigUpdateAdminAction": "admin:ConfigUpdate",
                "SiteReplicationRemoveAction": "admin:SiteReplicationRemove",
                "SetBucketTargetAction": "admin:SetBucketTarget",
                "HealAdminAction": "admin:Heal",
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel, content in files.items():
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            return metadata.extension_inventory(
                root,
                repo,
                None,
                names,
                inventory.strip_comments,
                inventory.matching_close,
                inventory.split_args,
                inventory.wire_name,
                inventory.fail,
            )

    def test_pre_native_routes_host_shape_still_passes(self):
        repo = Path(__file__).resolve().parents[1]
        pin = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        bindings, authorities = self._run_extension_inventory(self._host_fixture_files(pin, with_native_routes=False))
        self.assertEqual(len(bindings["extension_tables"]["s3"]), 2)
        self.assertEqual(len(bindings["extension_tables"]["control_plane"]), 8)
        self.assertNotIn(metadata.NATIVE_ROUTES, authorities)
        self.assertNotIn(metadata.NATIVE_AUTHORITY, authorities)

    def test_seven_non_get_native_routes_host_shape_passes_and_records_authorities(self):
        repo = Path(__file__).resolve().parents[1]
        pin = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        files = self._host_fixture_files(pin, with_native_routes=True)
        bindings, authorities = self._run_extension_inventory(files)
        self.assertEqual(len(bindings["extension_tables"]["s3"]), 2)
        self.assertEqual(len(bindings["extension_tables"]["control_plane"]), 8)
        self.assertIn(metadata.NATIVE_ROUTES, authorities)
        self.assertIn(metadata.NATIVE_AUTHORITY, authorities)

        # Rustfmt emits braced match arms without trailing commas; accept them and reject trailing garbage.
        braced = dict(files)
        braced[metadata.NATIVE_AUTHORITY] = braced[metadata.NATIVE_AUTHORITY].replace(
            "=> (AdminAction::ConfigUpdateAdminAction, ResourceShape::Bucket),",
            "=> {\n                (AdminAction::ConfigUpdateAdminAction, ResourceShape::Bucket)\n            }",
            1,
        )
        self._run_extension_inventory(braced)

        tampered = dict(braced)
        tampered[metadata.NATIVE_AUTHORITY] = tampered[metadata.NATIVE_AUTHORITY].replace(
            "=> {\n                (AdminAction::ConfigUpdateAdminAction, ResourceShape::Bucket)\n            }",
            "=> {\n                (AdminAction::ConfigUpdateAdminAction, ResourceShape::Bucket)\n            } extra_token",
            1,
        )
        with self.assertRaises(inventory.InventoryError):
            self._run_extension_inventory(tampered)

    def test_native_claimed_routes_fail_closed_on_tampered_or_get_shapes(self):
        repo = Path(__file__).resolve().parents[1]
        pin = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        base = self._host_fixture_files(pin, with_native_routes=True)
        self._run_extension_inventory(base)

        # Orphan native_routes.rs on pre-native_routes control_plane.rs must fail closed.
        orphan = self._host_fixture_files(pin, with_native_routes=False)
        orphan[metadata.NATIVE_ROUTES] = base[metadata.NATIVE_ROUTES]
        with self.assertRaises(inventory.InventoryError):
            self._run_extension_inventory(orphan)

        mutations = [
            (metadata.CONTROL_HOST, "mod native_authority;", ""),
            (metadata.CONTROL_HOST, "mod native_routes;", "#[cfg(test)] mod native_routes;"),
            (metadata.CONTROL_HOST, "native_routes::append_rows(&mut rows);", ""),
            (metadata.CONTROL_HOST, "native_routes::declare(builder)", "builder"),
            (metadata.CONTROL_HOST, "let builder = native_routes::register(builder, &host);", ""),
            (metadata.CONTROL_HOST, "|| native_routes::contains(operation)", ""),
            (metadata.CONTROL_HOST, "async fn route(", "fn route("),
            (
                metadata.CONTROL_HOST,
                "self.router\n                                    .validate_notification_target_params(&head.method, &head.uri)\n                                    .map_err(handler_error)?;",
                "",
            ),
            (
                metadata.CONTROL_HOST,
                "native_authority::authorize(context, request, head).await",
                "Ok::<(), rustfs_s3_types::S3Error>(())",
            ),
            (metadata.CONTROL_HOST, "return Ok(Decision::Deny);", "return Ok(Decision::Allow);"),
            (metadata.CONTROL_HOST, "unwrap_or(Decision::Deny)", "unwrap_or(Decision::Allow)"),
            (metadata.NATIVE_ROUTES, "shadowed: NAME,", 'shadowed: "rustfs:AdminFallback",'),
            (metadata.NATIVE_ROUTES, "builder$(.register::<ops::$module::$operation, _>(Arc::clone(host)))+", "builder"),
            (
                metadata.NATIVE_ROUTES,
                "put_v3_bucket_etag_by_bucket::PutV3BucketEtagByBucket,",
                "put_v3_bucket_etag_by_bucket::PutV3BucketEtagByBucket,\n                    put_v3_bucket_etag_by_bucket::PutV3BucketEtagByBucket,",
            ),
            (
                metadata.NATIVE_ROUTES,
                "put_v3_bucket_etag_by_bucket::PutV3BucketEtagByBucket,",
                "missing_native_op::MissingNativeOp,",
            ),
            (metadata.NATIVE_AUTHORITY, "AuthSchemeRef::SigV4Header", "AuthSchemeRef::SigV4Query"),
            (metadata.NATIVE_AUTHORITY, "reject_site_replicator_on_public_admin(&credentials)?;", ""),
            (
                metadata.NATIVE_AUTHORITY,
                "| ops::put_v3_bucket_etag_by_bucket::NAME",
                "",
            ),
            (
                metadata.NATIVE_AUTHORITY,
                "ops::post_v4_heal_mrf_cluster_responsibilities_actions::NAME",
                "ops::get_v4_heal_mrf_cluster::NAME | ops::post_v4_heal_mrf_cluster_responsibilities_actions::NAME",
            ),
            (
                metadata.NATIVE_AUTHORITY,
                "AdminAction::ConfigUpdateAdminAction",
                "AdminAction::HealAdminAction",
            ),
        ]
        for path, old, new in mutations:
            with self.subTest(path=path, old=old, new=new):
                self.assertIn(old, base[path])
                mutated = dict(base)
                mutated[path] = mutated[path].replace(old, new, 1)
                with self.assertRaises(inventory.InventoryError):
                    self._run_extension_inventory(mutated)

        # Accidental GET op in native_routes! without GatewayStack Object Lambda fallback must fail closed.
        with_get = dict(base)
        with_get[metadata.NATIVE_ROUTES] = with_get[metadata.NATIVE_ROUTES].replace(
            "post_v4_heal_mrf_cluster_responsibilities_actions::PostV4HealMrfClusterResponsibilitiesActions,",
            "get_v4_heal_mrf_cluster::GetV4HealMrfCluster,\n                    post_v4_heal_mrf_cluster_responsibilities_actions::PostV4HealMrfClusterResponsibilitiesActions,",
            1,
        )
        with_get[metadata.NATIVE_AUTHORITY] = with_get[metadata.NATIVE_AUTHORITY].replace(
            "ops::post_v4_heal_mrf_cluster_responsibilities_actions::NAME",
            "ops::get_v4_heal_mrf_cluster::NAME | ops::post_v4_heal_mrf_cluster_responsibilities_actions::NAME",
            1,
        )
        with self.assertRaisesRegex(inventory.InventoryError, "GET native route requires GatewayStack Object Lambda fallback"):
            self._run_extension_inventory(with_get)

    def test_twelve_native_routes_with_object_lambda_fallback_pass_across_formatting_variants(self):
        repo = Path(__file__).resolve().parents[1]
        pin = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        base = self._host_fixture_files(pin, with_native_routes=True, with_get_native_routes=True, with_lambda_fallback=True)
        bindings, authorities = self._run_extension_inventory(base)
        self.assertEqual(len(bindings["extension_tables"]["s3"]), 2)
        self.assertEqual(len(bindings["extension_tables"]["control_plane"]), 8)
        self.assertIn(metadata.NATIVE_ROUTES, authorities)
        self.assertIn(metadata.NATIVE_AUTHORITY, authorities)

        # 4-field GatewayStack with valid fallback wiring is also accepted when only the 7 non-GET routes are mounted.
        seven_with_fallback = self._host_fixture_files(
            pin, with_native_routes=True, with_get_native_routes=False, with_lambda_fallback=True
        )
        self._run_extension_inventory(seven_with_fallback)

        # Short `S3Service` type, unbraced fallback arm, imported `object_lambda_target`, and sibling `TestGateway::call`.
        short_variant = dict(base)
        short_variant[metadata.NATIVE_STACK] = (
            "use crate::admin::router::object_lambda_target;\n"
            + short_variant[metadata.NATIVE_STACK]
            .replace("Option<rustfs_gateway::S3Service>", "Option<S3Service>", 1)
            .replace(
                "Some(fallback) if crate::admin::router::object_lambda_target(request.method(), request.uri()).is_some() => {\n"
                "                            fallback.clone()\n"
                "                        }",
                "Some(fallback) if object_lambda_target(request.method(), request.uri()).is_some() => fallback.clone(),",
                1,
            )
            + "\nimpl TestGateway { pub(crate) async fn call(&self, request: Request<Body>) -> Response<Body> { self.0.call(request).await } }\n"
        )
        short_variant[metadata.CONTROL_HOST] = short_variant[metadata.CONTROL_HOST].replace(
            "-> Result<rustfs_gateway::S3Service, GatewayAssemblyError>",
            "-> Result<S3Service, GatewayAssemblyError>",
            1,
        )
        self._run_extension_inventory(short_variant)

        # Rustfmt-wrapped `configured_builder`, fallback built before `let service`, moved `iam`/`root`/`host`,
        # single-line `object_lambda_dialect` build, `let service = ...; Ok(service)` in fallback builder,
        # and multiline wrapped tuple arms in `native_authority::permission`.
        before_service = dict(base)
        before_service[metadata.NATIVE_STACK] = before_service[metadata.NATIVE_STACK].replace(
            "crate::admin::router::object_lambda_target(request.method(), request.uri()).is_some()",
            "crate::admin::router::object_lambda_target(\n"
            "                            request.method(),\n"
            "                            request.uri(),\n"
            "                        )\n"
            "                        .is_some()",
            1,
        )
        before_service[metadata.CONTROL_HOST] = (
            before_service[metadata.CONTROL_HOST]
            .replace(
                "control_plane::declare(builder)\n"
                "                    .build()\n"
                "                    .map_err(GatewayAssemblyError::AdminDialect)",
                "control_plane::declare(builder).build().map_err(GatewayAssemblyError::AdminDialect)",
                1,
            )
            .replace(
                "builder\n"
                "                    .hand_caller_secret_to_every_operation_after_listing_in_the_posture_report()",
                "let service = builder\n"
                "                    .hand_caller_secret_to_every_operation_after_listing_in_the_posture_report()",
                1,
            )
            .replace(
                ".map_err(GatewayAssemblyError::Service)\n"
                "            }",
                ".map_err(GatewayAssemblyError::Service)?;\n"
                "                Ok(service)\n"
                "            }",
                1,
            )
            .replace(
                "let (builder, _settings) = GatewayStack::configured_builder(&assembly, Arc::clone(&iam), Arc::clone(&root), gate, authenticator)?",
                "let object_lambda_fallback = assemble_object_lambda_fallback(\n"
                "                    &assembly,\n"
                "                    Arc::clone(&iam),\n"
                "                    Arc::clone(&root),\n"
                "                    Arc::clone(&router),\n"
                "                    Arc::clone(&host),\n"
                "                )?;\n"
                "                let (builder, _settings) = GatewayStack::configured_builder(\n"
                "                    &assembly,\n"
                "                    iam,\n"
                "                    root,\n"
                "                    gate,\n"
                "                    authenticator,\n"
                "                )?",
                1,
            )
            .replace(
                ".register::<ListenBucketNotification, _>(Arc::clone(&host))",
                ".register::<ListenBucketNotification, _>(host)",
                1,
            )
            .replace(
                "\n                let object_lambda_fallback = assemble_object_lambda_fallback("
                "&assembly, Arc::clone(&iam), Arc::clone(&root), Arc::clone(&router), Arc::clone(&host))?;",
                "",
                1,
            )
        )
        before_service[metadata.NATIVE_AUTHORITY] = before_service[metadata.NATIVE_AUTHORITY].replace(
            "=> (AdminAction::SiteReplicationRemoveAction, ResourceShape::Service),",
            "=> (\n                            AdminAction::SiteReplicationRemoveAction,\n                            ResourceShape::Service,\n                        ),",
            1,
        )
        self._run_extension_inventory(before_service)

        # Inline `Some(assemble_object_lambda_fallback(...)?)` with moved final arguments.
        inline_fallback = dict(base)
        inline_fallback[metadata.CONTROL_HOST] = (
            inline_fallback[metadata.CONTROL_HOST]
            .replace(
                "\n                let object_lambda_fallback = assemble_object_lambda_fallback("
                "&assembly, Arc::clone(&iam), Arc::clone(&root), Arc::clone(&router), Arc::clone(&host))?;",
                "",
                1,
            )
            .replace(
                "object_lambda_fallback: Some(object_lambda_fallback),",
                "object_lambda_fallback: Some(assemble_object_lambda_fallback(&assembly, iam, root, router, host)?),",
                1,
            )
        )
        self._run_extension_inventory(inline_fallback)

    def test_get_native_routes_and_object_lambda_fallback_fail_closed(self):
        repo = Path(__file__).resolve().parents[1]
        pin = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        base = self._host_fixture_files(pin, with_native_routes=True, with_get_native_routes=True, with_lambda_fallback=True)
        self._run_extension_inventory(base)

        # 5 GET routes with only an unused `object_lambda_fallback` field (missing `GatewayStack::call` dispatch) must fail.
        unused_field = self._host_fixture_files(
            pin, with_native_routes=True, with_get_native_routes=True, with_lambda_fallback=False
        )
        unused_field[metadata.NATIVE_STACK] = unused_field[metadata.NATIVE_STACK].replace(
            "control_plane: bool,",
            "control_plane: bool,\n                object_lambda_fallback: Option<rustfs_gateway::S3Service>,",
            1,
        )
        unused_field[metadata.NATIVE_STACK] = unused_field[metadata.NATIVE_STACK].replace(
            "control_plane: false,",
            "control_plane: false,\n                        object_lambda_fallback: None,",
            1,
        )
        with self.assertRaises(inventory.InventoryError):
            self._run_extension_inventory(unused_field)

        # Unrelated struct naming `object_lambda_fallback` on a 3-field GatewayStack must fail closed on GET routes.
        decoy_struct = self._host_fixture_files(
            pin, with_native_routes=True, with_get_native_routes=True, with_lambda_fallback=False
        )
        decoy_struct[metadata.NATIVE_STACK] += "\nstruct Decoy { object_lambda_fallback: Option<rustfs_gateway::S3Service> }\n"
        with self.assertRaisesRegex(inventory.InventoryError, "GET native route requires GatewayStack Object Lambda fallback"):
            self._run_extension_inventory(decoy_struct)

        # Mismatch: 3-field GatewayStack cannot carry `object_lambda_fallback: None` in `assemble_with`.
        three_field_mismatch = self._host_fixture_files(pin, with_native_routes=True, with_lambda_fallback=False)
        three_field_mismatch[metadata.NATIVE_STACK] = three_field_mismatch[metadata.NATIVE_STACK].replace(
            "control_plane: false,",
            "control_plane: false,\n                        object_lambda_fallback: None,",
            1,
        )
        with self.assertRaises(inventory.InventoryError):
            self._run_extension_inventory(three_field_mismatch)

        # Orphan fallback helpers in control_plane.rs on a 3-field GatewayStack must fail closed.
        orphan_helpers = self._host_fixture_files(pin, with_native_routes=True, with_lambda_fallback=False)
        orphan_helpers[metadata.CONTROL_HOST] += "\nfn object_lambda_dialect() -> Result<Dialect, GatewayAssemblyError> { dialect() }\n"
        with self.assertRaises(inventory.InventoryError):
            self._run_extension_inventory(orphan_helpers)

        # Duplicate fallback construction (both before and after `let service`) must fail closed.
        double_fallback = dict(base)
        double_fallback[metadata.CONTROL_HOST] = double_fallback[metadata.CONTROL_HOST].replace(
            "let builder = native_routes::register(builder, &host);",
            "let builder = native_routes::register(builder, &host);\n"
            "                let object_lambda_fallback = assemble_object_lambda_fallback("
            "&assembly, Arc::clone(&iam), Arc::clone(&root), Arc::clone(&router), Arc::clone(&host))?;",
            1,
        )
        with self.assertRaises(inventory.InventoryError):
            self._run_extension_inventory(double_fallback)

        mutations = [
            # Wrong `object_lambda_fallback` field type on `GatewayStack`.
            (metadata.NATIVE_STACK, "Option<rustfs_gateway::S3Service>", "Option<String>"),
            # Mismatch: 4-field `GatewayStack` missing `object_lambda_fallback: None` in `assemble_with`.
            (metadata.NATIVE_STACK, "object_lambda_fallback: None,", ""),
            # `assemble_with` setting `Some(...)` instead of `None`.
            (metadata.NATIVE_STACK, "object_lambda_fallback: None,", "object_lambda_fallback: Some(service.clone()),"),
            # Missing `object_lambda_target` check in `GatewayStack::call`.
            (
                metadata.NATIVE_STACK,
                "Some(fallback) if crate::admin::router::object_lambda_target(request.method(), request.uri()).is_some() => {",
                "Some(fallback) => {",
            ),
            # Inverted `object_lambda_target` guard in `GatewayStack::call`.
            (metadata.NATIVE_STACK, ".is_some() => {", ".is_none() => {"),
            # `GatewayStack::call` ignores fallback and always clones `self.service`.
            (metadata.NATIVE_STACK, "fallback.clone()", "self.service.clone()"),
            # `GatewayStack::call` overwrites `service` after dispatch.
            (
                metadata.NATIVE_STACK,
                "let response = service.call(request).await;",
                "let service = self.service.clone();\n                        let response = service.call(request).await;",
            ),
            # `GatewayStack::call` invokes `self.service` instead of selected `service`.
            (
                metadata.NATIVE_STACK,
                "let response = service.call(request).await;",
                "let response = self.service.call(request).await;",
            ),
            # `GatewayStack::call` missing `control_plane::attach_head` before fallback selection.
            (
                metadata.NATIVE_STACK,
                "if self.control_plane {\n                        control_plane::attach_head(&mut request);\n                    }",
                "",
            ),
            # Unqualified `object_lambda_target` without `use crate::admin::router::object_lambda_target`.
            (
                metadata.NATIVE_STACK,
                "crate::admin::router::object_lambda_target(",
                "object_lambda_target(",
            ),
            # `control_plane::assemble` returns `object_lambda_fallback: None`.
            (
                metadata.CONTROL_HOST,
                "object_lambda_fallback: Some(object_lambda_fallback),",
                "object_lambda_fallback: None,",
            ),
            # `control_plane::assemble` returns `Some(service.clone())` instead of fallback.
            (
                metadata.CONTROL_HOST,
                "object_lambda_fallback: Some(object_lambda_fallback),",
                "object_lambda_fallback: Some(service.clone()),",
            ),
            # `object_lambda_dialect` accidentally appends `native_routes` overlay rows.
            (
                metadata.CONTROL_HOST,
                "rows.extend_from_slice(control_plane::ROWS);\n"
                "                let record = RECORD.get_or_init(|| DialectOverlay {\n"
                '                    name: "rustfs-control-plane-object-lambda",',
                "rows.extend_from_slice(control_plane::ROWS);\n"
                "                native_routes::append_rows(&mut rows);\n"
                "                let record = RECORD.get_or_init(|| DialectOverlay {\n"
                '                    name: "rustfs-control-plane-object-lambda",',
            ),
            # `object_lambda_dialect` accidentally calls `native_routes::declare`.
            (
                metadata.CONTROL_HOST,
                "control_plane::declare(builder)\n"
                "                    .build()\n"
                "                    .map_err(GatewayAssemblyError::AdminDialect)",
                "let builder = control_plane::declare(builder);\n"
                "                native_routes::declare(builder)\n"
                "                    .build()\n"
                "                    .map_err(GatewayAssemblyError::AdminDialect)",
            ),
            # `assemble_object_lambda_fallback` accidentally calls `native_routes::register`.
            (
                metadata.CONTROL_HOST,
                "let (builder, _settings) = GatewayStack::configured_builder(assembly, iam, root, gate, authenticator)?\n"
                "                    .config(super::service_config(assembly.body_read_timeout, CLAIMED_ROUTE_BODY_BYTES));",
                "let (builder, _settings) = GatewayStack::configured_builder(assembly, iam, root, gate, authenticator)?\n"
                "                    .config(super::service_config(assembly.body_read_timeout, CLAIMED_ROUTE_BODY_BYTES));\n"
                "                let builder = native_routes::register(builder, &host);",
            ),
            # `assemble_object_lambda_fallback` uses `dialect()?` instead of `object_lambda_dialect()?`.
            (metadata.CONTROL_HOST, ".dialect(&object_lambda_dialect()?)", ".dialect(&dialect()?)"),
            # `assemble_object_lambda_fallback` omits a control-plane extension registration.
            (
                metadata.CONTROL_HOST,
                ".dialect(&object_lambda_dialect()?)\n"
                "                    .register::<ControlPlane, _>(Arc::clone(&host))\n"
                "                    .register::<PostV3SpeedtestClientDevnull, _>(Arc::clone(&host))\n"
                "                    .register::<StsForm, _>(Arc::clone(&host))\n"
                "                    .register::<ResetBucketReplication, _>(Arc::clone(&host))\n"
                "                    .register::<GetReplicationResetStatus, _>(Arc::clone(&host))\n"
                "                    .register::<GetReplicationMetricsV2, _>(Arc::clone(&host))\n"
                "                    .register::<GetReplicationMetrics, _>(Arc::clone(&host))\n"
                "                    .register::<CheckReplication, _>(Arc::clone(&host))\n"
                "                    .register::<InvokeObjectLambda, _>(Arc::clone(&host))",
                ".dialect(&object_lambda_dialect()?)\n"
                "                    .register::<ControlPlane, _>(Arc::clone(&host))\n"
                "                    .register::<PostV3SpeedtestClientDevnull, _>(Arc::clone(&host))\n"
                "                    .register::<StsForm, _>(Arc::clone(&host))\n"
                "                    .register::<ResetBucketReplication, _>(Arc::clone(&host))\n"
                "                    .register::<GetReplicationResetStatus, _>(Arc::clone(&host))\n"
                "                    .register::<GetReplicationMetricsV2, _>(Arc::clone(&host))\n"
                "                    .register::<GetReplicationMetrics, _>(Arc::clone(&host))\n"
                "                    .register::<CheckReplication, _>(Arc::clone(&host))",
            ),
            # `#[cfg(test)]` on `GatewayStack::call` or `object_lambda_fallback` field must fail closed.
            (metadata.NATIVE_STACK, "pub(crate) fn call<B>(", "#[cfg(test)] pub(crate) fn call<B>("),
            (
                metadata.NATIVE_STACK,
                "object_lambda_fallback: Option<rustfs_gateway::S3Service>,",
                "#[cfg(test)] object_lambda_fallback: Option<rustfs_gateway::S3Service>,",
            ),
            # `#[cfg(test)]` on `object_lambda_dialect` or `assemble_object_lambda_fallback`.
            (metadata.CONTROL_HOST, "fn object_lambda_dialect()", "#[cfg(test)] fn object_lambda_dialect()"),
            (metadata.CONTROL_HOST, "fn assemble_object_lambda_fallback(", "#[cfg(test)] fn assemble_object_lambda_fallback("),
            # `replicator_guard` must apply ONLY to `put_v3_site_replication_remove_v2`, not GET capabilities.
            (
                metadata.NATIVE_AUTHORITY,
                "if request.operation == ops::put_v3_site_replication_remove_v2::NAME {",
                "if matches!(request.operation, ops::put_v3_site_replication_remove_v2::NAME | ops::get_v3_site_replication_remove_v2_capabilities::NAME) {",
            ),
            # Missing one of the 5 GET ops in `native_authority::permission`.
            (metadata.NATIVE_AUTHORITY, "| ops::get_v3_bucket_etag_by_bucket::NAME", ""),
            # Wrong resource shape for `get_v3_bucket_etag_by_bucket` (must be Bucket, not Service).
            (
                metadata.NATIVE_AUTHORITY,
                "ops::delete_v3_bucket_etag_by_bucket::NAME\n"
                "                        | ops::get_v3_bucket_etag_by_bucket::NAME\n"
                "                        | ops::put_v3_bucket_etag_by_bucket::NAME => (AdminAction::ConfigUpdateAdminAction, ResourceShape::Bucket),",
                "ops::delete_v3_bucket_etag_by_bucket::NAME\n"
                "                        | ops::put_v3_bucket_etag_by_bucket::NAME => (AdminAction::ConfigUpdateAdminAction, ResourceShape::Bucket),\n"
                "                        ops::get_v3_bucket_etag_by_bucket::NAME => (AdminAction::ConfigUpdateAdminAction, ResourceShape::Service),",
            ),
        ]
        for path, old, new in mutations:
            with self.subTest(path=path, old=old, new=new):
                self.assertIn(old, base[path])
                mutated = dict(base)
                mutated[path] = mutated[path].replace(old, new, 1)
                with self.assertRaises(inventory.InventoryError):
                    self._run_extension_inventory(mutated)

        # Local `fn object_lambda_target` even when `use crate::admin::router::object_lambda_target;` is present must fail.
        shadowed_target = dict(base)
        shadowed_target[metadata.NATIVE_STACK] = (
            "use crate::admin::router::object_lambda_target;\n"
            + shadowed_target[metadata.NATIVE_STACK].replace("crate::admin::router::object_lambda_target(", "object_lambda_target(", 1)
            + "\nfn object_lambda_target(_m: &Method, _u: &Uri) -> Option<()> { None }\n"
        )
        with self.assertRaises(inventory.InventoryError):
            self._run_extension_inventory(shadowed_target)


if __name__ == "__main__":
    unittest.main()
