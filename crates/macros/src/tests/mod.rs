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

//! What the macro emits, where its errors point, and the governance rules asserted as tests.
//!
//! Responsible for: the expansion goldens, the span assertions that replace a `trybuild` `.stderr`
//! golden, the two governance guards (no minted type names, no rewritten bodies), and the mapping's
//! round trip.
//! NOT responsible for: whether the expansion registers the same operations as the hand-written
//! form — that needs the real registry, and lives in `tests/equivalence.rs`.
//! Upstream: `crate::expand`. Downstream: nothing.
//!
//! # Why the error assertions are here rather than in `trybuild`
//!
//! The property to hold is "the error points at the method name identifier, and suggests near
//! misses". Asserting that through a `.stderr` golden couples the test to how one compiler version
//! renders a diagnostic, which is the flakiest thing in a macro crate. Asserting it on the
//! `syn::Error` is the same property checked directly: the span's line and column are compared with
//! the position of the identifier in the source text.
//!
//! # Why the expansion goldens are rendered here rather than by `cargo expand`
//!
//! `cargo expand` needs a tool installed and a full compilation. `prettyplease` turns the same
//! token stream into the same readable file with neither. The goldens are in the repository for the
//! reason the rule exists — an agent reads the expansion instead of reasoning about the macro — and
//! that reason is served by the file, not by how it was produced.

use std::fs;
use std::path::PathBuf;

use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::{Attribute, Error, File, ImplItem, Item, ItemImpl, Meta};

use crate::expand::expand;
use crate::levenshtein::{distance, suggestions};
use crate::mapping::{pascal_of, snake_of};
use crate::op_names::OPERATION_NAMES;

// ── helpers ──────────────────────────────────────────────────────────────────────────────────

/// The `tests/expand` directory.
fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("expand")
}

/// Splits a golden input into the attribute arguments and the `impl` block they apply to.
fn split_input(source: &str) -> (TokenStream, TokenStream) {
    let file: File = syn::parse_str(source).expect("the golden input parses");
    let mut block: ItemImpl = file
        .items
        .into_iter()
        .find_map(|item| match item {
            Item::Impl(block) => Some(block),
            _ => None,
        })
        .expect("the golden input has an impl block");

    let mut attr_tokens = TokenStream::new();
    let attrs: Vec<Attribute> = std::mem::take(&mut block.attrs);
    for attr in attrs {
        if attr.path().is_ident("handlers") {
            if let Meta::List(list) = &attr.meta {
                attr_tokens = list.tokens.clone();
            }
        } else {
            block.attrs.push(attr);
        }
    }
    (attr_tokens, block.to_token_stream())
}

/// Expands a source string and renders it the way the checked-in golden is rendered.
fn render(source: &str) -> String {
    let (attr, item) = split_input(source);
    let expanded = expand(attr, item).expect("the input expands");
    let file: File = syn::parse2(expanded).expect("the expansion is a parseable file");
    prettyplease::unparse(&file)
}

/// Expands a source string, expecting the macro to refuse it.
fn refuse(source: &str) -> Error {
    let (attr, item) = split_input(source);
    expand(attr, item).expect_err("this input must be refused")
}

/// Where a `syn::Error`'s span starts: one-based line, zero-based column.
fn position(error: &Error) -> (usize, usize) {
    let start = error.span().start();
    (start.line, start.column)
}

/// What every checked-in golden starts with.
///
/// The licence header is not decoration here: `scripts/check_license_headers.sh` checks every
/// tracked `.rs` file, and a generated file that cannot carry the header would need an allowance
/// for something that is simply a rendering choice. The `@generated` line is what stops a reader
/// from editing the file by hand.
const GOLDEN_HEADER: &str = "\
// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the \"License\");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an \"AS IS\" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// @generated by `cargo test -p rustfs-gateway-macros`. Do not edit: change the macro and rerun
// with UPDATE_GOLDEN=1. This is what the compiler sees for the input file of the same name, so
// reading it is always an alternative to reading the macro.

";

/// Compares an expansion with its checked-in golden, or rewrites it when asked to.
fn assert_golden(name: &str) {
    let source = fs::read_to_string(golden_dir().join(format!("{name}.rs"))).expect("the golden input exists");
    let rendered = format!("{GOLDEN_HEADER}{}", render(&source));
    let golden_path = golden_dir().join(format!("{name}.expanded.rs"));

    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        fs::write(&golden_path, &rendered).expect("the golden is writable");
        return;
    }

    let expected = fs::read_to_string(&golden_path).unwrap_or_else(|_| {
        panic!("{name}.expanded.rs is missing; run `UPDATE_GOLDEN=1 cargo test -p rustfs-gateway-macros` to create it")
    });
    assert_eq!(
        rendered, expected,
        "the expansion of {name}.rs changed; read the diff, and if the change is intended run \
         `UPDATE_GOLDEN=1 cargo test -p rustfs-gateway-macros`"
    );
}

/// Every type name the expansion introduces. Governance rule 1 says there are none.
fn minted_type_names(rendered: &str) -> Vec<String> {
    let file: File = syn::parse_str(rendered).expect("the expansion parses");
    file.items
        .iter()
        .filter_map(|item| match item {
            Item::Struct(item) => Some(item.ident.to_string()),
            Item::Enum(item) => Some(item.ident.to_string()),
            Item::Type(item) => Some(item.ident.to_string()),
            Item::Union(item) => Some(item.ident.to_string()),
            Item::Trait(item) => Some(item.ident.to_string()),
            Item::Mod(item) => Some(item.ident.to_string()),
            _ => None,
        })
        .collect()
}

/// The body of every method in every `impl` block, as token text.
fn bodies(source: &str) -> Vec<String> {
    let file: File = syn::parse_str(source).expect("parses");
    file.items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(block) => Some(block),
            _ => None,
        })
        .flat_map(|block| block.items.iter())
        .filter_map(|item| match item {
            ImplItem::Fn(method) => Some(method.block.to_token_stream().to_string()),
            _ => None,
        })
        .collect()
}

// ── positive: what the macro emits ───────────────────────────────────────────────────────────

/// Positive -- one operation, no group: `impl Handler<GetBucketLocation>` and `Fs::register`.
#[test]
fn a_single_operation_expands_to_its_golden() {
    assert_golden("basic");
}

/// Positive -- `group = objects` names the register function, and two operations chain.
#[test]
fn a_group_expands_to_its_golden() {
    assert_golden("groups");
}

/// Positive -- a skipped helper stays in the block and gets no handler.
#[test]
fn a_skipped_helper_expands_to_its_golden() {
    assert_golden("skip");
}

/// Positive -- the group name decides the function name, and nothing else changes.
#[test]
fn the_group_argument_names_the_register_function() {
    let source = fs::read_to_string(golden_dir().join("groups.rs")).expect("input");
    let rendered = render(&source);
    assert!(rendered.contains("pub fn register_objects("), "{rendered}");
    assert!(!rendered.contains("pub fn register("), "{rendered}");

    let ungrouped = render(&source.replace("#[handlers(group = objects)]", "#[handlers]"));
    assert!(ungrouped.contains("pub fn register("), "{ungrouped}");
}

/// Positive -- two blocks in two files generate two register functions that do not collide.
#[test]
fn two_blocks_generate_two_register_functions() {
    let objects = render(
        "#[handlers(group = objects)] impl Fs { async fn put_object(&self, r: Req<PutObject>) -> HandlerResult<PutObject> { self.a(r).await } }",
    );
    let buckets = render(
        "#[handlers(group = buckets)] impl Fs { async fn get_bucket_location(&self, r: Req<GetBucketLocation>) -> HandlerResult<GetBucketLocation> { self.b(r).await } }",
    );
    assert!(objects.contains("pub fn register_objects("), "{objects}");
    assert!(buckets.contains("pub fn register_buckets("), "{buckets}");
    // No summary function is generated: stitching the groups together needs knowledge of every
    // file, which the macro does not have and must not pretend to.
    assert!(!objects.contains("register_all"), "{objects}");
}

/// Positive -- the mapping is a bijection over every name this build knows.
#[test]
fn the_name_mapping_round_trips() {
    for name in OPERATION_NAMES {
        let snake = snake_of(name);
        assert_eq!(&pascal_of(&snake), name, "{name} does not survive the round trip through {snake}");
    }
    assert_eq!(snake_of("ListObjectsV2"), "list_objects_v2");
    assert_eq!(pascal_of("list_objects_v2"), "ListObjectsV2");
}

/// Positive -- the suggestion metric is the ordinary edit distance.
#[test]
fn the_edit_distance_is_the_usual_one() {
    assert_eq!(distance("get_object", "get_object"), 0);
    assert_eq!(distance("get_objects", "get_object"), 1);
    assert_eq!(distance("", "abc"), 3);
    assert_eq!(suggestions("put_objekt", ["put_object", "list_objects_v2"]), vec!["put_object"]);
}

// ── negative: what the macro refuses, and where it points ────────────────────────────────────

/// Negative -- an unknown method name is refused, and the error points at the identifier.
///
/// The span assertion is the whole test: an error on the `impl` block would pass a message check
/// and be useless in a file with forty methods.
#[test]
fn an_unknown_operation_is_reported_on_the_method_name() {
    let source = "#[handlers]\nimpl Fs {\n    async fn put_objects(&self, r: Req<PutObject>) -> HandlerResult<PutObject> { self.a(r).await }\n}";
    let error = refuse(source);
    let message = error.to_string();
    assert!(message.contains("unknown S3 operation `PutObjects`"), "{message}");
    assert!(message.contains("did you mean `put_object`?"), "{message}");
    assert!(message.contains("OPERATIONS.md"), "{message}");

    // Line 3, column 13: the `put_objects` identifier, not the `impl` on line 2 and not the
    // attribute on line 1.
    assert_eq!(position(&error), (3, 13));
}

/// Negative -- the error is not reported on the `impl` block.
#[test]
fn the_error_is_not_reported_on_the_impl_block() {
    let source = "#[handlers]\nimpl Fs {\n    async fn put_objects(&self, r: Req<PutObject>) -> HandlerResult<PutObject> { self.a(r).await }\n}";
    let (line, column) = position(&refuse(source));
    assert_ne!((line, column), (2, 0), "an error on the impl block tells the reader nothing");
    assert!(line > 2, "the error must point inside the block, at line {line}");
}

/// Negative -- a signature naming another operation is reported on the `Req<..>` type.
///
/// The most common mistake there is: a file copied from the operation beside it, renamed at the
/// method and not at the signature.
#[test]
fn a_signature_for_another_operation_is_reported_on_the_request_type() {
    let source = "#[handlers]\nimpl Fs {\n    async fn put_object(&self, r: Req<GetBucketLocation>) -> HandlerResult<PutObject> { self.a(r).await }\n}";
    let error = refuse(source);
    let message = error.to_string();
    assert!(message.contains("this signature is for `GetBucketLocation`"), "{message}");
    assert!(message.contains("the method name spells `PutObject`"), "{message}");
    assert!(message.contains("rename the method to `get_bucket_location`"), "{message}");

    // Column 34 is the `Req<GetBucketLocation>` type, not the method name at column 13.
    assert_eq!(position(&error), (3, 34));
}

/// Negative -- an unrecognised method with no near miss is still an error, never a silent skip.
#[test]
fn an_unrelated_method_name_is_an_error_rather_than_a_skip() {
    let error = refuse(
        "#[handlers]\nimpl Fs {\n    async fn helper(&self, r: Req<PutObject>) -> HandlerResult<PutObject> { self.a(r).await }\n}",
    );
    let message = error.to_string();
    assert!(message.contains("unknown S3 operation `Helper`"), "{message}");
    assert!(message.contains("#[handlers(skip)]"), "{message}");
    assert_eq!(position(&error), (3, 13));
}

/// Negative -- two methods mapping to one operation, reported on the second.
#[test]
fn two_methods_for_one_operation_are_refused() {
    let source = "#[handlers]\nimpl Fs {\n    async fn put_object(&self, r: Req<PutObject>) -> HandlerResult<PutObject> { self.a(r).await }\n    async fn put_object(&self, r: Req<PutObject>) -> HandlerResult<PutObject> { self.b(r).await }\n}";
    let error = refuse(source);
    assert!(error.to_string().contains("`PutObject` is already handled by `put_object`"), "{error}");
    assert_eq!(position(&error).0, 4, "the error belongs on the second method");
}

/// Negative -- a handler method that is not `async` cannot be delegated to.
#[test]
fn a_synchronous_method_is_refused() {
    let error = refuse(
        "#[handlers]\nimpl Fs {\n    fn put_object(&self, r: Req<PutObject>) -> HandlerResult<PutObject> { self.a(r) }\n}",
    );
    assert!(error.to_string().contains("must be `async fn`"), "{error}");
    assert_eq!(position(&error), (3, 7));
}

/// Negative -- a handler method taking something other than `Req<..>`.
#[test]
fn an_argument_that_is_not_a_request_is_refused() {
    let error = refuse(
        "#[handlers]\nimpl Fs {\n    async fn put_object(&self, input: PutObjectInput) -> HandlerResult<PutObject> { self.a(input).await }\n}",
    );
    assert!(error.to_string().contains("takes `Req<PutObject>`"), "{error}");
}

/// Negative -- a handler method taking `self` by value.
#[test]
fn a_method_that_consumes_self_is_refused() {
    let error = refuse(
        "#[handlers]\nimpl Fs {\n    async fn put_object(self, r: Req<PutObject>) -> HandlerResult<PutObject> { self.a(r).await }\n}",
    );
    assert!(error.to_string().contains("takes `&self`"), "{error}");
}

/// Negative -- the macro is for inherent blocks; a trait implementation is what it writes.
#[test]
fn a_trait_impl_is_refused() {
    let error = refuse(
        "#[handlers]\nimpl Handler<PutObject> for Fs {\n    async fn call(&self, r: Req<PutObject>) -> HandlerResult<PutObject> { self.a(r).await }\n}",
    );
    assert!(error.to_string().contains("inherent `impl` block"), "{error}");
}

/// Negative -- a block that registers nothing is a mistake, not a no-op.
#[test]
fn a_block_with_no_operations_is_refused() {
    let error = refuse("#[handlers]\nimpl Fs {\n    #[handlers(skip)]\n    async fn helper(&self) {}\n}");
    assert!(error.to_string().contains("registers no operation"), "{error}");
}

/// Negative -- an argument the macro does not have.
#[test]
fn an_unknown_attribute_argument_is_refused() {
    let error = refuse(
        "#[handlers(prefix = objects)]\nimpl Fs {\n    async fn put_object(&self, r: Req<PutObject>) -> HandlerResult<PutObject> { self.a(r).await }\n}",
    );
    assert!(error.to_string().contains("the only argument is `group = <name>`"), "{error}");
}

/// Negative -- a mistyped per-method marker, which would otherwise drop the method silently.
#[test]
fn a_mistyped_skip_marker_is_refused() {
    let error = refuse("#[handlers]\nimpl Fs {\n    #[handlers(skipp)]\n    async fn helper(&self) {}\n}");
    assert!(error.to_string().contains("the only per-method argument is `skip`"), "{error}");
}

// ── negative: the governance rules ───────────────────────────────────────────────────────────

/// Negative -- governance rule 1: the expansion mints no type name `grep` cannot find.
#[test]
fn the_expansion_mints_no_public_type_name() {
    for name in ["basic", "groups", "skip"] {
        let source = fs::read_to_string(golden_dir().join(format!("{name}.rs"))).expect("input");
        let minted = minted_type_names(&render(&source));
        assert!(
            minted.is_empty(),
            "{name}: the expansion introduced {minted:?}; a generated type name is a definition no \
             reader can find"
        );
    }
}

/// Negative -- governance rule 2: every method body comes out token for token as it went in.
#[test]
fn the_expansion_rewrites_no_function_body() {
    for name in ["basic", "groups", "skip"] {
        let source = fs::read_to_string(golden_dir().join(format!("{name}.rs"))).expect("input");
        let before = bodies(&source);
        let after = bodies(&render(&source));
        assert!(!before.is_empty(), "{name}: the fixture has no bodies to compare");
        for body in &before {
            assert!(
                after.contains(body),
                "{name}: a method body was rewritten by the macro\n  before: {body}\n  after:  {after:?}"
            );
        }
    }
}

/// Negative -- the generated trait implementation delegates and does not inline the body.
///
/// An inlined body would be a second copy of the code, and the copy a reader finds by grepping
/// would be the one they did not edit.
#[test]
fn the_generated_handler_only_delegates() {
    let source = fs::read_to_string(golden_dir().join("basic.rs")).expect("input");
    let rendered = render(&source);
    assert!(rendered.contains("self.get_bucket_location(request)"), "{rendered}");
    assert_eq!(
        rendered.matches("self.region_of(&bucket)").count(),
        1,
        "the body must appear once, in the method the user wrote:\n{rendered}"
    );
}

#[test]
fn n_conditional_presence_does_not_forward_method_only_attributes() {
    for (attrs, projected) in [
        ("#[cfg(any())]", "#[cfg(any())]"),
        ("#[cfg_attr(true, cfg(false))]", "#[cfg_attr(true, cfg(false))]"),
        ("#[cfg_attr(all(), cfg(any()), inline)]", "#[cfg_attr(all(), cfg(any()))]"),
        (
            "#[cfg_attr(all(), cfg_attr(all(), cfg(any()), inline), cold)]",
            "#[cfg_attr(all(), cfg_attr(all(), cfg(any())))]",
        ),
        (
            "#[cfg(all())] #[cfg_attr(any(), cfg(any()))]",
            "#[cfg(all())] #[cfg_attr(any(), cfg(any()))]",
        ),
        ("#[inline] #[cfg_attr(all(), cold)]", ""),
    ] {
        let source = format!(
            "#[handlers] impl Fs {{ {attrs} async fn get_bucket_location(&self, r: Req<GetBucketLocation>) -> HandlerResult<GetBucketLocation> {{ self.answer(r).await }} }}"
        );
        let file: File = syn::parse_str(&render(&source)).expect("the expansion parses");
        let handler = file
            .items
            .iter()
            .find_map(|item| match item {
                Item::Impl(block) if block.trait_.is_some() => Some(block),
                _ => None,
            })
            .expect("a handler impl is emitted");
        let expected: TokenStream = projected.parse().expect("the expected attributes parse");
        let handler_attrs: TokenStream = handler.attrs.iter().map(ToTokens::to_token_stream).collect();
        assert_eq!(handler_attrs.to_string(), expected.to_string(), "handler presence for {attrs}");
        let registration_attrs: TokenStream = file
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Impl(block) if block.trait_.is_none() => Some(block),
                _ => None,
            })
            .flat_map(|block| &block.items)
            .filter_map(|item| match item {
                ImplItem::Fn(method) if method.sig.ident == "register" => Some(method),
                _ => None,
            })
            .flat_map(|method| &method.block.stmts)
            .filter_map(|statement| match statement {
                syn::Stmt::Local(local) => Some(&local.attrs),
                _ => None,
            })
            .flatten()
            .map(ToTokens::to_token_stream)
            .collect();
        assert_eq!(registration_attrs.to_string(), expected.to_string(), "registry presence for {attrs}");
    }
}
