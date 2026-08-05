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

//! Method name to operation name, and every way that can go wrong.
//!
//! Responsible for: [`operation_of`] — the mechanical snake_case to PascalCase mapping and its
//! validation against the known names — [`snake_of`], the inverse used to phrase suggestions, and
//! [`check_signature`], which catches the copy-paste error this macro exists to make survivable.
//! NOT responsible for: emitting anything (`crate::expand`) or knowing the names
//! (`crate::op_names`).
//! Upstream: `crate::op_names`, `crate::levenshtein`. Downstream: `crate::expand`.
//!
//! # The mapping has no exception table
//!
//! AWS operation names are PascalCase and stable, so `put_object` is `PutObject` and
//! `list_objects_v2` is `ListObjectsV2` by a rule with no cases in it. A per-operation table would
//! be a second place for a name to live, and the first place would win a disagreement silently.
//!
//! # Where the errors point
//!
//! At the method name identifier, and at the `Req<...>` type — never at the `impl` block. An error
//! reported on a 400-line `impl` says "something in here is wrong", which is what the reader
//! already knew.

use proc_macro2::Span;
use syn::spanned::Spanned;
use syn::{Error, FnArg, Ident, PatType, ReceiverKind, Signature, Type};

use crate::levenshtein::suggestions;
use crate::op_names::{OPERATION_NAMES, SNAKE_ALIASES};

/// The PascalCase operation name a snake_case method name spells.
///
/// Mechanical: every `_`-separated segment is capitalised and the segments are joined.
pub(crate) fn pascal_of(method: &str) -> String {
    let mut out = String::with_capacity(method.len());
    for segment in method.split('_').filter(|segment| !segment.is_empty()) {
        let mut chars = segment.chars();
        if let Some(first) = chars.next() {
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
        }
    }
    out
}

/// The snake_case method name a PascalCase operation name spells.
///
/// The inverse of [`pascal_of`] for every name in the list, which `tests` asserts rather than
/// assumes: a pair of conversions that disagree would make a suggestion that does not compile.
pub(crate) fn snake_of(operation: &str) -> String {
    if let Some((_, alias)) = SNAKE_ALIASES.iter().find(|(name, _)| *name == operation) {
        return (*alias).to_owned();
    }
    let mut out = String::with_capacity(operation.len().saturating_add(4));
    let mut previous_was_lower = false;
    for ch in operation.chars() {
        if ch.is_uppercase() && previous_was_lower {
            out.push('_');
        }
        previous_was_lower = ch.is_lowercase() || ch.is_numeric();
        out.extend(ch.to_lowercase());
    }
    out
}

/// The operation a method name names.
///
/// # Errors
///
/// [`Error`] on the method name's own span when the name spells no known operation, carrying the
/// nearest two method names as suggestions.
pub(crate) fn operation_of(method: &Ident) -> Result<Ident, Error> {
    let method_name = method.to_string();
    let operation = pascal_of(&method_name);
    if OPERATION_NAMES.contains(&operation.as_str()) {
        return Ok(Ident::new(&operation, method.span()));
    }

    let known: Vec<String> = OPERATION_NAMES.iter().map(|name| snake_of(name)).collect();
    let near = suggestions(&method_name, known.iter().map(String::as_str));
    let mut message = format!("unknown S3 operation `{operation}`, mapped from the method name `{method_name}`");
    for (position, candidate) in near.iter().enumerate() {
        let lead = if position == 0 { "did you mean" } else { "or" };
        message.push_str(&format!("\nhelp: {lead} `{candidate}`?"));
    }
    if near.is_empty() {
        message.push_str("\nhelp: add `#[handlers(skip)]` if this method is a helper rather than an operation");
    }
    message.push_str("\nnote: the operations this build knows are listed in OPERATIONS.md");
    Err(Error::new(method.span(), message))
}

/// The `Req<...>` argument of a handler method, with the operation it names.
///
/// # Errors
///
/// [`Error`] when the method does not take `&self` and one `Req<Operation>`, or when the operation
/// in the signature is not the one the method name spells. The second error is reported on the
/// `Req<...>` type, because that is the token that is wrong: the method name is what the reader
/// asked for, and the signature is what was left over from the file it was copied from.
pub(crate) fn check_signature(signature: &Signature, expected: &Ident) -> Result<(), Error> {
    if signature.asyncness.is_none() {
        return Err(Error::new(
            signature.ident.span(),
            "a handler method must be `async fn`; the generated `impl Handler` delegates to it and \
             has nothing to await otherwise\nhelp: add `#[handlers(skip)]` if this method is a \
             helper rather than an operation",
        ));
    }

    let mut arguments = signature.inputs.iter();
    match arguments.next() {
        Some(FnArg::Receiver(receiver))
            if matches!(receiver.kind, ReceiverKind::Reference(_, _, None)) && receiver.mutability.is_none() => {}
        Some(other) => {
            return Err(Error::new(other.span(), "a handler method takes `&self`"));
        }
        None => {
            return Err(Error::new(signature.ident.span(), "a handler method takes `&self` and one `Req<..>`"));
        }
    }

    let Some(FnArg::Typed(request)) = arguments.next() else {
        return Err(Error::new(
            signature.ident.span(),
            "a handler method takes exactly one argument after `&self`, of type `Req<..>`",
        ));
    };
    if let Some(extra) = arguments.next() {
        return Err(Error::new(extra.span(), "a handler method takes no argument after the `Req<..>`"));
    }

    check_request_type(request, expected)
}

/// Whether the `Req<X>` argument names the operation the method name spells.
fn check_request_type(request: &PatType, expected: &Ident) -> Result<(), Error> {
    let named = request_operation(&request.ty);
    match named {
        Some(named) if named == *expected => Ok(()),
        Some(named) => Err(Error::new(
            request.ty.span(),
            format!(
                "this signature is for `{named}`, but the method name spells `{expected}`\n\
                 help: rename the method to `{}`, or change the argument to `Req<{expected}>`",
                snake_of(&named.to_string())
            ),
        )),
        None => Err(Error::new(
            request.ty.span(),
            format!("a handler method takes `Req<{expected}>`, spelled out so that the operation is readable here"),
        )),
    }
}

/// The `X` of a `Req<X>`, whatever module path the `Req` was written with.
fn request_operation(ty: &Type) -> Option<Ident> {
    let Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    if segment.ident != "Req" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    let syn::GenericArgument::Type(Type::Path(operation)) = arguments.args.first()? else {
        return None;
    };
    let last = operation.path.segments.last()?;
    Some(Ident::new(&last.ident.to_string(), operation.span()))
}

/// A span for an error that has no better token to point at.
pub(crate) fn call_site() -> Span {
    Span::call_site()
}
