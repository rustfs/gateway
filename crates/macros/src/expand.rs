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

//! The whole expansion: what is read, what is copied through, and what is written.
//!
//! Responsible for: [`expand`] — parsing the attribute arguments, walking the `impl` block,
//! validating each method, and emitting the original block plus one `impl Handler` per method plus
//! one `register` function.
//! NOT responsible for: the name mapping (`crate::mapping`) or the suggestions
//! (`crate::levenshtein`).
//! Upstream: `crate::mapping`. Downstream: `crate::lib`'s attribute entry point.
//!
//! # What is copied and what is written
//!
//! The `impl` block goes out exactly as it came in, minus the `#[handlers(skip)]` markers, which
//! are this macro's own vocabulary and would not compile on their own. Every method body is moved,
//! not read: `crate::tests` compares the bodies token for token before and after, because "the
//! macro does not rewrite your code" is the claim the rest of the design rests on.
//!
//! The generated `impl Handler` bodies are one delegating call each. Inlining the body into the
//! trait implementation would produce two copies of it, and the copy a reader finds by grepping
//! would be the one they did not edit.
//!
//! # Why `register` lands in a second `impl` block
//!
//! Because the first one is copied through untouched. A generated function inserted into the
//! block the user wrote would mean the emitted block is no longer the block they can read in their
//! own file.

use proc_macro2::{TokenStream, TokenTree};
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream, Parser};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{Attribute, Error, Ident, ImplItem, ItemImpl, Meta, Token};

use crate::mapping::{call_site, check_signature, operation_of};

/// The attribute's own arguments: `#[handlers]` or `#[handlers(group = objects)]`.
struct Args {
    group: Option<Ident>,
}

impl Parse for Args {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        if input.is_empty() {
            return Ok(Self { group: None });
        }
        let key: Ident = input.parse()?;
        if key != "group" {
            return Err(Error::new(
                key.span(),
                "the only argument is `group = <name>`, which decides whether this block generates \
                 `register` or `register_<name>`",
            ));
        }
        input.parse::<Token![=]>()?;
        let group: Ident = input.parse()?;
        if !input.is_empty() {
            return Err(Error::new(input.span(), "the only argument is `group = <name>`"));
        }
        Ok(Self { group: Some(group) })
    }
}

/// One method that will get an `impl Handler`.
struct Registration {
    method: Ident,
    operation: Ident,
    presence: Vec<Meta>,
}

/// The macro, as a function over token streams so that it can be tested without a compiler.
pub(crate) fn expand(attr: TokenStream, item: TokenStream) -> Result<TokenStream, Error> {
    let args: Args = syn::parse2(attr)?;
    let mut block: ItemImpl = syn::parse2(item)?;

    if let Some((path, _)) = &block.trait_ {
        return Err(Error::new(
            path.span(),
            "#[handlers] goes on an inherent `impl` block; the trait implementations are what it \
             generates",
        ));
    }

    let mut registrations: Vec<Registration> = Vec::new();
    for item in &mut block.items {
        let ImplItem::Fn(method) = item else {
            continue;
        };
        let skipped = take_skip_markers(&mut method.attrs)?;
        if skipped {
            continue;
        }

        let operation = operation_of(&method.sig.ident)?;
        check_signature(&method.sig, &operation)?;
        if let Some(previous) = registrations.iter().find(|entry| entry.operation == operation) {
            return Err(Error::new(
                method.sig.ident.span(),
                format!(
                    "`{operation}` is already handled by `{}` in this block; one operation has one \
                     handler, and the second registration would be refused at run time anyway",
                    previous.method
                ),
            ));
        }
        registrations.push(Registration {
            method: method.sig.ident.clone(),
            operation,
            presence: method
                .attrs
                .iter()
                .filter_map(|attr| presence_meta(&attr.meta).transpose())
                .collect::<Result<_, _>>()?,
        });
    }

    if registrations.is_empty() {
        return Err(Error::new(
            block.self_ty.span(),
            "this `impl` block registers no operation; remove `#[handlers]`, or remove the \
             `#[handlers(skip)]` from the method that was meant to be one",
        ));
    }

    Ok(emit(&block, &args, &registrations))
}

/// Keeps only attributes that determine whether the method exists, including nested `cfg_attr`.
fn presence_meta(meta: &Meta) -> Result<Option<Meta>, Error> {
    if meta.path().is_ident("cfg") {
        return Ok(Some(meta.clone()));
    }
    if !meta.path().is_ident("cfg_attr") {
        return Ok(None);
    }
    let Meta::List(list) = meta else {
        return Err(Error::new_spanned(meta, "cfg_attr requires a predicate and attributes"));
    };
    // The compiler owns the predicate grammar; groups keep its nested commas intact.
    let mut arguments = list.tokens.clone().into_iter();
    let predicate: TokenStream = arguments
        .by_ref()
        .take_while(|token| !matches!(token, TokenTree::Punct(punctuation) if punctuation.as_char() == ','))
        .collect();
    let presence: Vec<Meta> = Punctuated::<Meta, Token![,]>::parse_terminated
        .parse2(arguments.collect())?
        .into_iter()
        .filter_map(|attr| presence_meta(&attr).transpose())
        .collect::<Result<_, _>>()?;
    if presence.is_empty() {
        return Ok(None);
    }
    Ok(Some(syn::parse_quote_spanned!(list.span()=> cfg_attr(#predicate, #(#presence),*))))
}

/// Removes `#[handlers(skip)]` from a method and says whether it was there.
///
/// # Errors
///
/// [`Error`] when the attribute carries anything other than `skip`, so that a typo inside it is a
/// message rather than a method that is quietly not registered.
fn take_skip_markers(attrs: &mut Vec<Attribute>) -> Result<bool, Error> {
    let mut skipped = false;
    let mut failure = None;
    attrs.retain(|attr| {
        if !attr.path().is_ident("handlers") {
            return true;
        }
        match attr.parse_args::<Ident>() {
            Ok(argument) if argument == "skip" => skipped = true,
            _ => {
                failure = Some(Error::new(
                    attr.span(),
                    "the only per-method argument is `skip`, as in `#[handlers(skip)]`",
                ));
            }
        }
        false
    });
    match failure {
        Some(error) => Err(error),
        None => Ok(skipped),
    }
}

/// The emitted tokens: the original block, the register function, one `impl Handler` per method.
fn emit(block: &ItemImpl, args: &Args, registrations: &[Registration]) -> TokenStream {
    let self_ty = &block.self_ty;
    let (impl_generics, _, where_clause) = block.generics.split_for_impl();

    let register = match &args.group {
        Some(group) => format_ident!("register_{}", group, span = group.span()),
        None => format_ident!("register", span = call_site()),
    };
    let operations: Vec<&Ident> = registrations.iter().map(|entry| &entry.operation).collect();
    let methods: Vec<&Ident> = registrations.iter().map(|entry| &entry.method).collect();
    let presence: Vec<TokenStream> = registrations
        .iter()
        .map(|entry| {
            let attrs = &entry.presence;
            quote! { #(#[#attrs])* }
        })
        .collect();

    let register_doc = format!(
        "Registers the operations implemented in this block: {}.",
        operations.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
    );

    quote! {
        #block

        impl #impl_generics #self_ty #where_clause {
            #[doc = #register_doc]
            ///
            /// Generated by `#[rustfs_gateway::handlers]`. The hand-written equivalent is a
            /// chain of `RouterBuilder::handle` calls, one per operation.
            pub fn #register(
                this: &::std::sync::Arc<Self>,
                builder: ::rustfs_gateway::RouterBuilder,
            ) -> ::rustfs_gateway::RouterBuilder {
                let _ = this;
                #(
                    #presence
                    let builder = builder.handle::<#operations, Self>(::std::sync::Arc::clone(this));
                )*
                builder
            }
        }

        #(
            #presence
            impl #impl_generics ::rustfs_gateway::Handler<#operations> for #self_ty #where_clause {
                fn call(
                    &self,
                    request: ::rustfs_gateway::Req<#operations>,
                ) -> impl ::core::future::Future<
                    Output = ::rustfs_gateway::HandlerResult<#operations>,
                > + ::core::marker::Send {
                    self.#methods(request)
                }

                fn call_with_context(
                    &self,
                    request: ::rustfs_gateway::Req<#operations>,
                    _context: ::rustfs_gateway::HandlerContext,
                ) -> impl ::core::future::Future<
                    Output = ::rustfs_gateway::HandlerResult<#operations>,
                > + ::core::marker::Send {
                    self.#methods(request)
                }
            }
        )*
    }
}
