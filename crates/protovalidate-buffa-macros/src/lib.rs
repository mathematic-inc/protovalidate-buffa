//! `#[connect_impl]` — inserts `req.validate()?` at the top of every Connect
//! service handler method in an `impl` block whose request parameter is an
//! `OwnedView<_>` or `connectrpc::ServiceRequest<'_, _>`. Single-site safety
//! net: add it once to the service impl and every present-and-future handler is
//! validated on entry.
//!
//! Non-handler `async fn`s inside the same `impl` block are left alone
//! (they lack a recognized request parameter, so the macro skips them).

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Error, FnArg, ImplItem, ItemImpl, PatType, Type, TypePath, parse_macro_input};

#[proc_macro_attribute]
pub fn connect_impl(attr: TokenStream, input: TokenStream) -> TokenStream {
    if !attr.is_empty() {
        return Error::new_spanned(
            TokenStream2::from(attr),
            "protovalidate_buffa::connect_impl takes no arguments",
        )
        .to_compile_error()
        .into();
    }

    let mut item = parse_macro_input!(input as ItemImpl);

    for impl_item in &mut item.items {
        if let ImplItem::Fn(f) = impl_item
            && let Some(arg_ident) = find_request_arg(&f.sig)
        {
            let pv_ident =
                proc_macro2::Ident::new("__protovalidate_buffa_req_owned", arg_ident.span());

            let decode: syn::Stmt = syn::parse_quote! {
                let #pv_ident = #arg_ident.to_owned_message();
            };
            let validate: syn::Stmt = syn::parse_quote! {
                <_ as ::protovalidate_buffa::Validate>::validate(&#pv_ident)
                    .map_err(::protovalidate_buffa::ValidationError::into_connect_error)?;
            };

            f.block.stmts.insert(0, decode);
            f.block.stmts.insert(1, validate);
        }
    }

    TokenStream::from(quote! { #item })
}

/// Returns the ident of the first request parameter whose type exposes
/// `to_owned_message()`, such as `OwnedView<pb::CreateFooRequestView<'static>>`
/// or `connectrpc::ServiceRequest<'_, pb::CreateFooRequest>`. Non-handler
/// methods that lack such a parameter return `None`.
fn find_request_arg(sig: &syn::Signature) -> Option<syn::Ident> {
    for arg in &sig.inputs {
        if let FnArg::Typed(PatType { pat, ty, .. }) = arg
            && is_request_type(ty)
            && let syn::Pat::Ident(pat_ident) = pat.as_ref()
        {
            return Some(pat_ident.ident.clone());
        }
    }
    None
}

fn is_request_type(ty: &Type) -> bool {
    if let Type::Path(TypePath { path, .. }) = ty
        && let Some(last) = path.segments.last()
    {
        return last.ident == "OwnedView" || last.ident == "ServiceRequest";
    }
    false
}
