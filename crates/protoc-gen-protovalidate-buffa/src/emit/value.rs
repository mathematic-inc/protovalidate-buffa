//! Compose rules for a bound value. Ignore policy encloses standard rules,
//! custom rules, and recursion together; no successful emission skips a stage.

use anyhow::Result;
use proc_macro2::TokenStream;
use quote::quote;

use crate::scan::{FieldKind, FieldValidator, Ignore};

use super::{cel, rule_site::RuleSite, scalar, wkt};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Presence {
    Implicit,
    Explicit,
}

/// Validate an already-present value. Numeric and enum expressions are values;
/// strings, bytes, and messages are borrowed. Collection elements are present
/// even when their scalar value is zero.
pub(super) fn emit(
    kind: &FieldKind,
    value: &TokenStream,
    rules: Option<&FieldValidator>,
    site: &RuleSite,
    presence: Presence,
    schemas: &cel::SchemaIndex,
) -> Result<TokenStream> {
    if rules.is_some_and(|r| r.ignore == Ignore::Always) {
        return Ok(TokenStream::new());
    }
    let mut checks = Vec::new();
    if let Some(rules) = rules {
        let wrapper = match kind {
            FieldKind::Message { full_name } => crate::scan::wrapper_kind(full_name),
            _ => None,
        };
        let inner = match kind {
            FieldKind::Wrapper(inner) => inner.as_ref(),
            _ => wrapper.as_ref().unwrap_or(kind),
        };
        let access = if wrapper.is_some() || matches!(kind, FieldKind::Wrapper(_)) {
            quote! { (#value).value }
        } else {
            value.clone()
        };
        let access = match inner {
            FieldKind::String => quote! { ::core::convert::AsRef::<str>::as_ref(&(#access)) },
            FieldKind::Bytes => quote! { ::core::convert::AsRef::<[u8]>::as_ref(&(#access)) },
            _ => quote! { (#access) },
        };
        if let FieldKind::Message { full_name } = inner {
            checks.extend(wkt::emit(&rules.standard, full_name, &access, site));
        } else {
            checks.extend(scalar::emit_scalar_rules(
                &access,
                inner,
                &rules.standard,
                site,
            )?);
        }
        checks.extend(emit_custom(
            inner,
            rules,
            site,
            schemas,
            cel::this_binding_for_kind_with(inner, &access, Some(schemas)),
        ));
    }
    if matches!(kind, FieldKind::Message { full_name } if !full_name.starts_with("google.protobuf."))
    {
        checks.push(recurse(value, site));
    }
    if checks.is_empty() {
        return Ok(TokenStream::new());
    }
    let body = quote! {{
        #[allow(unused_imports, reason = "closed enums need the Enumeration trait")]
        use ::buffa::Enumeration as _;
        #( #checks )*
    }};
    if presence == Presence::Implicit
        && rules.is_some_and(|r| r.ignore == Ignore::IfZeroValue)
        && let Some(guard) = nonzero_guard(kind, value)
    {
        return Ok(quote! { if #guard { #body } });
    }
    Ok(body)
}

/// Standard and custom rules use the same site and already-bound value.
/// Collection bindings differ in representation, not in rule composition.
pub(super) fn emit_custom(
    kind: &FieldKind,
    rules: &FieldValidator,
    site: &RuleSite,
    schemas: &cel::SchemaIndex,
    binding: Option<(TokenStream, super::cel_compile::CelType)>,
) -> Vec<TokenStream> {
    let mut checks = Vec::new();
    let field = site.field_path();
    let mut cel_index = 0;
    let mut expression_index = 0;
    for rule in &rules.cel {
        let (list, index) = if rule.is_cel_expression {
            let index = expression_index;
            expression_index += 1;
            (super::rule_site::CelList::Expression, index)
        } else {
            let index = cel_index;
            cel_index += 1;
            (super::rule_site::CelList::Rule, index)
        };
        let check = binding.clone().and_then(|(this, ty)| {
            cel::try_compile_cel_check(
                &rule.expression,
                &rule.id,
                &rule.message,
                this,
                ty,
                None,
                &field,
                &site.cel_rule(list, index),
                site.for_key(),
                schemas,
            )
        });
        checks.push(check.unwrap_or_else(|| {
            cel::emit_runtime_error_violation(
                &rule.id,
                &format!("unsupported CEL: {}", rule.expression),
            )
        }));
    }
    for rule in &rules.standard.predefined {
        let family = rule
            .family_override
            .map(|(name, number)| cel::Family { name, number })
            .or_else(|| cel::predef_family_for(kind));
        let check = family.and_then(|family| {
            let path = site.rule(
                family.name,
                family.number,
                &format!("[{}]", rule.ext_name),
                rule.ext_number,
                &rule.ext_field_type,
            );
            let (this, ty) = binding.clone()?;
            cel::try_compile_cel_check(
                &rule.expression,
                &rule.id,
                &rule.message,
                this,
                ty,
                rule.rule_const.as_ref(),
                &field,
                &path,
                site.for_key(),
                schemas,
            )
        });
        checks.push(check.unwrap_or_else(|| {
            cel::emit_runtime_error_violation(
                &rule.id,
                &format!("unsupported predefined CEL: {}", rule.expression),
            )
        }));
    }
    checks
}

/// Prefix nested violations, but propagate schema and evaluation failures.
pub(super) fn recurse(value: &TokenStream, site: &RuleSite) -> TokenStream {
    let field = site.field_path();
    quote! {
        if let Err(sub) = (#value).validate() {
            if sub.compile_error.is_some() || sub.runtime_error.is_some() {
                return Err(sub);
            }
            violations.extend(sub.violations.into_iter().map(|mut v| {
                v.field.elements.splice(0..0, (#field).elements);
                v
            }));
        }
    }
}

/// Zero-value policy only applies to values without explicit presence.
pub(super) fn nonzero_guard(kind: &FieldKind, value: &TokenStream) -> Option<TokenStream> {
    match kind {
        FieldKind::String | FieldKind::Bytes | FieldKind::Repeated(_) | FieldKind::Map { .. } => {
            Some(quote! { !(#value).is_empty() })
        }
        FieldKind::Float | FieldKind::Double => Some(quote! { #value != 0.0 }),
        FieldKind::Int32
        | FieldKind::Int64
        | FieldKind::Sint32
        | FieldKind::Sint64
        | FieldKind::Sfixed32
        | FieldKind::Sfixed64
        | FieldKind::Uint32
        | FieldKind::Uint64
        | FieldKind::Fixed32
        | FieldKind::Fixed64 => Some(quote! { #value != 0 }),
        FieldKind::Bool => Some(quote! { #value }),
        FieldKind::Enum { .. } => Some(quote! {{
            fn is_default<T: ::core::default::Default + ::core::cmp::PartialEq>(value: &T) -> bool {
                value == &T::default()
            }
            !is_default(&(#value))
        }}),
        FieldKind::Message { .. } | FieldKind::Wrapper(_) | FieldKind::Optional(_) => None,
    }
}

pub(super) fn element_value(kind: &FieldKind, ident: &syn::Ident) -> TokenStream {
    match kind {
        FieldKind::String
        | FieldKind::Bytes
        | FieldKind::Message { .. }
        | FieldKind::Wrapper(_)
        | FieldKind::Optional(_)
        | FieldKind::Repeated(_)
        | FieldKind::Map { .. } => quote! { #ident },
        FieldKind::Int32
        | FieldKind::Int64
        | FieldKind::Sint32
        | FieldKind::Sint64
        | FieldKind::Sfixed32
        | FieldKind::Sfixed64
        | FieldKind::Uint32
        | FieldKind::Uint64
        | FieldKind::Fixed32
        | FieldKind::Fixed64
        | FieldKind::Float
        | FieldKind::Double
        | FieldKind::Bool
        | FieldKind::Enum { .. } => quote! { *#ident },
    }
}
