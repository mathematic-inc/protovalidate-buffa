//! Emit validation code for `repeated` and `map` fields, including per-element
//! / per-key / per-value rule application and message-type recursion.

use anyhow::Result;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::scan::{FieldKind, MapStandard, RepeatedStandard};

fn repeated_field_path(name: &str, number: i32, ty: &str) -> TokenStream {
    let ty_ident = format_ident!("{}", ty);
    quote! {
        ::protovalidate_buffa::FieldPath {
            elements: ::std::vec![
                ::protovalidate_buffa::FieldPathElement {
                    field_number: Some(#number),
                    field_name: Some(::std::borrow::Cow::Borrowed(#name)),
                    field_type: Some(::protovalidate_buffa::FieldType::#ty_ident),
                    key_type: None,
                    value_type: None,
                    subscript: None,
                },
            ],
        }
    }
}

fn repeated_rule_path(inner: &str, inner_num: i32) -> TokenStream {
    repeated_rule_path_ty(inner, inner_num, "Uint64")
}

fn repeated_rule_path_ty(inner: &str, inner_num: i32, ty: &str) -> TokenStream {
    let ty_ident = format_ident!("{}", ty);
    quote! {
        ::protovalidate_buffa::FieldPath {
            elements: ::std::vec![
                ::protovalidate_buffa::FieldPathElement {
                    field_number: Some(18i32),
                    field_name: Some(::std::borrow::Cow::Borrowed("repeated")),
                    field_type: Some(::protovalidate_buffa::FieldType::Message),
                    key_type: None,
                    value_type: None,
                    subscript: None,
                },
                ::protovalidate_buffa::FieldPathElement {
                    field_number: Some(#inner_num),
                    field_name: Some(::std::borrow::Cow::Borrowed(#inner)),
                    field_type: Some(::protovalidate_buffa::FieldType::#ty_ident),
                    key_type: None,
                    value_type: None,
                    subscript: None,
                },
            ],
        }
    }
}

fn map_field_path(name: &str, number: i32) -> TokenStream {
    quote! {
        ::protovalidate_buffa::FieldPath {
            elements: ::std::vec![
                ::protovalidate_buffa::FieldPathElement {
                    field_number: Some(#number),
                    field_name: Some(::std::borrow::Cow::Borrowed(#name)),
                    field_type: Some(::protovalidate_buffa::FieldType::Message),
                    key_type: None,
                    value_type: None,
                    subscript: None,
                },
            ],
        }
    }
}

fn map_rule_path(inner: &str, inner_num: i32) -> TokenStream {
    map_rule_path_ty(inner, inner_num, "Uint64")
}

fn map_rule_path_ty(inner: &str, inner_num: i32, ty: &str) -> TokenStream {
    let ty_ident = format_ident!("{}", ty);
    quote! {
        ::protovalidate_buffa::FieldPath {
            elements: ::std::vec![
                ::protovalidate_buffa::FieldPathElement {
                    field_number: Some(19i32),
                    field_name: Some(::std::borrow::Cow::Borrowed("map")),
                    field_type: Some(::protovalidate_buffa::FieldType::Message),
                    key_type: None,
                    value_type: None,
                    subscript: None,
                },
                ::protovalidate_buffa::FieldPathElement {
                    field_number: Some(#inner_num),
                    field_name: Some(::std::borrow::Cow::Borrowed(#inner)),
                    field_type: Some(::protovalidate_buffa::FieldType::#ty_ident),
                    key_type: None,
                    value_type: None,
                    subscript: None,
                },
            ],
        }
    }
}

// ─── repeated ────────────────────────────────────────────────────────────────

/// Emit the validation snippet for a `repeated` field.
///
/// Handles:
/// - `min_items` / `max_items` length checks.
/// - Standard and custom rules from `items` for every supported value type.
/// - Per-element message recursion (for message-typed elements).
///
/// # Errors
///
/// Returns an error if a nested enum type reference cannot be resolved.
///
/// # Panics
///
/// Panics if `min_items` or `max_items` cannot be converted to `usize`. In
/// practice proto length bounds are small non-negative integers, so this
/// invariant always holds.
pub fn emit_repeated(
    accessor: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    element_type_variant: &str,
    spec: &RepeatedStandard,
    element_kind: &FieldKind,
    schemas: &crate::emit::cel::SchemaIndex,
) -> Result<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    let fp = || repeated_field_path(name_lit, field_number, element_type_variant);

    if let Some(min) = spec.min_items {
        let min_usize = usize::try_from(min).expect("proto length bound fits in usize");
        let field = fp();
        let rule = repeated_rule_path("min_items", 1);
        out.push(quote! {
            if self.#accessor.len() < #min_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("repeated.min_items"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "list must contain at least {} items (got {})",
                        #min_usize, self.#accessor.len()
                    )),
                    for_key: false,
                });
            }
        });
    }

    if let Some(max) = spec.max_items {
        let max_usize = usize::try_from(max).expect("proto length bound fits in usize");
        let field = fp();
        let rule = repeated_rule_path("max_items", 2);
        out.push(quote! {
            if self.#accessor.len() > #max_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("repeated.max_items"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "list must contain at most {} items (got {})",
                        #max_usize, self.#accessor.len()
                    )),
                    for_key: false,
                });
            }
        });
    }

    if spec.unique == Some(true) && !matches!(element_kind, FieldKind::Message { .. }) {
        let field = fp();
        let rule = repeated_rule_path_ty("unique", 3, "Bool");
        let insert = if matches!(element_kind, FieldKind::Float | FieldKind::Double) {
            // CEL numeric equality: signed zeros match; NaN never matches itself.
            quote! {
                !item.is_nan() && !seen.insert(if *item == 0.0 { 0 } else { item.to_bits() })
            }
        } else {
            quote! { !seen.insert(item) }
        };
        out.push(quote! {
            {
                let mut seen = ::std::collections::HashSet::with_capacity(self.#accessor.len());
                let dup = self.#accessor.iter().any(|item| { #insert });
                if dup {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("repeated.unique"),
                        message: ::std::borrow::Cow::Borrowed("repeated value must contain unique items"),
                        for_key: false,
                    });
                }
            }
        });
    }

    let site =
        super::rule_site::RuleSite::repeated_item(name_lit, field_number, element_type_variant);
    let value = super::value::element_value(element_kind, &format_ident!("elem"));
    let checks = super::value::emit(
        element_kind,
        &value,
        spec.items.as_deref(),
        &site,
        super::value::Presence::Implicit,
        schemas,
    )?;
    if !checks.is_empty() {
        out.push(quote! { for (idx, elem) in self.#accessor.iter().enumerate() { #checks } });
    }
    Ok(quote! { #( #out )* })
}

// ─── map ─────────────────────────────────────────────────────────────────────

/// Emit the validation snippet for a `map` field.
///
/// Handles:
/// - `min_pairs` / `max_pairs` size checks.
/// - Per-key scalar rule application (`keys`).
/// - Per-value scalar rule application (`values`).
///
/// # Errors
///
/// Returns an error for an unsupported map key type or an unresolved nested
/// enum type reference.
///
/// # Panics
///
/// Panics if `min_pairs` or `max_pairs` cannot be converted to `usize`. In
/// practice proto size bounds are small non-negative integers, so this
/// invariant always holds.
pub fn emit_map(
    map: &TokenStream,
    name_lit: &str,
    field_number: i32,
    spec: &MapStandard,
    key_kind: &FieldKind,
    value_kind: &FieldKind,
    schemas: &crate::emit::cel::SchemaIndex,
) -> Result<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    let fp = || map_field_path(name_lit, field_number);

    if let Some(min) = spec.min_pairs {
        let min_usize = usize::try_from(min).expect("proto length bound fits in usize");
        let field = fp();
        let rule = map_rule_path("min_pairs", 1);
        out.push(quote! {
            if (#map).len() < #min_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("map.min_pairs"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "map must contain at least {} pairs (got {})",
                        #min_usize, (#map).len()
                    )),
                    for_key: false,
                });
            }
        });
    }

    if let Some(max) = spec.max_pairs {
        let max_usize = usize::try_from(max).expect("proto length bound fits in usize");
        let field = fp();
        let rule = map_rule_path("max_pairs", 2);
        out.push(quote! {
            if (#map).len() > #max_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("map.max_pairs"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "map must contain at most {} pairs (got {})",
                        #max_usize, (#map).len()
                    )),
                    for_key: false,
                });
            }
        });
    }

    let key_type = super::rule_site::kind_to_field_type(key_kind);
    let value_type = super::rule_site::kind_to_field_type(value_kind);
    let subscript = super::rule_site::kind_variant_to_subscript(key_type)
        .ok_or_else(|| anyhow::anyhow!("unsupported map key type: {key_type}"))?;
    let mut checks = Vec::new();
    for (side, kind, rules, ident) in [
        (
            super::rule_site::MapSide::Key,
            key_kind,
            spec.keys.as_deref(),
            format_ident!("key"),
        ),
        (
            super::rule_site::MapSide::Value,
            value_kind,
            spec.values.as_deref(),
            format_ident!("value"),
        ),
    ] {
        let site = super::rule_site::RuleSite::map_entry(
            name_lit,
            field_number,
            key_type,
            value_type,
            &subscript,
            side,
        );
        let value = super::value::element_value(kind, &ident);
        checks.push(super::value::emit(
            kind,
            &value,
            rules,
            &site,
            super::value::Presence::Implicit,
            schemas,
        )?);
    }
    if checks.iter().any(|check| !check.is_empty()) {
        out.push(quote! { for (key, value) in (#map).iter() { #( #checks )* } });
    }
    Ok(quote! { #( #out )* })
}
