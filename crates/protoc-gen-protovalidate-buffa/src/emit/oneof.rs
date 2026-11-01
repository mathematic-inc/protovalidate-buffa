//! Emit `impl Validate` blocks for oneof-level rules.

use anyhow::Result;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::scan::{FieldKind, FieldValidator, OneofValidator};

#[derive(Clone, Copy)]
enum Representation {
    Owned,
    View,
}

/// Emit the validation snippet for a single oneof.
///
/// Generates a `match &self.<oneof>` block that:
///   1. Checks `oneof.required` when the entire oneof is `None`.
///   2. For each variant that has per-field rules, emits those rules inside the
///      corresponding match arm so the value can be accessed directly.
///
/// # Errors
///
/// Returns an error if a variant's enum-rule type reference cannot be resolved
/// to a local Rust path. (Field/oneof names are escaped via
/// [`crate::emit::field_ident`], which is infallible.)
pub fn emit(v: &OneofValidator) -> Result<TokenStream> {
    emit_for(
        v,
        Representation::Owned,
        &crate::emit::cel::SchemaIndex::new(),
    )
}

pub(super) fn emit_with_schemas(
    v: &OneofValidator,
    shape: super::Shape,
    schemas: &super::cel::SchemaIndex,
) -> Result<TokenStream> {
    let representation = match shape {
        super::Shape::Owned => Representation::Owned,
        super::Shape::View => Representation::View,
    };
    emit_for(v, representation, schemas)
}

fn emit_for(
    v: &OneofValidator,
    representation: Representation,
    schemas: &super::cel::SchemaIndex,
) -> Result<TokenStream> {
    let has_required = v.required;
    let has_required_variants = v.fields.iter().any(|f| f.required);

    let accessor = crate::emit::field_ident(&v.rust_name);
    let name_lit = &v.name;

    // These are constant across all variants, so derive them once and pass them
    // down to the per-variant emitters.
    let module = module_path(&v.parent_msg_name);
    let oneof_enum_ident = crate::emit::field_ident(&to_pascal_case(&v.name));
    let oneof_root = match representation {
        Representation::Owned => quote! { __buffa::oneof },
        Representation::View => quote! { __buffa::view::oneof },
    };

    let none_arm = if has_required {
        quote! {
            None => {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::FieldPath {
                        elements: ::std::vec![
                            ::protovalidate_buffa::FieldPathElement {
                                field_number: None,
                                field_name: Some(::std::borrow::Cow::Borrowed(#name_lit)),
                                field_type: None,
                                key_type: None,
                                value_type: None,
                                subscript: None,
                            },
                        ],
                    },
                    rule: ::protovalidate_buffa::FieldPath::default(),
                    rule_id: ::std::borrow::Cow::Borrowed("required"),
                    message: ::std::borrow::Cow::Borrowed("at least one variant is required"),
                    for_key: false,
                });
            }
        }
    } else {
        quote! { None => {} }
    };

    // Let the shared value emitter decide which variants need validation.
    let some_arms: Vec<TokenStream> = v
        .fields
        .iter()
        .map(|f| emit_variant_arm(f, &oneof_root, &module, &oneof_enum_ident, schemas))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|ts| !ts.is_empty())
        .collect();

    // Compute required_variant_blocks early so they survive all early-return paths.
    let required_variant_blocks =
        emit_required_variant_blocks(v, &accessor, &oneof_root, &module, &oneof_enum_ident);

    // If no variant has rules, we only need the None check (already handled above).
    if some_arms.is_empty() && !has_required && !has_required_variants {
        return Ok(quote! {});
    }
    if some_arms.is_empty() && !has_required_variants {
        // Only oneof.required, no per-variant checks needed.
        return Ok(quote! {
            if self.#accessor.is_none() {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::FieldPath {
                        elements: ::std::vec![
                            ::protovalidate_buffa::FieldPathElement {
                                field_number: None,
                                field_name: Some(::std::borrow::Cow::Borrowed(#name_lit)),
                                field_type: None,
                                key_type: None,
                                value_type: None,
                                subscript: None,
                            },
                        ],
                    },
                    rule: ::protovalidate_buffa::FieldPath::default(),
                    rule_id: ::std::borrow::Cow::Borrowed("required"),
                    message: ::std::borrow::Cow::Borrowed("at least one variant is required"),
                    for_key: false,
                });
            }
        });
    }

    // Wildcard catch-all for variants we're not emitting arms for. Since
    // buffa's generated oneof enum includes every variant, we always need
    // to cover the ones that aren't explicitly handled above.
    let emitted_variant_count = some_arms.len();
    let has_catch_all = emitted_variant_count < v.fields.len();
    let catch_all = if has_catch_all {
        quote! { Some(_) => {} }
    } else {
        quote! {}
    };

    let match_block = if some_arms.is_empty() && !has_required {
        quote! {}
    } else {
        quote! {
            match &self.#accessor {
                #( #some_arms )*
                #catch_all
                #none_arm
            }
        }
    };
    Ok(quote! {
        #( #required_variant_blocks )*
        #match_block
    })
}

fn emit_required_variant_blocks(
    v: &OneofValidator,
    accessor: &syn::Ident,
    oneof_root: &TokenStream,
    module: &TokenStream,
    oneof_enum_ident: &syn::Ident,
) -> Vec<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    for f in &v.fields {
        if !f.required {
            continue;
        }
        if matches!(f.ignore, crate::scan::Ignore::Always) {
            continue;
        }
        let variant_name_str = to_pascal_case(&f.field_name);
        let variant_ident = crate::emit::field_ident(&variant_name_str);
        let name_lit = &f.field_name;
        let fnum = f.field_number;
        let field_ty = match f.field_type {
            FieldKind::String => quote!(String),
            FieldKind::Bytes => quote!(Bytes),
            FieldKind::Int32 => quote!(Int32),
            FieldKind::Int64 => quote!(Int64),
            FieldKind::Uint32 => quote!(Uint32),
            FieldKind::Uint64 => quote!(Uint64),
            FieldKind::Sint32 => quote!(Sint32),
            FieldKind::Sint64 => quote!(Sint64),
            FieldKind::Fixed32 => quote!(Fixed32),
            FieldKind::Fixed64 => quote!(Fixed64),
            FieldKind::Sfixed32 => quote!(Sfixed32),
            FieldKind::Sfixed64 => quote!(Sfixed64),
            FieldKind::Float => quote!(Float),
            FieldKind::Double => quote!(Double),
            FieldKind::Bool => quote!(Bool),
            FieldKind::Enum { .. } => quote!(Enum),
            FieldKind::Message { .. } | FieldKind::Wrapper(_) => quote!(Message),
            _ => quote!(Message),
        };
        out.push(quote! {
            if !matches!(&self.#accessor, Some(#oneof_root::#module::#oneof_enum_ident::#variant_ident(_))) {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::FieldPath {
                        elements: ::std::vec![
                            ::protovalidate_buffa::FieldPathElement {
                                field_number: Some(#fnum),
                                field_name: Some(::std::borrow::Cow::Borrowed(#name_lit)),
                                field_type: Some(::protovalidate_buffa::FieldType::#field_ty),
                                key_type: None,
                                value_type: None,
                                subscript: None,
                            },
                        ],
                    },
                    rule: ::protovalidate_buffa::FieldPath {
                        elements: ::std::vec![
                            ::protovalidate_buffa::FieldPathElement {
                                field_number: Some(25i32),
                                field_name: Some(::std::borrow::Cow::Borrowed("required")),
                                field_type: Some(::protovalidate_buffa::FieldType::Bool),
                                key_type: None,
                                value_type: None,
                                subscript: None,
                            },
                        ],
                    },
                    rule_id: ::std::borrow::Cow::Borrowed("required"),
                    message: ::std::borrow::Cow::Borrowed("field is required"),
                    for_key: false,
                });
            }
        });
    }
    out
}

/// Emit a `Some(Variant(v)) => { ... }` match arm for a single oneof field.
fn emit_variant_arm(
    f: &FieldValidator,
    oneof_root: &TokenStream,
    module: &TokenStream,
    oneof_enum_ident: &syn::Ident,
    schemas: &super::cel::SchemaIndex,
) -> Result<TokenStream> {
    let variant_ident = crate::emit::field_ident(&to_pascal_case(&f.field_name));
    let value = super::value::element_value(&f.field_type, &format_ident!("v"));
    let ty = if f.is_group {
        "Group"
    } else {
        super::rule_site::kind_to_field_type(&f.field_type)
    };
    let site = super::rule_site::RuleSite::field(&f.field_name, f.field_number, ty);
    let checks = super::value::emit(
        &f.field_type,
        &value,
        Some(f),
        &site,
        super::value::Presence::Explicit,
        schemas,
    )?;
    if checks.is_empty() {
        return Ok(TokenStream::new());
    }
    Ok(quote! {
        Some(#oneof_root::#module::#oneof_enum_ident::#variant_ident(v)) => { #checks }
    })
}

/// The module buffa generates for a message's oneof enums: one snake_case
/// segment per message, outermost first (`Outer.InnerMsg` → `outer::inner_msg`).
pub(super) fn module_path(parent_msg_name: &str) -> TokenStream {
    let segments = parent_msg_name
        .split('.')
        .map(|name| crate::emit::field_ident(&to_snake_case(name)));
    quote! { #(#segments)::* }
}

pub(super) fn to_snake_case(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len() + 2);
    for (i, &c) in chars.iter().enumerate() {
        if c.is_uppercase() && i > 0 {
            let prev = chars[i - 1];
            let next_is_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            if prev.is_lowercase() || (prev.is_uppercase() && next_is_lower) {
                out.push('_');
            }
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

/// Convert `snake_case` to `PascalCase` (for buffa enum variant/type names).
pub(super) fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|part| {
            let mut chars = part.chars();
            chars.next().map_or_else(String::new, |c| {
                c.to_uppercase().collect::<String>() + chars.as_str()
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::module_path;

    #[test]
    fn module_path_nests_one_snake_case_segment_per_message() {
        for (parent_msg_name, expected) in [
            ("CreateGradingRequest", "create_grading_request"),
            ("Outer.HTTPRequest.Type", "outer :: http_request :: r#type"),
        ] {
            assert_eq!(module_path(parent_msg_name).to_string(), expected);
        }
    }
}
