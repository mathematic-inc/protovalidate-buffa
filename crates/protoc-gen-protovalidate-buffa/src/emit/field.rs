//! Emit per-field validation code for scalar types, enums, bytes, repeated,
//! map, and message-field recursion.

use super::rule_site::{RuleSite, field_path_scalar, kind_to_field_type};
use anyhow::Result;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::scan::{FieldKind, FieldValidator, Ignore};

/// Emit the validation snippet for a single field.
///
/// Returns an empty `TokenStream` when the field is `Ignore::Always`, when
/// no rules are configured for it, or when the field belongs to a oneof
/// (oneof-member field rules are emitted inside the oneof match arm instead).
///
/// # Errors
///
/// Returns an error if an enum type reference cannot be resolved to a local
/// Rust path (e.g. nested types not yet supported), or if a repeated/map
/// sub-field emitter fails.
#[expect(
    clippy::too_many_lines,
    reason = "codegen helper — one branch per FieldKind; splitting hurts readability"
)]
pub(crate) fn emit(
    field: &FieldValidator,
    schemas: &crate::emit::cel::SchemaIndex,
    shape: crate::emit::Shape,
) -> Result<TokenStream> {
    if matches!(field.ignore, Ignore::Always) {
        return Ok(quote! {});
    }
    // Oneof-member fields are NOT flat struct fields in buffa's generated code.
    // Their validation is emitted inside the oneof enum match arm in oneof.rs.
    if field.oneof_name.is_some() {
        return Ok(quote! {});
    }

    let accessor = crate::emit::field_ident(&field.rust_name);
    let name_lit = &field.field_name;
    let mut blocks: Vec<TokenStream> = Vec::new();

    let required_block: Option<TokenStream> = if field.required && !field.is_legacy_required {
        Some(emit_required(
            &accessor,
            name_lit,
            field.field_number,
            &field.field_type,
            field.is_group,
        ))
    } else {
        None
    };

    match &field.field_type {
        FieldKind::Repeated(inner) => {
            let default = crate::scan::RepeatedStandard {
                min_items: None,
                max_items: None,
                unique: None,
                items: None,
            };
            blocks.push(super::repeated::emit_repeated(
                &accessor,
                name_lit,
                field.field_number,
                kind_to_field_type(inner),
                field.standard.repeated.as_ref().unwrap_or(&default),
                inner,
                schemas,
            )?);
        }
        FieldKind::Map { key, value } => {
            let default = crate::scan::MapStandard {
                min_pairs: None,
                max_pairs: None,
                keys: None,
                values: None,
            };
            let map = shape.map_access(&accessor, field.field_number);
            blocks.push(super::repeated::emit_map(
                &map,
                name_lit,
                field.field_number,
                field.standard.map.as_ref().unwrap_or(&default),
                key,
                value,
                schemas,
            )?);
        }
        FieldKind::Optional(inner) => {
            let site = RuleSite::field(name_lit, field.field_number, kind_to_field_type(inner));
            let checks = super::value::emit(
                inner,
                &quote! { v },
                Some(field),
                &site,
                super::value::Presence::Explicit,
                schemas,
            )?;
            let access = if matches!(inner.as_ref(), FieldKind::String | FieldKind::Bytes) {
                quote! { self.#accessor.as_deref() }
            } else {
                quote! { self.#accessor }
            };
            blocks.push(quote! { if let Some(v) = #access { #checks } });
        }
        FieldKind::Message { .. } | FieldKind::Wrapper(_) => {
            let ty = if field.is_group { "Group" } else { "Message" };
            let site = RuleSite::field(name_lit, field.field_number, ty);
            let checks = super::value::emit(
                &field.field_type,
                &quote! { inner },
                Some(field),
                &site,
                super::value::Presence::Explicit,
                schemas,
            )?;
            blocks.push(quote! { if let Some(inner) = self.#accessor.as_option() { #checks } });
        }
        kind => {
            let site = RuleSite::field(name_lit, field.field_number, kind_to_field_type(kind));
            // The field-level guard below also coordinates required semantics.
            blocks.push(super::value::emit(
                kind,
                &quote! { self.#accessor },
                Some(field),
                &site,
                super::value::Presence::Explicit,
                schemas,
            )?);
        }
    }

    if matches!(
        field.field_type,
        FieldKind::Repeated(_) | FieldKind::Map { .. }
    ) {
        let ty = match &field.field_type {
            FieldKind::Repeated(inner) => kind_to_field_type(inner),
            kind => kind_to_field_type(kind),
        };
        let site = RuleSite::field(name_lit, field.field_number, ty);
        blocks.extend(super::value::emit_custom(
            &field.field_type,
            field,
            &site,
            schemas,
            super::cel::collection_binding(field, &accessor, schemas, shape),
        ));
    }

    // IGNORE_IF_ZERO_VALUE: wrap all rule checks in a zero-value guard so
    // that default values bypass every constraint. The exact guard depends
    // on the field kind (`is_empty()` for string/bytes/repeated/map,
    // `!= 0/0.0/false` for scalars).
    if matches!(field.ignore, Ignore::IfZeroValue)
        && !field.is_legacy_required
        && let Some(g) = nonzero_guard(&field.field_type, &accessor)
    {
        return Ok(quote! {
            if #g {
                #( #blocks )*
            }
        });
    }

    // When `required` is set, the other rules should only run when the value
    // is present (i.e. non-default). This mirrors protovalidate's semantics:
    // a default-valued required field reports `required` and nothing else.
    if let Some(req) = required_block {
        let guard = match &field.field_type {
            FieldKind::Message { .. } | FieldKind::Wrapper(_) => {
                Some(quote! { self.#accessor.is_set() })
            }
            FieldKind::Optional(_) => Some(quote! { self.#accessor.is_some() }),
            _ => nonzero_guard(&field.field_type, &accessor),
        };
        return Ok(guard.map_or_else(
            || quote! { #req #( #blocks )* },
            |g| quote! { #req if #g { #( #blocks )* } },
        ));
    }

    Ok(quote! { #( #blocks )* })
}

/// Test the zero value of a field that does not track presence.
/// Optional, wrapper, and message fields use their own presence checks.
pub(super) fn nonzero_guard(kind: &FieldKind, accessor: &syn::Ident) -> Option<TokenStream> {
    super::value::nonzero_guard(kind, &quote! { self.#accessor })
}

fn emit_required(
    accessor: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    kind: &FieldKind,
    is_group: bool,
) -> TokenStream {
    // required is FieldRules.required = 25 (TYPE_BOOL).
    let required_rule = rule_path_scalar_single("required", 25, "Bool");
    let field_ty = if is_group {
        "Group"
    } else {
        match kind {
            FieldKind::String => "String",
            FieldKind::Bytes => "Bytes",
            FieldKind::Int32 => "Int32",
            FieldKind::Int64 => "Int64",
            FieldKind::Uint32 => "Uint32",
            FieldKind::Uint64 => "Uint64",
            FieldKind::Sint32 => "Sint32",
            FieldKind::Sint64 => "Sint64",
            FieldKind::Fixed32 => "Fixed32",
            FieldKind::Fixed64 => "Fixed64",
            FieldKind::Sfixed32 => "Sfixed32",
            FieldKind::Sfixed64 => "Sfixed64",
            FieldKind::Float => "Float",
            FieldKind::Double => "Double",
            FieldKind::Bool => "Bool",
            FieldKind::Enum { .. } => "Enum",
            FieldKind::Message { .. } | FieldKind::Wrapper(_) => "Message",
            // For repeated/map fields the path's field_type is the *element* type
            // (protovalidate treats the repeatedness as implicit).
            FieldKind::Repeated(inner) => kind_to_field_type(inner),
            FieldKind::Map { .. } => "Message",
            FieldKind::Optional(inner) => kind_to_field_type(inner),
        }
    };
    let field_path = field_path_scalar(name_lit, field_number, field_ty);
    match kind {
        FieldKind::String | FieldKind::Bytes | FieldKind::Repeated(_) | FieldKind::Map { .. } => {
            quote! {
                if self.#accessor.is_empty() {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field_path,
                        rule: #required_rule,
                        rule_id: ::std::borrow::Cow::Borrowed("required"),
                        message: ::std::borrow::Cow::Borrowed("value is required"),
                        for_key: false,
                    });
                }
            }
        }
        FieldKind::Message { .. } | FieldKind::Wrapper(_) => quote! {
            if !self.#accessor.is_set() {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field_path,
                    rule: #required_rule,
                    rule_id: ::std::borrow::Cow::Borrowed("required"),
                    message: ::std::borrow::Cow::Borrowed("value is required"),
                    for_key: false,
                });
            }
        },
        FieldKind::Optional(_) => quote! {
            if self.#accessor.is_none() {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field_path,
                    rule: #required_rule,
                    rule_id: ::std::borrow::Cow::Borrowed("required"),
                    message: ::std::borrow::Cow::Borrowed("value is required"),
                    for_key: false,
                });
            }
        },
        // Scalars (int32, float, bool, enum, etc.) use IfZeroValue semantics for
        // "required" — a zero-value scalar (0, 0.0, false, etc.) is considered
        // absent. Since proto3 always initialises to zero, we cannot distinguish
        // "not set" from "set to zero" without proto3 optional. Emit no check for
        // plain scalar required; the caller should use proto3 optional or oneof
        // required instead.
        FieldKind::Int32
        | FieldKind::Int64
        | FieldKind::Uint32
        | FieldKind::Uint64
        | FieldKind::Sint32
        | FieldKind::Sint64
        | FieldKind::Fixed32
        | FieldKind::Fixed64
        | FieldKind::Sfixed32
        | FieldKind::Sfixed64
        | FieldKind::Float
        | FieldKind::Double
        | FieldKind::Bool
        | FieldKind::Enum { .. } => quote! {},
    }
}

/// Single-element FieldPath for a rule path where there is no outer
/// message field (e.g. `required` lives directly on FieldRules as a bool).
fn rule_path_scalar_single(name: &str, number: i32, ty: &str) -> TokenStream {
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

// Preserve the public numeric helpers at their original module path.
pub use super::scalar::{
    emit_double_on_pub, emit_float_on_pub, emit_int32_on_pub, emit_int64_on_pub,
    emit_uint32_on_pub, emit_uint64_on_pub,
};
