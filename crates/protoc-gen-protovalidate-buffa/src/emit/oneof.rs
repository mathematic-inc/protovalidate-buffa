//! Emit `impl Validate` blocks for oneof-level rules.

use anyhow::Result;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::parse_str;

use crate::scan::{FieldKind, FieldValidator, OneofValidator};

/// Emit the validation snippet for a single oneof.
///
/// Generates a `match &self.<oneof>` block that:
///   1. Checks `oneof.required` when the entire oneof is `None`.
///   2. For each variant that has per-field rules, emits those rules inside the
///      corresponding match arm so the value can be accessed directly.
///
/// # Errors
///
/// Returns an error if the oneof name or a variant field name cannot be parsed
/// as a valid Rust identifier (e.g. contains characters not allowed in identifiers).
pub fn emit(v: &OneofValidator) -> Result<TokenStream> {
    let has_required = v.required;
    // If nothing to emit at all, skip.
    let has_variant_rules = v.fields.iter().any(has_field_rules);
    let has_required_variants = v.fields.iter().any(|f| f.required);
    if !has_required && !has_variant_rules && !has_required_variants {
        return Ok(quote! {});
    }

    let accessor = parse_str::<syn::Ident>(&v.name)?;
    let name_lit = &v.name;

    // The module name buffa generates for a message's oneof is the snake_case of
    // the parent message name, e.g. `CreateGradingRequest` → `create_grading_request`.
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

    // Filter out variants that have no rules (they'd generate empty arms).
    // Also drop any arm whose emission came back empty (e.g. a message-typed
    // variant where recursion is skipped for WKT / cross-package reasons).
    let some_arms: Vec<TokenStream> = v
        .fields
        .iter()
        .filter(|f| has_field_rules(f))
        .map(|f| emit_variant_arm(v, f))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|ts| !ts.is_empty())
        .collect();

    // Compute required_variant_blocks early so they survive all early-return paths.
    let required_variant_blocks = emit_required_variant_blocks(v)?;

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

fn emit_required_variant_blocks(v: &OneofValidator) -> Result<Vec<TokenStream>> {
    let mut out: Vec<TokenStream> = Vec::new();
    let accessor = parse_str::<syn::Ident>(&v.name)?;
    for f in &v.fields {
        if !f.required {
            continue;
        }
        if matches!(f.ignore, crate::scan::Ignore::Always) {
            continue;
        }
        let module_name_str = to_snake_case(&v.parent_msg_name);
        let module_ident: syn::Ident = parse_str(&module_name_str)?;
        let oneof_enum_str = to_pascal_case(&v.name);
        let oneof_enum_ident: syn::Ident = parse_str(&oneof_enum_str)?;
        let variant_name_str = to_pascal_case(&f.field_name);
        let variant_ident: syn::Ident = parse_str(&variant_name_str)?;
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
            if !matches!(&self.#accessor, Some(__buffa::oneof::#module_ident::#oneof_enum_ident::#variant_ident(_))) {
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
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        });
    }
    Ok(out)
}

/// Returns true if a field has any rules that produce emitted checks.
fn has_field_rules(f: &FieldValidator) -> bool {
    f.required
        || f.standard.string.is_some()
        || f.standard.bytes.is_some()
        || f.standard.int32.is_some()
        || f.standard.int64.is_some()
        || f.standard.uint32.is_some()
        || f.standard.uint64.is_some()
        || f.standard.float.is_some()
        || f.standard.double.is_some()
        || !f.cel.is_empty()
        || matches!(f.field_type, FieldKind::Message { ref full_name } if !full_name.starts_with("google.protobuf."))
}

/// Emit a `Some(Variant(ref v)) => { ... }` match arm for a single oneof field.
fn emit_variant_arm(v: &OneofValidator, f: &FieldValidator) -> Result<TokenStream> {
    if matches!(f.ignore, crate::scan::Ignore::Always) {
        return Ok(quote! {});
    }
    let module_name_str = to_snake_case(&v.parent_msg_name);
    let module_ident = parse_str::<syn::Ident>(&module_name_str)?;
    let oneof_enum_str = to_pascal_case(&v.name);
    let oneof_enum_ident = parse_str::<syn::Ident>(&oneof_enum_str)?;

    // Buffa's variant name: PascalCase of the field name.
    let variant_name_str = to_pascal_case(&f.field_name);
    let variant_ident = parse_str::<syn::Ident>(&variant_name_str)?;

    let name_lit = &f.field_name;
    let val_ident = format_ident!("v");

    // Emit field rules using `v` as the accessor.
    let mut checks: Vec<TokenStream> = Vec::new();
    match &f.field_type {
        FieldKind::String => {
            if let Some(s) = &f.standard.string {
                checks.extend(crate::emit::field::emit_string_checks_on(
                    &val_ident,
                    name_lit,
                    f.field_number,
                    s,
                ));
            }
        }
        FieldKind::Int32
        | FieldKind::Sint32
        | FieldKind::Sfixed32
        | FieldKind::Int64
        | FieldKind::Sint64
        | FieldKind::Sfixed64
        | FieldKind::Uint32
        | FieldKind::Fixed32
        | FieldKind::Uint64
        | FieldKind::Fixed64
        | FieldKind::Float
        | FieldKind::Double => {
            checks.extend(crate::emit::field::emit_numeric_checks_on(
                &val_ident,
                name_lit,
                f.field_number,
                &f.field_type,
                &f.standard,
            ));
        }
        FieldKind::Message { full_name } if !full_name.starts_with("google.protobuf.") => {
            let fnum = f.field_number;
            let nlit = name_lit.clone();
            checks.push(quote! {
                if let Err(sub) = #val_ident.validate() {
                    violations.extend(sub.violations.into_iter().map(|mut v| {
                        v.field.elements.insert(0, ::protovalidate_buffa::FieldPathElement {
                            field_number: Some(#fnum),
                            field_name: Some(::std::borrow::Cow::Borrowed(#nlit)),
                            field_type: Some(::protovalidate_buffa::FieldType::Message),
                            key_type: None,
                            value_type: None,
                            subscript: None,
                        });
                        v
                    }));
                }
            });
        }
        _ => {}
    }

    if checks.is_empty() {
        // Arm with no checks — return a wildcard so caller can decide.
        return Ok(quote! {});
    }

    // For Copy scalar types the helpers operate on an owned `v: T`. Deref
    // via an intermediate `let` so the checks can compare directly without
    // needing `*v` at every call site.
    let needs_copy_deref = matches!(
        f.field_type,
        FieldKind::Int32
            | FieldKind::Sint32
            | FieldKind::Sfixed32
            | FieldKind::Int64
            | FieldKind::Sint64
            | FieldKind::Sfixed64
            | FieldKind::Uint32
            | FieldKind::Fixed32
            | FieldKind::Uint64
            | FieldKind::Fixed64
            | FieldKind::Float
            | FieldKind::Double
            | FieldKind::Bool
    );
    if needs_copy_deref {
        Ok(quote! {
            Some(__buffa::oneof::#module_ident::#oneof_enum_ident::#variant_ident(ref __oneof_val)) => {
                let #val_ident = *__oneof_val;
                #( #checks )*
            }
        })
    } else {
        Ok(quote! {
            Some(__buffa::oneof::#module_ident::#oneof_enum_ident::#variant_ident(ref #val_ident)) => {
                #( #checks )*
            }
        })
    }
}

/// Emit string field checks using an explicit `value_ident` instead of `self.<field>`.
fn to_snake_case(s: &str) -> String {
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
fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|part| {
            let mut chars = part.chars();
            chars.next().map_or_else(String::new, |c| {
                c.to_uppercase().collect::<String>() + chars.as_str()
            })
        })
        .collect()
}
