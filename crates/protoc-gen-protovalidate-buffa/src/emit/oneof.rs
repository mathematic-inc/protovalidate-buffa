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
        || f.standard.bool_rules.is_some()
        || f.standard.enum_rules.is_some()
        || f.standard.int32.is_some()
        || f.standard.int64.is_some()
        || f.standard.uint32.is_some()
        || f.standard.uint64.is_some()
        || f.standard.float.is_some()
        || f.standard.double.is_some()
        || f.standard.any_rules.is_some()
        || f.standard.duration.is_some()
        || f.standard.timestamp.is_some()
        || f.standard.field_mask.is_some()
        || !f.standard.predefined.is_empty()
        || !f.cel.is_empty()
        || matches!(f.field_type, FieldKind::Message { ref full_name } if !full_name.starts_with("google.protobuf."))
}

/// Emit a `Some(Variant(v)) => { ... }` match arm for a single oneof field.
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
        FieldKind::Bytes => {
            if let Some(b) = &f.standard.bytes {
                checks.extend(crate::emit::field::emit_bytes_checks_on(
                    &val_ident,
                    name_lit,
                    f.field_number,
                    b,
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
        FieldKind::Bool => {
            if let Some(b) = &f.standard.bool_rules {
                checks.extend(crate::emit::field::emit_bool_checks_on(
                    &val_ident,
                    name_lit,
                    f.field_number,
                    b,
                ));
            }
        }
        FieldKind::Enum { full_name } => {
            if let Some(e) = &f.standard.enum_rules {
                checks.extend(crate::emit::field::emit_enum_checks_on(
                    &val_ident,
                    name_lit,
                    f.field_number,
                    e,
                    full_name,
                )?);
            }
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
        FieldKind::Message { full_name } => {
            checks.extend(emit_oneof_wkt_checks(f, full_name, &val_ident));
        }
        FieldKind::Wrapper(inner) => {
            let inner_checks =
                crate::emit::field::emit_wrapper_inner(name_lit, f.field_number, inner, f);
            if !inner_checks.is_empty() {
                checks.push(quote! {
                    {
                        let v = v.value.clone();
                        #( #inner_checks )*
                    }
                });
            }
        }
        _ => {}
    }

    checks.extend(emit_oneof_field_cel(f));
    checks.extend(emit_oneof_predefined(f));

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
            Some(__buffa::oneof::#module_ident::#oneof_enum_ident::#variant_ident(__oneof_val)) => {
                let #val_ident = *__oneof_val;
                #( #checks )*
            }
        })
    } else {
        Ok(quote! {
            Some(__buffa::oneof::#module_ident::#oneof_enum_ident::#variant_ident(#val_ident)) => {
                #( #checks )*
            }
        })
    }
}

/// Emit string field checks using an explicit `value_ident` instead of `self.<field>`.
fn emit_oneof_field_cel(f: &FieldValidator) -> Vec<TokenStream> {
    if f.cel.is_empty() {
        return Vec::new();
    }
    if let FieldKind::Message { full_name } = &f.field_type
        && crate::emit::cel::is_unsupported_wkt_for_cel(full_name)
    {
        return Vec::new();
    }
    f.cel
        .iter()
        .map(|rule| {
            crate::emit::cel::emit_runtime_error_violation(
                &rule.id,
                &format!("unsupported CEL (oneof): {}", rule.expression),
            )
        })
        .collect()
}

fn emit_oneof_predefined(f: &FieldValidator) -> Vec<TokenStream> {
    f.standard
        .predefined
        .iter()
        .map(|rule| {
            crate::emit::cel::emit_runtime_error_violation(
                &rule.id,
                &format!("unsupported predefined CEL (oneof): {}", rule.expression),
            )
        })
        .collect()
}

#[expect(
    clippy::too_many_lines,
    reason = "codegen helper mirrors the WKT rule families oneof members can carry"
)]
fn emit_oneof_wkt_checks(
    f: &FieldValidator,
    full_name: &str,
    val_ident: &syn::Ident,
) -> Vec<TokenStream> {
    let mut out = Vec::new();
    let field_path = oneof_field_path(f);

    if full_name == "google.protobuf.Any"
        && let Some(any) = &f.standard.any_rules
    {
        if !any.in_set.is_empty() {
            let set = &any.in_set;
            let field = &field_path;
            let rule = oneof_rule_path("any", 20, "in", 2, "String");
            out.push(quote! {
                {
                    const ALLOWED: &[&str] = &[ #( #set ),* ];
                    if !ALLOWED.iter().any(|s| *s == #val_ident.type_url.as_str()) {
                        violations.push(::protovalidate_buffa::Violation {
                            field: #field,
                            rule: #rule,
                            rule_id: ::std::borrow::Cow::Borrowed("any.in"),
                            message: ::std::borrow::Cow::Borrowed(""),
                            for_key: false,
                        });
                    }
                }
            });
        }
        if !any.not_in.is_empty() {
            let set = &any.not_in;
            let field = &field_path;
            let rule = oneof_rule_path("any", 20, "not_in", 3, "String");
            out.push(quote! {
                {
                    const DISALLOWED: &[&str] = &[ #( #set ),* ];
                    if DISALLOWED.iter().any(|s| *s == #val_ident.type_url.as_str()) {
                        violations.push(::protovalidate_buffa::Violation {
                            field: #field,
                            rule: #rule,
                            rule_id: ::std::borrow::Cow::Borrowed("any.not_in"),
                            message: ::std::borrow::Cow::Borrowed(""),
                            for_key: false,
                        });
                    }
                }
            });
        }
    }

    if full_name == "google.protobuf.FieldMask"
        && let Some(field_mask) = &f.standard.field_mask
    {
        if let Some(expected) = &field_mask.r#const {
            let expected_lits = expected.iter().map(String::as_str);
            let message = format!("must equal paths [{}]", expected.join(", "));
            let field = &field_path;
            let rule = oneof_rule_path("field_mask", 28, "const", 1, "Message");
            out.push(quote! {
                {
                    const EXPECTED: &[&str] = &[ #( #expected_lits ),* ];
                    let actual: ::std::vec::Vec<&str> = #val_ident.paths.iter().map(|s| s.as_str()).collect();
                    let eq = actual.len() == EXPECTED.len()
                        && actual.iter().zip(EXPECTED.iter()).all(|(a, b)| a == b);
                    if !eq {
                        violations.push(::protovalidate_buffa::Violation {
                            field: #field,
                            rule: #rule,
                            rule_id: ::std::borrow::Cow::Borrowed("field_mask.const"),
                            message: ::std::borrow::Cow::Borrowed(#message),
                            for_key: false,
                        });
                    }
                }
            });
        }
        if !field_mask.in_set.is_empty() {
            let allowed = field_mask.in_set.iter().map(String::as_str);
            let field = &field_path;
            let rule = oneof_rule_path("field_mask", 28, "in", 2, "String");
            out.push(quote! {
                {
                    const ALLOWED: &[&str] = &[ #( #allowed ),* ];
                    let ok = #val_ident.paths.iter().all(|p| {
                        ALLOWED.iter().any(|c| ::protovalidate_buffa::rules::string::fieldmask_covers(c, p.as_str()))
                    });
                    if !ok {
                        violations.push(::protovalidate_buffa::Violation {
                            field: #field,
                            rule: #rule,
                            rule_id: ::std::borrow::Cow::Borrowed("field_mask.in"),
                            message: ::std::borrow::Cow::Borrowed(""),
                            for_key: false,
                        });
                    }
                }
            });
        }
        if !field_mask.not_in.is_empty() {
            let denied = field_mask.not_in.iter().map(String::as_str);
            let field = &field_path;
            let rule = oneof_rule_path("field_mask", 28, "not_in", 3, "String");
            out.push(quote! {
                {
                    const DENIED: &[&str] = &[ #( #denied ),* ];
                    let bad = #val_ident.paths.iter().any(|p| {
                        DENIED.iter().any(|c| ::protovalidate_buffa::rules::string::fieldmask_covers(c, p.as_str())
                            || ::protovalidate_buffa::rules::string::fieldmask_covers(p.as_str(), c))
                    });
                    if bad {
                        violations.push(::protovalidate_buffa::Violation {
                            field: #field,
                            rule: #rule,
                            rule_id: ::std::borrow::Cow::Borrowed("field_mask.not_in"),
                            message: ::std::borrow::Cow::Borrowed(""),
                            for_key: false,
                        });
                    }
                }
            });
        }
    }

    if full_name == "google.protobuf.Duration"
        && let Some(duration) = &f.standard.duration
    {
        out.extend(emit_oneof_duration_checks(duration, val_ident, &field_path));
    }

    if full_name == "google.protobuf.Timestamp"
        && let Some(timestamp) = &f.standard.timestamp
    {
        out.extend(emit_oneof_timestamp_checks(
            timestamp,
            val_ident,
            &field_path,
        ));
    }

    out
}

fn oneof_rule_path(
    outer_name: &str,
    outer_number: i32,
    inner_name: &str,
    inner_number: i32,
    inner_type_variant: &str,
) -> TokenStream {
    let inner_ty = format_ident!("{}", inner_type_variant);
    quote! {
        ::protovalidate_buffa::FieldPath {
            elements: ::std::vec![
                ::protovalidate_buffa::FieldPathElement {
                    field_number: Some(#outer_number),
                    field_name: Some(::std::borrow::Cow::Borrowed(#outer_name)),
                    field_type: Some(::protovalidate_buffa::FieldType::Message),
                    key_type: None,
                    value_type: None,
                    subscript: None,
                },
                ::protovalidate_buffa::FieldPathElement {
                    field_number: Some(#inner_number),
                    field_name: Some(::std::borrow::Cow::Borrowed(#inner_name)),
                    field_type: Some(::protovalidate_buffa::FieldType::#inner_ty),
                    key_type: None,
                    value_type: None,
                    subscript: None,
                },
            ],
        }
    }
}

fn duration_nanos_literal(value: (i64, i32)) -> TokenStream {
    let total = (value.0 as i128) * 1_000_000_000 + (value.1 as i128);
    let total_i128 = proc_macro2::Literal::i128_suffixed(total);
    quote! { #total_i128 }
}

const fn duration_nanos_lt(left: (i64, i32), right: (i64, i32)) -> bool {
    let left_ns = (left.0 as i128) * 1_000_000_000 + (left.1 as i128);
    let right_ns = (right.0 as i128) * 1_000_000_000 + (right.1 as i128);
    left_ns < right_ns
}

fn emit_oneof_duration_checks(
    duration: &crate::scan::DurationStandard,
    val_ident: &syn::Ident,
    field_path: &TokenStream,
) -> Vec<TokenStream> {
    let actual =
        quote! { ((#val_ident.seconds as i128) * 1_000_000_000 + (#val_ident.nanos as i128)) };
    emit_oneof_time_checks(
        "duration",
        21,
        duration.r#const,
        duration.lt,
        duration.lte,
        duration.gt,
        duration.gte,
        &duration.in_set,
        &duration.not_in,
        None,
        None,
        None,
        &actual,
        field_path,
    )
}

fn emit_oneof_timestamp_checks(
    timestamp: &crate::scan::TimestampStandard,
    val_ident: &syn::Ident,
    field_path: &TokenStream,
) -> Vec<TokenStream> {
    let actual =
        quote! { ((#val_ident.seconds as i128) * 1_000_000_000 + (#val_ident.nanos as i128)) };
    emit_oneof_time_checks(
        "timestamp",
        22,
        timestamp.r#const,
        timestamp.lt,
        timestamp.lte,
        timestamp.gt,
        timestamp.gte,
        &[],
        &[],
        Some(timestamp.lt_now),
        Some(timestamp.gt_now),
        timestamp.within,
        &actual,
        field_path,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "shared codegen helper for DurationRules and TimestampRules"
)]
fn emit_oneof_time_checks(
    family: &'static str,
    family_number: i32,
    const_value: Option<(i64, i32)>,
    lt: Option<(i64, i32)>,
    lte: Option<(i64, i32)>,
    gt: Option<(i64, i32)>,
    gte: Option<(i64, i32)>,
    in_set: &[(i64, i32)],
    not_in: &[(i64, i32)],
    lt_now: Option<bool>,
    gt_now: Option<bool>,
    within: Option<(i64, i32)>,
    actual: &TokenStream,
    field_path: &TokenStream,
) -> Vec<TokenStream> {
    let mut out = Vec::new();
    let push = |out: &mut Vec<TokenStream>,
                inner: &str,
                inner_num: i32,
                inner_ty: &str,
                rule_id: &'static str,
                cond: TokenStream| {
        let field = field_path.clone();
        let rule = oneof_rule_path(family, family_number, inner, inner_num, inner_ty);
        out.push(quote! {
            if #cond {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field,
                    rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        });
    };

    if let (Some(lo), Some(hi)) = (gt, lt) {
        let lo_ns = duration_nanos_literal(lo);
        let hi_ns = duration_nanos_literal(hi);
        let is_exclusive = duration_nanos_lt(hi, lo);
        let rule_id = if family == "duration" {
            if is_exclusive {
                "duration.gt_lt_exclusive"
            } else {
                "duration.gt_lt"
            }
        } else if is_exclusive {
            "timestamp.gt_lt_exclusive"
        } else {
            "timestamp.gt_lt"
        };
        let cond = if is_exclusive {
            quote! { #actual >= #hi_ns && #actual <= #lo_ns }
        } else {
            quote! { #actual <= #lo_ns || #actual >= #hi_ns }
        };
        push(&mut out, "gt", 5, "Message", rule_id, cond);
        return out;
    }
    if let (Some(lo), Some(hi)) = (gte, lte) {
        let lo_ns = duration_nanos_literal(lo);
        let hi_ns = duration_nanos_literal(hi);
        let is_exclusive = duration_nanos_lt(hi, lo);
        let rule_id = if family == "duration" {
            if is_exclusive {
                "duration.gte_lte_exclusive"
            } else {
                "duration.gte_lte"
            }
        } else if is_exclusive {
            "timestamp.gte_lte_exclusive"
        } else {
            "timestamp.gte_lte"
        };
        let cond = if is_exclusive {
            quote! { #actual > #hi_ns && #actual < #lo_ns }
        } else {
            quote! { #actual < #lo_ns || #actual > #hi_ns }
        };
        push(&mut out, "gte", 6, "Message", rule_id, cond);
        return out;
    }

    if let Some(value) = const_value {
        let expected = duration_nanos_literal(value);
        let rule_id = if family == "duration" {
            "duration.const"
        } else {
            "timestamp.const"
        };
        push(
            &mut out,
            "const",
            2,
            "Message",
            rule_id,
            quote! { #actual != #expected },
        );
    }
    if let Some(value) = lt {
        let bound = duration_nanos_literal(value);
        let rule_id = if family == "duration" {
            "duration.lt"
        } else {
            "timestamp.lt"
        };
        push(
            &mut out,
            "lt",
            3,
            "Message",
            rule_id,
            quote! { #actual >= #bound },
        );
    }
    if let Some(value) = lte {
        let bound = duration_nanos_literal(value);
        let rule_id = if family == "duration" {
            "duration.lte"
        } else {
            "timestamp.lte"
        };
        push(
            &mut out,
            "lte",
            4,
            "Message",
            rule_id,
            quote! { #actual > #bound },
        );
    }
    if let Some(value) = gt {
        let bound = duration_nanos_literal(value);
        let rule_id = if family == "duration" {
            "duration.gt"
        } else {
            "timestamp.gt"
        };
        push(
            &mut out,
            "gt",
            5,
            "Message",
            rule_id,
            quote! { #actual <= #bound },
        );
    }
    if let Some(value) = gte {
        let bound = duration_nanos_literal(value);
        let rule_id = if family == "duration" {
            "duration.gte"
        } else {
            "timestamp.gte"
        };
        push(
            &mut out,
            "gte",
            6,
            "Message",
            rule_id,
            quote! { #actual < #bound },
        );
    }
    if !in_set.is_empty() {
        let values: Vec<TokenStream> = in_set.iter().copied().map(duration_nanos_literal).collect();
        let field = field_path.clone();
        let rule = oneof_rule_path(family, family_number, "in", 7, "Message");
        out.push(quote! {
            {
                const ALLOWED: &[i128] = &[ #( #values ),* ];
                if !ALLOWED.iter().any(|x| *x == #actual) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field,
                        rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("duration.in"),
                        message: ::std::borrow::Cow::Borrowed(""),
                        for_key: false,
                    });
                }
            }
        });
    }
    if !not_in.is_empty() {
        let values: Vec<TokenStream> = not_in.iter().copied().map(duration_nanos_literal).collect();
        let field = field_path.clone();
        let rule = oneof_rule_path(family, family_number, "not_in", 8, "Message");
        out.push(quote! {
            {
                const DISALLOWED: &[i128] = &[ #( #values ),* ];
                if DISALLOWED.iter().any(|x| *x == #actual) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field,
                        rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("duration.not_in"),
                        message: ::std::borrow::Cow::Borrowed(""),
                        for_key: false,
                    });
                }
            }
        });
    }
    if lt_now == Some(true) {
        push(
            &mut out,
            "lt_now",
            7,
            "Bool",
            "timestamp.lt_now",
            quote! {
                #actual >= ::std::time::SystemTime::now()
                    .duration_since(::std::time::UNIX_EPOCH)
                    .map_or(0i128, |d| d.as_nanos() as i128)
            },
        );
    }
    if gt_now == Some(true) {
        push(
            &mut out,
            "gt_now",
            8,
            "Bool",
            "timestamp.gt_now",
            quote! {
                #actual <= ::std::time::SystemTime::now()
                    .duration_since(::std::time::UNIX_EPOCH)
                    .map_or(0i128, |d| d.as_nanos() as i128)
            },
        );
    }
    if let Some(value) = within {
        let bound = duration_nanos_literal(value);
        push(
            &mut out,
            "within",
            9,
            "Message",
            "timestamp.within",
            quote! {
                {
                    let now_ns = ::std::time::SystemTime::now()
                        .duration_since(::std::time::UNIX_EPOCH)
                        .map_or(0i128, |d| d.as_nanos() as i128);
                    (#actual - now_ns).abs() > #bound
                }
            },
        );
    }

    out
}

fn oneof_field_path(f: &FieldValidator) -> TokenStream {
    let field_name = &f.field_name;
    let field_number = f.field_number;
    let field_type = if f.is_group {
        "Group"
    } else {
        crate::emit::field::kind_to_field_type(&f.field_type)
    };
    let field_type_ident = format_ident!("{}", field_type);
    quote! {
        ::protovalidate_buffa::FieldPath {
            elements: ::std::vec![
                ::protovalidate_buffa::FieldPathElement {
                    field_number: Some(#field_number),
                    field_name: Some(::std::borrow::Cow::Borrowed(#field_name)),
                    field_type: Some(::protovalidate_buffa::FieldType::#field_type_ident),
                    key_type: None,
                    value_type: None,
                    subscript: None,
                },
            ],
        }
    }
}

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
