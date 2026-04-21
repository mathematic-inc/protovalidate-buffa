//! Emit per-field validation code for scalar types, enums, bytes, repeated,
//! map, and message-field recursion.

use anyhow::Result;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::scan::{
    BoolStandard, BytesStandard, DoubleStandard, EnumStandard, FieldKind, FieldValidator,
    FloatStandard, Ignore, Int32Standard, Int64Standard, StringStandard, Uint32Standard,
    Uint64Standard,
};

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
pub fn emit(field: &FieldValidator) -> Result<TokenStream> {
    if matches!(field.ignore, Ignore::Always) {
        return Ok(quote! {});
    }
    // Oneof-member fields are NOT flat struct fields in buffa's generated code.
    // Their validation is emitted inside the oneof enum match arm in oneof.rs.
    if field.oneof_name.is_some() {
        return Ok(quote! {});
    }

    let accessor = safe_ident(&field.field_name);
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
        FieldKind::String => {
            if let Some(s) = &field.standard.string {
                blocks.extend(emit_string(&accessor, name_lit, field.field_number, s));
            }
        }
        FieldKind::Bytes => {
            if let Some(b) = &field.standard.bytes {
                blocks.extend(emit_bytes(&accessor, name_lit, field.field_number, b));
            }
        }
        FieldKind::Int32 => {
            if let Some(n) = &field.standard.int32 {
                blocks.extend(emit_int32(
                    &accessor,
                    name_lit,
                    field.field_number,
                    NUM_INT32,
                    n,
                ));
            }
        }
        FieldKind::Sint32 => {
            if let Some(n) = &field.standard.int32 {
                blocks.extend(emit_int32(
                    &accessor,
                    name_lit,
                    field.field_number,
                    NUM_SINT32,
                    n,
                ));
            }
        }
        FieldKind::Sfixed32 => {
            if let Some(n) = &field.standard.int32 {
                blocks.extend(emit_int32(
                    &accessor,
                    name_lit,
                    field.field_number,
                    NUM_SFIXED32,
                    n,
                ));
            }
        }
        FieldKind::Int64 => {
            if let Some(n) = &field.standard.int64 {
                blocks.extend(emit_int64(
                    &accessor,
                    name_lit,
                    field.field_number,
                    NUM_INT64,
                    n,
                ));
            }
        }
        FieldKind::Sint64 => {
            if let Some(n) = &field.standard.int64 {
                blocks.extend(emit_int64(
                    &accessor,
                    name_lit,
                    field.field_number,
                    NUM_SINT64,
                    n,
                ));
            }
        }
        FieldKind::Sfixed64 => {
            if let Some(n) = &field.standard.int64 {
                blocks.extend(emit_int64(
                    &accessor,
                    name_lit,
                    field.field_number,
                    NUM_SFIXED64,
                    n,
                ));
            }
        }
        FieldKind::Uint32 => {
            if let Some(n) = &field.standard.uint32 {
                blocks.extend(emit_uint32(
                    &accessor,
                    name_lit,
                    field.field_number,
                    NUM_UINT32,
                    n,
                ));
            }
        }
        FieldKind::Fixed32 => {
            if let Some(n) = &field.standard.uint32 {
                blocks.extend(emit_uint32(
                    &accessor,
                    name_lit,
                    field.field_number,
                    NUM_FIXED32,
                    n,
                ));
            }
        }
        FieldKind::Uint64 => {
            if let Some(n) = &field.standard.uint64 {
                blocks.extend(emit_uint64(
                    &accessor,
                    name_lit,
                    field.field_number,
                    NUM_UINT64,
                    n,
                ));
            }
        }
        FieldKind::Fixed64 => {
            if let Some(n) = &field.standard.uint64 {
                blocks.extend(emit_uint64(
                    &accessor,
                    name_lit,
                    field.field_number,
                    NUM_FIXED64,
                    n,
                ));
            }
        }
        FieldKind::Float => {
            if let Some(f) = &field.standard.float {
                blocks.extend(emit_float(&accessor, name_lit, field.field_number, f));
            }
        }
        FieldKind::Double => {
            if let Some(d) = &field.standard.double {
                blocks.extend(emit_double(&accessor, name_lit, field.field_number, d));
            }
        }
        FieldKind::Enum { full_name } => {
            if let Some(e) = &field.standard.enum_rules {
                blocks.extend(emit_enum(
                    &accessor,
                    name_lit,
                    field.field_number,
                    e,
                    full_name,
                )?);
            }
        }
        FieldKind::Optional(inner) => {
            // EXPLICIT-presence scalar: buffa generates `Option<T>`.
            // Emit all rules inside a guard that binds `v` without moving out
            // of `self`. For Copy types we dereference; for String/Bytes we
            // clone the inner so the downstream emitters that expect owned `v`
            // continue to compile.
            let inner_blocks = emit_optional_inner(&accessor, name_lit, inner, field);
            if !inner_blocks.is_empty() {
                match inner.as_ref() {
                    FieldKind::String => blocks.push(quote! {
                        if let Some(v) = self.#accessor.as_ref() {
                            let v: ::std::string::String = v.clone();
                            #( #inner_blocks )*
                        }
                    }),
                    FieldKind::Bytes => blocks.push(quote! {
                        if let Some(v) = self.#accessor.as_ref() {
                            let v: ::std::vec::Vec<u8> = v.clone();
                            #( #inner_blocks )*
                        }
                    }),
                    _ => blocks.push(quote! {
                        if let Some(v) = self.#accessor {
                            #( #inner_blocks )*
                        }
                    }),
                }
            }
        }
        FieldKind::Repeated(inner) => {
            if let Some(r) = &field.standard.repeated {
                blocks.push(crate::emit::repeated::emit_repeated(
                    &accessor,
                    name_lit,
                    field.field_number,
                    kind_to_field_type(inner),
                    r,
                    inner,
                )?);
            } else if let FieldKind::Message { full_name } = inner.as_ref() {
                // Repeated message with no repeated-level rules — still recurse.
                if !full_name.starts_with("google.protobuf.") {
                    let fnum = field.field_number;
                    blocks.push(quote! {
                        for (idx, elem) in self.#accessor.iter().enumerate() {
                            if let Err(sub) = elem.validate() {
                                violations.extend(sub.violations.into_iter().map(|mut v| {
                                    v.field.elements.insert(0, ::protovalidate_buffa::FieldPathElement {
                                        field_number: Some(#fnum),
                                        field_name: Some(::std::borrow::Cow::Borrowed(#name_lit)),
                                        field_type: Some(::protovalidate_buffa::FieldType::Message),
                                        key_type: None,
                                        value_type: None,
                                        subscript: Some(::protovalidate_buffa::Subscript::Index(idx as u64)),
                                    });
                                    v
                                }));
                            }
                        }
                    });
                }
            }
        }
        FieldKind::Map { key, value } => {
            if let Some(m) = &field.standard.map {
                blocks.push(crate::emit::repeated::emit_map(
                    &accessor,
                    name_lit,
                    field.field_number,
                    m,
                    key,
                    value,
                )?);
            } else if let FieldKind::Message { full_name } = value.as_ref() {
                // Map<K, Message> with no map-level rules — still recurse
                // into message values so nested validators fire.
                if !full_name.starts_with("google.protobuf.") {
                    let fnum = field.field_number;
                    let nl = name_lit;
                    let key_ty_ident = format_ident!("{}", kind_to_field_type(key));
                    let val_ty_ident = format_ident!("{}", kind_to_field_type(value));
                    if let Some(key_subscript) =
                        crate::emit::repeated::kind_variant_to_subscript(kind_to_field_type(key))
                    {
                        blocks.push(quote! {
                            for (key, value) in self.#accessor.iter() {
                                if let Err(sub) = value.validate() {
                                    violations.extend(sub.violations.into_iter().map(|mut v| {
                                        v.field.elements.insert(0, ::protovalidate_buffa::FieldPathElement {
                                            field_number: Some(#fnum),
                                            field_name: Some(::std::borrow::Cow::Borrowed(#nl)),
                                            field_type: Some(::protovalidate_buffa::FieldType::Message),
                                            key_type: Some(::protovalidate_buffa::FieldType::#key_ty_ident),
                                            value_type: Some(::protovalidate_buffa::FieldType::#val_ty_ident),
                                            subscript: Some(#key_subscript),
                                        });
                                        v
                                    }));
                                }
                            }
                        });
                    }
                }
            }
        }
        FieldKind::Message { full_name } => {
            // Scalar (optional) message field — recurse via MessageField<T>.
            // buffa generates `MessageField<T>` for message-typed fields.
            // `MessageField::as_option()` returns `Option<&T>`.
            //
            // Skip well-known google.protobuf.* types — they have no Validate impl.
            //
            // Skip fields that are part of a oneof: buffa represents those as an
            // enum variant inside `Option<XxxOneof>`, NOT as flat struct fields.
            // Generating `self.grading_started.as_option()` for a oneof field would
            // not compile. Fields in oneofs are only recursed via oneof.rs (which
            // emits a match arm over the oneof enum).
            if !full_name.starts_with("google.protobuf.") && field.oneof_name.is_none() {
                let fnum = field.field_number;
                let ty_ident = if field.is_group {
                    format_ident!("Group")
                } else {
                    format_ident!("Message")
                };
                blocks.push(quote! {
                    if let Some(inner) = self.#accessor.as_option() {
                        if let Err(sub) = inner.validate() {
                            violations.extend(sub.violations.into_iter().map(|mut v| {
                                v.field.elements.insert(0, ::protovalidate_buffa::FieldPathElement {
                                    field_number: Some(#fnum),
                                    field_name: Some(::std::borrow::Cow::Borrowed(#name_lit)),
                                    field_type: Some(::protovalidate_buffa::FieldType::#ty_ident),
                                    key_type: None,
                                    value_type: None,
                                    subscript: None,
                                });
                                v
                            }));
                        }
                    }
                });
            }
            // google.protobuf.Duration rules.
            if full_name == "google.protobuf.Duration" {
                if let Some(d) = &field.standard.duration {
                    blocks.extend(emit_duration_rules(
                        &accessor,
                        name_lit,
                        field.field_number,
                        d,
                    ));
                }
            }
            // google.protobuf.Timestamp rules.
            if full_name == "google.protobuf.Timestamp" {
                if let Some(t) = &field.standard.timestamp {
                    blocks.extend(emit_timestamp_rules(
                        &accessor,
                        name_lit,
                        field.field_number,
                        t,
                    ));
                }
            }
            // google.protobuf.FieldMask rules.
            if full_name == "google.protobuf.FieldMask" {
                if let Some(fm) = &field.standard.field_mask {
                    let fp_msg = field_path_scalar(name_lit, field.field_number, "Message");
                    if let Some(expected) = &fm.r#const {
                        let fp_c = &fp_msg;
                        let rule = rule_path_scalar("field_mask", 28, "const", 1, "Message");
                        let expected_lits = expected.iter().map(String::as_str);
                        let msg_str = format!("must equal paths [{}]", expected.join(", "));
                        blocks.push(quote! {
                            if let Some(inner) = self.#accessor.as_option() {
                                const EXPECTED: &[&str] = &[ #( #expected_lits ),* ];
                                let actual: ::std::vec::Vec<&str> = inner.paths.iter().map(|s| s.as_str()).collect();
                                let eq = actual.len() == EXPECTED.len()
                                    && actual.iter().zip(EXPECTED.iter()).all(|(a, b)| a == b);
                                if !eq {
                                    violations.push(::protovalidate_buffa::Violation {
                                        field: #fp_c, rule: #rule,
                                        rule_id: ::std::borrow::Cow::Borrowed("field_mask.const"),
                                        message: ::std::borrow::Cow::Borrowed(#msg_str),
                                        for_key: false,
                                    });
                                }
                            }
                        });
                    }
                    if !fm.in_set.is_empty() {
                        let fp_i = &fp_msg;
                        let rule = rule_path_scalar("field_mask", 28, "in", 2, "String");
                        let allowed = fm.in_set.iter().map(String::as_str);
                        blocks.push(quote! {
                            if let Some(inner) = self.#accessor.as_option() {
                                const ALLOWED: &[&str] = &[ #( #allowed ),* ];
                                let ok = inner.paths.iter().all(|p| {
                                    ALLOWED.iter().any(|c| ::protovalidate_buffa::rules::string::fieldmask_covers(c, p.as_str()))
                                });
                                if !ok {
                                    violations.push(::protovalidate_buffa::Violation {
                                        field: #fp_i, rule: #rule,
                                        rule_id: ::std::borrow::Cow::Borrowed("field_mask.in"),
                                        message: ::std::borrow::Cow::Borrowed(""),
                                        for_key: false,
                                    });
                                }
                            }
                        });
                    }
                    if !fm.not_in.is_empty() {
                        let fp_n = &fp_msg;
                        let rule = rule_path_scalar("field_mask", 28, "not_in", 3, "String");
                        let denied = fm.not_in.iter().map(String::as_str);
                        blocks.push(quote! {
                            if let Some(inner) = self.#accessor.as_option() {
                                const DENIED: &[&str] = &[ #( #denied ),* ];
                                let bad = inner.paths.iter().any(|p| {
                                    DENIED.iter().any(|c| ::protovalidate_buffa::rules::string::fieldmask_covers(c, p.as_str())
                                        || ::protovalidate_buffa::rules::string::fieldmask_covers(p.as_str(), c))
                                });
                                if bad {
                                    violations.push(::protovalidate_buffa::Violation {
                                        field: #fp_n, rule: #rule,
                                        rule_id: ::std::borrow::Cow::Borrowed("field_mask.not_in"),
                                        message: ::std::borrow::Cow::Borrowed(""),
                                        for_key: false,
                                    });
                                }
                            }
                        });
                    }
                }
            }
            // google.protobuf.Any `type_url` checks.
            if full_name == "google.protobuf.Any" {
                if let Some(a) = &field.standard.any_rules {
                    let field_path = field_path_scalar(name_lit, field.field_number, "Message");
                    if !a.in_set.is_empty() {
                        let set = &a.in_set;
                        let rule = rule_path_scalar("any", 20, "in", 2, "String");
                        blocks.push(quote! {
                            if let Some(inner) = self.#accessor.as_option() {
                                const ALLOWED: &[&str] = &[ #( #set ),* ];
                                if !ALLOWED.iter().any(|s| *s == inner.type_url.as_str()) {
                                    violations.push(::protovalidate_buffa::Violation {
                                        field: #field_path, rule: #rule,
                                        rule_id: ::std::borrow::Cow::Borrowed("any.in"),
                                        message: ::std::borrow::Cow::Borrowed(""),
                                        for_key: false,
                                    });
                                }
                            }
                        });
                    }
                    if !a.not_in.is_empty() {
                        let set = &a.not_in;
                        let field_path2 =
                            field_path_scalar(name_lit, field.field_number, "Message");
                        let rule = rule_path_scalar("any", 20, "not_in", 3, "String");
                        blocks.push(quote! {
                            if let Some(inner) = self.#accessor.as_option() {
                                const DISALLOWED: &[&str] = &[ #( #set ),* ];
                                if DISALLOWED.iter().any(|s| *s == inner.type_url.as_str()) {
                                    violations.push(::protovalidate_buffa::Violation {
                                        field: #field_path2, rule: #rule,
                                        rule_id: ::std::borrow::Cow::Borrowed("any.not_in"),
                                        message: ::std::borrow::Cow::Borrowed(""),
                                        for_key: false,
                                    });
                                }
                            }
                        });
                    }
                }
            }
            let _ = full_name;
        }
        FieldKind::Bool => {
            if let Some(b) = &field.standard.bool_rules {
                blocks.extend(emit_bool(&accessor, name_lit, field.field_number, b));
            }
        }
        FieldKind::Wrapper(inner) => {
            // Unwrap MessageField<T> → `w.value` then apply inner scalar rules.
            // The outer field in the rule path is TYPE_MESSAGE (the wrapper),
            // not the inner scalar — so use a Message-typed field path.
            let inner_blocks = emit_wrapper_inner(name_lit, field.field_number, inner, field);
            if !inner_blocks.is_empty() {
                blocks.push(quote! {
                    if let Some(__wrapper_inner) = self.#accessor.as_option() {
                        let v = __wrapper_inner.value.clone();
                        #( #inner_blocks )*
                    }
                });
            }
        }
    }

    // IGNORE_IF_ZERO_VALUE: wrap all rule checks in a zero-value guard so
    // that default values bypass every constraint. The exact guard depends
    // on the field kind (`is_empty()` for string/bytes/repeated/map,
    // `!= 0/0.0/false` for scalars).
    if matches!(field.ignore, Ignore::IfZeroValue) && !field.is_legacy_required {
        let guard: Option<TokenStream> = match &field.field_type {
            FieldKind::String | FieldKind::Bytes => Some(quote! { !self.#accessor.is_empty() }),
            FieldKind::Repeated(_) | FieldKind::Map { .. } => {
                Some(quote! { !self.#accessor.is_empty() })
            }
            FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32 => {
                Some(quote! { self.#accessor != 0i32 })
            }
            FieldKind::Int64 | FieldKind::Sint64 | FieldKind::Sfixed64 => {
                Some(quote! { self.#accessor != 0i64 })
            }
            FieldKind::Uint32 | FieldKind::Fixed32 => Some(quote! { self.#accessor != 0u32 }),
            FieldKind::Uint64 | FieldKind::Fixed64 => Some(quote! { self.#accessor != 0u64 }),
            FieldKind::Float => Some(quote! { self.#accessor != 0f32 }),
            FieldKind::Double => Some(quote! { self.#accessor != 0f64 }),
            FieldKind::Bool => Some(quote! { self.#accessor }),
            FieldKind::Enum { .. } => Some(quote! { (self.#accessor as i32) != 0i32 }),
            FieldKind::Message { .. } | FieldKind::Optional(_) | FieldKind::Wrapper(_) => None,
        };
        if let Some(g) = guard {
            return Ok(quote! {
                if #g {
                    #( #blocks )*
                }
            });
        }
    }

    // When `required` is set, the other rules should only run when the value
    // is present (i.e. non-default). This mirrors protovalidate's semantics:
    // a default-valued required field reports `required` and nothing else.
    if let Some(req) = required_block {
        let guard: Option<TokenStream> = match &field.field_type {
            FieldKind::String | FieldKind::Bytes => Some(quote! { !self.#accessor.is_empty() }),
            FieldKind::Repeated(_) | FieldKind::Map { .. } => {
                Some(quote! { !self.#accessor.is_empty() })
            }
            FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32 => {
                Some(quote! { self.#accessor != 0i32 })
            }
            FieldKind::Int64 | FieldKind::Sint64 | FieldKind::Sfixed64 => {
                Some(quote! { self.#accessor != 0i64 })
            }
            FieldKind::Uint32 | FieldKind::Fixed32 => Some(quote! { self.#accessor != 0u32 }),
            FieldKind::Uint64 | FieldKind::Fixed64 => Some(quote! { self.#accessor != 0u64 }),
            FieldKind::Float => Some(quote! { self.#accessor != 0f32 }),
            FieldKind::Double => Some(quote! { self.#accessor != 0f64 }),
            FieldKind::Bool => Some(quote! { self.#accessor }),
            FieldKind::Enum { .. } => Some(quote! { (self.#accessor as i32) != 0i32 }),
            FieldKind::Message { .. } | FieldKind::Wrapper(_) => {
                Some(quote! { self.#accessor.is_set() })
            }
            FieldKind::Optional(_) => Some(quote! { self.#accessor.is_some() }),
        };
        return Ok(guard.map_or_else(
            || quote! { #req #( #blocks )* },
            |g| quote! { #req if #g { #( #blocks )* } },
        ));
    }

    Ok(quote! { #( #blocks )* })
}

// ─── optional (EXPLICIT presence) ────────────────────────────────────────────

/// Emit rule checks for an EXPLICIT-presence scalar field whose Rust type is
/// `Option<T>`. The generated code is placed inside an `if let Some(v) = ...`
/// block so all inner snippets use `v` (the unwrapped value) instead of
/// `self.<field>`.
fn emit_optional_inner(
    accessor: &syn::Ident,
    name_lit: &str,
    inner: &FieldKind,
    field: &FieldValidator,
) -> Vec<TokenStream> {
    // For numeric kinds, emit metadata-bearing checks inline so the
    // conformance diff includes field_number + field_type.
    const fn num_fam_for(kind: &FieldKind) -> Option<NumFamily> {
        match kind {
            FieldKind::Int32 => Some(NUM_INT32),
            FieldKind::Sint32 => Some(NUM_SINT32),
            FieldKind::Sfixed32 => Some(NUM_SFIXED32),
            FieldKind::Int64 => Some(NUM_INT64),
            FieldKind::Sint64 => Some(NUM_SINT64),
            FieldKind::Sfixed64 => Some(NUM_SFIXED64),
            FieldKind::Uint32 => Some(NUM_UINT32),
            FieldKind::Fixed32 => Some(NUM_FIXED32),
            FieldKind::Uint64 => Some(NUM_UINT64),
            FieldKind::Fixed64 => Some(NUM_FIXED64),
            FieldKind::Float => Some(FLOAT_FAM),
            FieldKind::Double => Some(DOUBLE_FAM),
            _ => None,
        }
    }
    // Use `v` as the ident for the unwrapped value inside the if-let block.
    let v = format_ident!("v");
    let fnum = field.field_number;
    let mut out: Vec<TokenStream> = Vec::new();

    if let Some(fam) = num_fam_for(inner) {
        let field_path_expr = field_path_scalar(name_lit, fnum, fam.scalar_ty);
        // Helper to emit a single comparison with full metadata.
        let emit_cmp = |out: &mut Vec<TokenStream>,
                        inner_name: &str,
                        inner_num: i32,
                        rule_id: String,
                        cond: TokenStream| {
            let field = field_path_expr.clone();
            let rule = rule_path_scalar(
                fam.family,
                fam.outer_number,
                inner_name,
                inner_num,
                fam.scalar_ty,
            );
            out.push(quote! {
                if #cond {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                        message: ::std::borrow::Cow::Borrowed(""),
                        for_key: false,
                    });
                }
            });
        };
        let std = &field.standard;
        match inner {
            FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32 => {
                if let Some(n) = &std.int32 {
                    if let Some(c) = n.r#const {
                        emit_cmp(
                            &mut out,
                            "const",
                            INNER_CONST,
                            format!("{}.const", fam.family),
                            quote! { #v != #c },
                        );
                    }
                    if let Some(lo) = n.gt {
                        emit_cmp(
                            &mut out,
                            "gt",
                            INNER_GT,
                            format!("{}.gt", fam.family),
                            quote! { #v <= #lo },
                        );
                    }
                    if let Some(lo) = n.gte {
                        emit_cmp(
                            &mut out,
                            "gte",
                            INNER_GTE,
                            format!("{}.gte", fam.family),
                            quote! { #v < #lo },
                        );
                    }
                    if let Some(hi) = n.lt {
                        emit_cmp(
                            &mut out,
                            "lt",
                            INNER_LT,
                            format!("{}.lt", fam.family),
                            quote! { #v >= #hi },
                        );
                    }
                    if let Some(hi) = n.lte {
                        emit_cmp(
                            &mut out,
                            "lte",
                            INNER_LTE,
                            format!("{}.lte", fam.family),
                            quote! { #v > #hi },
                        );
                    }
                }
            }
            FieldKind::Int64 | FieldKind::Sint64 | FieldKind::Sfixed64 => {
                if let Some(n) = &std.int64 {
                    if let Some(c) = n.r#const {
                        emit_cmp(
                            &mut out,
                            "const",
                            INNER_CONST,
                            format!("{}.const", fam.family),
                            quote! { #v != #c },
                        );
                    }
                    if let Some(lo) = n.gt {
                        emit_cmp(
                            &mut out,
                            "gt",
                            INNER_GT,
                            format!("{}.gt", fam.family),
                            quote! { #v <= #lo },
                        );
                    }
                    if let Some(lo) = n.gte {
                        emit_cmp(
                            &mut out,
                            "gte",
                            INNER_GTE,
                            format!("{}.gte", fam.family),
                            quote! { #v < #lo },
                        );
                    }
                    if let Some(hi) = n.lt {
                        emit_cmp(
                            &mut out,
                            "lt",
                            INNER_LT,
                            format!("{}.lt", fam.family),
                            quote! { #v >= #hi },
                        );
                    }
                    if let Some(hi) = n.lte {
                        emit_cmp(
                            &mut out,
                            "lte",
                            INNER_LTE,
                            format!("{}.lte", fam.family),
                            quote! { #v > #hi },
                        );
                    }
                }
            }
            FieldKind::Uint32 | FieldKind::Fixed32 => {
                if let Some(n) = &std.uint32 {
                    if let Some(c) = n.r#const {
                        emit_cmp(
                            &mut out,
                            "const",
                            INNER_CONST,
                            format!("{}.const", fam.family),
                            quote! { #v != #c },
                        );
                    }
                    if let Some(lo) = n.gt {
                        emit_cmp(
                            &mut out,
                            "gt",
                            INNER_GT,
                            format!("{}.gt", fam.family),
                            quote! { #v <= #lo },
                        );
                    }
                    if let Some(lo) = n.gte {
                        emit_cmp(
                            &mut out,
                            "gte",
                            INNER_GTE,
                            format!("{}.gte", fam.family),
                            quote! { #v < #lo },
                        );
                    }
                    if let Some(hi) = n.lt {
                        emit_cmp(
                            &mut out,
                            "lt",
                            INNER_LT,
                            format!("{}.lt", fam.family),
                            quote! { #v >= #hi },
                        );
                    }
                    if let Some(hi) = n.lte {
                        emit_cmp(
                            &mut out,
                            "lte",
                            INNER_LTE,
                            format!("{}.lte", fam.family),
                            quote! { #v > #hi },
                        );
                    }
                }
            }
            FieldKind::Uint64 | FieldKind::Fixed64 => {
                if let Some(n) = &std.uint64 {
                    if let Some(c) = n.r#const {
                        emit_cmp(
                            &mut out,
                            "const",
                            INNER_CONST,
                            format!("{}.const", fam.family),
                            quote! { #v != #c },
                        );
                    }
                    if let Some(lo) = n.gt {
                        emit_cmp(
                            &mut out,
                            "gt",
                            INNER_GT,
                            format!("{}.gt", fam.family),
                            quote! { #v <= #lo },
                        );
                    }
                    if let Some(lo) = n.gte {
                        emit_cmp(
                            &mut out,
                            "gte",
                            INNER_GTE,
                            format!("{}.gte", fam.family),
                            quote! { #v < #lo },
                        );
                    }
                    if let Some(hi) = n.lt {
                        emit_cmp(
                            &mut out,
                            "lt",
                            INNER_LT,
                            format!("{}.lt", fam.family),
                            quote! { #v >= #hi },
                        );
                    }
                    if let Some(hi) = n.lte {
                        emit_cmp(
                            &mut out,
                            "lte",
                            INNER_LTE,
                            format!("{}.lte", fam.family),
                            quote! { #v > #hi },
                        );
                    }
                }
            }
            FieldKind::Float => {
                if let Some(f) = &std.float {
                    if let Some(lo) = f.gt {
                        emit_cmp(
                            &mut out,
                            "gt",
                            INNER_GT,
                            format!("{}.gt", fam.family),
                            quote! { !(#v > #lo) },
                        );
                    }
                    if let Some(lo) = f.gte {
                        emit_cmp(
                            &mut out,
                            "gte",
                            INNER_GTE,
                            format!("{}.gte", fam.family),
                            quote! { !(#v >= #lo) },
                        );
                    }
                    if let Some(hi) = f.lt {
                        emit_cmp(
                            &mut out,
                            "lt",
                            INNER_LT,
                            format!("{}.lt", fam.family),
                            quote! { !(#v < #hi) },
                        );
                    }
                    if let Some(hi) = f.lte {
                        emit_cmp(
                            &mut out,
                            "lte",
                            INNER_LTE,
                            format!("{}.lte", fam.family),
                            quote! { !(#v <= #hi) },
                        );
                    }
                }
            }
            FieldKind::Double => {
                if let Some(d) = &std.double {
                    if let Some(lo) = d.gt {
                        emit_cmp(
                            &mut out,
                            "gt",
                            INNER_GT,
                            format!("{}.gt", fam.family),
                            quote! { !(#v > #lo) },
                        );
                    }
                    if let Some(lo) = d.gte {
                        emit_cmp(
                            &mut out,
                            "gte",
                            INNER_GTE,
                            format!("{}.gte", fam.family),
                            quote! { !(#v >= #lo) },
                        );
                    }
                    if let Some(hi) = d.lt {
                        emit_cmp(
                            &mut out,
                            "lt",
                            INNER_LT,
                            format!("{}.lt", fam.family),
                            quote! { !(#v < #hi) },
                        );
                    }
                    if let Some(hi) = d.lte {
                        emit_cmp(
                            &mut out,
                            "lte",
                            INNER_LTE,
                            format!("{}.lte", fam.family),
                            quote! { !(#v <= #hi) },
                        );
                    }
                }
            }
            _ => {}
        }
        let _ = accessor;
        return out;
    }

    match inner {
        FieldKind::Float => {
            if let Some(f) = &field.standard.float {
                out.extend(emit_float_on(&v, name_lit, f));
            }
        }
        FieldKind::Double => {
            if let Some(d) = &field.standard.double {
                out.extend(emit_double_on(&v, name_lit, d));
            }
        }
        FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32 => {
            if let Some(n) = &field.standard.int32 {
                out.extend(emit_int32_on(&v, name_lit, n));
            }
        }
        FieldKind::Int64 | FieldKind::Sint64 | FieldKind::Sfixed64 => {
            if let Some(n) = &field.standard.int64 {
                out.extend(emit_int64_on(&v, name_lit, n));
            }
        }
        FieldKind::Uint32 | FieldKind::Fixed32 => {
            if let Some(n) = &field.standard.uint32 {
                out.extend(emit_uint32_on(&v, name_lit, n));
            }
        }
        FieldKind::Uint64 | FieldKind::Fixed64 => {
            if let Some(n) = &field.standard.uint64 {
                out.extend(emit_uint64_on(&v, name_lit, n));
            }
        }
        // String/Bytes/Enum/Message/Bool/Repeated/Map/Optional with EXPLICIT
        // presence are unusual and unsupported for now.
        FieldKind::String => {
            if let Some(s) = &field.standard.string {
                out.extend(emit_string_checks_on(&v, name_lit, field.field_number, s));
            }
        }
        FieldKind::Bytes => {
            if let Some(b) = &field.standard.bytes {
                out.extend(emit_bytes_on(&v, name_lit, b));
            }
        }
        FieldKind::Bool => {
            if let Some(b) = &field.standard.bool_rules {
                if let Some(c) = b.r#const {
                    let fp = field_path_scalar(name_lit, field.field_number, "Bool");
                    let rp = rule_path_scalar("bool", 13, "const", 1, "Bool");
                    out.push(quote! {
                        if #v != #c {
                            violations.push(::protovalidate_buffa::Violation {
                                field: #fp, rule: #rp,
                                rule_id: ::std::borrow::Cow::Borrowed("bool.const"),
                                message: ::std::borrow::Cow::Borrowed(""),
                                for_key: false,
                            });
                        }
                    });
                }
            }
        }
        FieldKind::Enum { .. }
        | FieldKind::Message { .. }
        | FieldKind::Repeated(_)
        | FieldKind::Map { .. }
        | FieldKind::Optional(_)
        | FieldKind::Wrapper(_) => {}
    }

    let _ = accessor; // name_lit already embedded in inner
    out
}

fn emit_bytes_on(val: &syn::Ident, _name_lit: &str, b: &BytesStandard) -> Vec<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    if let Some(n) = b.min_len {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        out.push(quote! {
            if #val.len() < #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::FieldPath::default(),
                    rule: ::protovalidate_buffa::FieldPath::default(),
                    rule_id: ::std::borrow::Cow::Borrowed("bytes.min_len"),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        });
    }
    if let Some(n) = b.max_len {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        out.push(quote! {
            if #val.len() > #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::FieldPath::default(),
                    rule: ::protovalidate_buffa::FieldPath::default(),
                    rule_id: ::std::borrow::Cow::Borrowed("bytes.max_len"),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        });
    }
    out
}

// Variants of numeric/float emitters that take an explicit `value_ident`
// (the unwrapped `v`) instead of `self.<field>`.

#[must_use]
pub fn emit_float_on_pub(val: &syn::Ident, name_lit: &str, f: &FloatStandard) -> Vec<TokenStream> {
    emit_float_on(val, name_lit, f)
}

fn emit_float_on(val: &syn::Ident, name_lit: &str, f: &FloatStandard) -> Vec<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    if let Some(lower) = f.gt {
        out.push(quote! {
            if #val <= #lower {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::field_path!(#name_lit),
                    rule: ::protovalidate_buffa::field_path!("float", "gt"),
                    rule_id: ::std::borrow::Cow::Borrowed("float.gt"),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be > {} (got {})", #lower, #val)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(lower) = f.gte {
        out.push(quote! {
            if #val < #lower {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::field_path!(#name_lit),
                    rule: ::protovalidate_buffa::field_path!("float", "gte"),
                    rule_id: ::std::borrow::Cow::Borrowed("float.gte"),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be >= {} (got {})", #lower, #val)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(upper) = f.lt {
        out.push(quote! {
            if #val >= #upper {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::field_path!(#name_lit),
                    rule: ::protovalidate_buffa::field_path!("float", "lt"),
                    rule_id: ::std::borrow::Cow::Borrowed("float.lt"),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be < {} (got {})", #upper, #val)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(upper) = f.lte {
        out.push(quote! {
            if #val > #upper {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::field_path!(#name_lit),
                    rule: ::protovalidate_buffa::field_path!("float", "lte"),
                    rule_id: ::std::borrow::Cow::Borrowed("float.lte"),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be <= {} (got {})", #upper, #val)),
                    for_key: false,
                });
            }
        });
    }
    if f.finite {
        out.push(quote! {
            if !::protovalidate_buffa::rules::float::is_finite_f32(#val) {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::field_path!(#name_lit),
                    rule: ::protovalidate_buffa::field_path!("float", "finite"),
                    rule_id: ::std::borrow::Cow::Borrowed("float.finite"),
                    message: ::std::borrow::Cow::Borrowed("value must be finite"),
                    for_key: false,
                });
            }
        });
    }
    out
}

#[must_use]
pub fn emit_double_on_pub(
    val: &syn::Ident,
    name_lit: &str,
    d: &DoubleStandard,
) -> Vec<TokenStream> {
    emit_double_on(val, name_lit, d)
}

fn emit_double_on(val: &syn::Ident, name_lit: &str, d: &DoubleStandard) -> Vec<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    if let Some(lower) = d.gt {
        out.push(quote! {
            if #val <= #lower {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::field_path!(#name_lit),
                    rule: ::protovalidate_buffa::field_path!("double", "gt"),
                    rule_id: ::std::borrow::Cow::Borrowed("double.gt"),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be > {} (got {})", #lower, #val)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(lower) = d.gte {
        out.push(quote! {
            if #val < #lower {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::field_path!(#name_lit),
                    rule: ::protovalidate_buffa::field_path!("double", "gte"),
                    rule_id: ::std::borrow::Cow::Borrowed("double.gte"),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be >= {} (got {})", #lower, #val)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(upper) = d.lt {
        out.push(quote! {
            if #val >= #upper {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::field_path!(#name_lit),
                    rule: ::protovalidate_buffa::field_path!("double", "lt"),
                    rule_id: ::std::borrow::Cow::Borrowed("double.lt"),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be < {} (got {})", #upper, #val)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(upper) = d.lte {
        out.push(quote! {
            if #val > #upper {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::field_path!(#name_lit),
                    rule: ::protovalidate_buffa::field_path!("double", "lte"),
                    rule_id: ::std::borrow::Cow::Borrowed("double.lte"),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be <= {} (got {})", #upper, #val)),
                    for_key: false,
                });
            }
        });
    }
    if d.finite {
        out.push(quote! {
            if !::protovalidate_buffa::rules::float::is_finite_f64(#val) {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::field_path!(#name_lit),
                    rule: ::protovalidate_buffa::field_path!("double", "finite"),
                    rule_id: ::std::borrow::Cow::Borrowed("double.finite"),
                    message: ::std::borrow::Cow::Borrowed("value must be finite"),
                    for_key: false,
                });
            }
        });
    }
    out
}

#[must_use]
pub fn emit_int32_on_pub(val: &syn::Ident, name_lit: &str, n: &Int32Standard) -> Vec<TokenStream> {
    emit_int32_on(val, name_lit, n)
}

fn emit_int32_on(val: &syn::Ident, name_lit: &str, n: &Int32Standard) -> Vec<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    if let Some(lower) = n.gt {
        out.push(quote! { if #val <= #lower { violations.push(::protovalidate_buffa::Violation { field: ::protovalidate_buffa::field_path!(#name_lit), rule: ::protovalidate_buffa::field_path!("int32","gt"), rule_id: ::std::borrow::Cow::Borrowed("int32.gt"), message: ::std::borrow::Cow::Owned(::std::format!("value must be > {} (got {})", #lower, #val)), for_key: false }); } });
    }
    if let Some(lower) = n.gte {
        out.push(quote! { if #val < #lower { violations.push(::protovalidate_buffa::Violation { field: ::protovalidate_buffa::field_path!(#name_lit), rule: ::protovalidate_buffa::field_path!("int32","gte"), rule_id: ::std::borrow::Cow::Borrowed("int32.gte"), message: ::std::borrow::Cow::Owned(::std::format!("value must be >= {} (got {})", #lower, #val)), for_key: false }); } });
    }
    if let Some(upper) = n.lt {
        out.push(quote! { if #val >= #upper { violations.push(::protovalidate_buffa::Violation { field: ::protovalidate_buffa::field_path!(#name_lit), rule: ::protovalidate_buffa::field_path!("int32","lt"), rule_id: ::std::borrow::Cow::Borrowed("int32.lt"), message: ::std::borrow::Cow::Owned(::std::format!("value must be < {} (got {})", #upper, #val)), for_key: false }); } });
    }
    if let Some(upper) = n.lte {
        out.push(quote! { if #val > #upper { violations.push(::protovalidate_buffa::Violation { field: ::protovalidate_buffa::field_path!(#name_lit), rule: ::protovalidate_buffa::field_path!("int32","lte"), rule_id: ::std::borrow::Cow::Borrowed("int32.lte"), message: ::std::borrow::Cow::Owned(::std::format!("value must be <= {} (got {})", #upper, #val)), for_key: false }); } });
    }
    out
}

#[must_use]
pub fn emit_int64_on_pub(val: &syn::Ident, name_lit: &str, n: &Int64Standard) -> Vec<TokenStream> {
    emit_int64_on(val, name_lit, n)
}

fn emit_int64_on(val: &syn::Ident, name_lit: &str, n: &Int64Standard) -> Vec<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    if let Some(lower) = n.gt {
        out.push(quote! { if #val <= #lower { violations.push(::protovalidate_buffa::Violation { field: ::protovalidate_buffa::field_path!(#name_lit), rule: ::protovalidate_buffa::field_path!("int64","gt"), rule_id: ::std::borrow::Cow::Borrowed("int64.gt"), message: ::std::borrow::Cow::Owned(::std::format!("value must be > {} (got {})", #lower, #val)), for_key: false }); } });
    }
    if let Some(lower) = n.gte {
        out.push(quote! { if #val < #lower { violations.push(::protovalidate_buffa::Violation { field: ::protovalidate_buffa::field_path!(#name_lit), rule: ::protovalidate_buffa::field_path!("int64","gte"), rule_id: ::std::borrow::Cow::Borrowed("int64.gte"), message: ::std::borrow::Cow::Owned(::std::format!("value must be >= {} (got {})", #lower, #val)), for_key: false }); } });
    }
    if let Some(upper) = n.lt {
        out.push(quote! { if #val >= #upper { violations.push(::protovalidate_buffa::Violation { field: ::protovalidate_buffa::field_path!(#name_lit), rule: ::protovalidate_buffa::field_path!("int32","lt"), rule_id: ::std::borrow::Cow::Borrowed("int64.lt"), message: ::std::borrow::Cow::Owned(::std::format!("value must be < {} (got {})", #upper, #val)), for_key: false }); } });
    }
    if let Some(upper) = n.lte {
        out.push(quote! { if #val > #upper { violations.push(::protovalidate_buffa::Violation { field: ::protovalidate_buffa::field_path!(#name_lit), rule: ::protovalidate_buffa::field_path!("int64","lte"), rule_id: ::std::borrow::Cow::Borrowed("int64.lte"), message: ::std::borrow::Cow::Owned(::std::format!("value must be <= {} (got {})", #upper, #val)), for_key: false }); } });
    }
    out
}

#[must_use]
pub fn emit_uint32_on_pub(
    val: &syn::Ident,
    name_lit: &str,
    n: &Uint32Standard,
) -> Vec<TokenStream> {
    emit_uint32_on(val, name_lit, n)
}

fn emit_uint32_on(val: &syn::Ident, name_lit: &str, n: &Uint32Standard) -> Vec<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    if let Some(lower) = n.gt {
        out.push(quote! { if #val <= #lower { violations.push(::protovalidate_buffa::Violation { field: ::protovalidate_buffa::field_path!(#name_lit), rule: ::protovalidate_buffa::field_path!("uint32","gt"), rule_id: ::std::borrow::Cow::Borrowed("uint32.gt"), message: ::std::borrow::Cow::Owned(::std::format!("value must be > {} (got {})", #lower, #val)), for_key: false }); } });
    }
    if let Some(lower) = n.gte {
        out.push(quote! { if #val < #lower { violations.push(::protovalidate_buffa::Violation { field: ::protovalidate_buffa::field_path!(#name_lit), rule: ::protovalidate_buffa::field_path!("uint32","gte"), rule_id: ::std::borrow::Cow::Borrowed("uint32.gte"), message: ::std::borrow::Cow::Owned(::std::format!("value must be >= {} (got {})", #lower, #val)), for_key: false }); } });
    }
    if let Some(upper) = n.lt {
        out.push(quote! { if #val >= #upper { violations.push(::protovalidate_buffa::Violation { field: ::protovalidate_buffa::field_path!(#name_lit), rule: ::protovalidate_buffa::field_path!("uint32","lt"), rule_id: ::std::borrow::Cow::Borrowed("uint32.lt"), message: ::std::borrow::Cow::Owned(::std::format!("value must be < {} (got {})", #upper, #val)), for_key: false }); } });
    }
    if let Some(upper) = n.lte {
        out.push(quote! { if #val > #upper { violations.push(::protovalidate_buffa::Violation { field: ::protovalidate_buffa::field_path!(#name_lit), rule: ::protovalidate_buffa::field_path!("uint32","lte"), rule_id: ::std::borrow::Cow::Borrowed("uint32.lte"), message: ::std::borrow::Cow::Owned(::std::format!("value must be <= {} (got {})", #upper, #val)), for_key: false }); } });
    }
    out
}

#[must_use]
pub fn emit_uint64_on_pub(
    val: &syn::Ident,
    name_lit: &str,
    n: &Uint64Standard,
) -> Vec<TokenStream> {
    emit_uint64_on(val, name_lit, n)
}

fn emit_uint64_on(val: &syn::Ident, name_lit: &str, n: &Uint64Standard) -> Vec<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    if let Some(lower) = n.gt {
        out.push(quote! { if #val <= #lower { violations.push(::protovalidate_buffa::Violation { field: ::protovalidate_buffa::field_path!(#name_lit), rule: ::protovalidate_buffa::field_path!("uint64","gt"), rule_id: ::std::borrow::Cow::Borrowed("uint64.gt"), message: ::std::borrow::Cow::Owned(::std::format!("value must be > {} (got {})", #lower, #val)), for_key: false }); } });
    }
    if let Some(lower) = n.gte {
        out.push(quote! { if #val < #lower { violations.push(::protovalidate_buffa::Violation { field: ::protovalidate_buffa::field_path!(#name_lit), rule: ::protovalidate_buffa::field_path!("uint64","gte"), rule_id: ::std::borrow::Cow::Borrowed("uint64.gte"), message: ::std::borrow::Cow::Owned(::std::format!("value must be >= {} (got {})", #lower, #val)), for_key: false }); } });
    }
    if let Some(upper) = n.lt {
        out.push(quote! { if #val >= #upper { violations.push(::protovalidate_buffa::Violation { field: ::protovalidate_buffa::field_path!(#name_lit), rule: ::protovalidate_buffa::field_path!("uint64","lt"), rule_id: ::std::borrow::Cow::Borrowed("uint64.lt"), message: ::std::borrow::Cow::Owned(::std::format!("value must be < {} (got {})", #upper, #val)), for_key: false }); } });
    }
    if let Some(upper) = n.lte {
        out.push(quote! { if #val > #upper { violations.push(::protovalidate_buffa::Violation { field: ::protovalidate_buffa::field_path!(#name_lit), rule: ::protovalidate_buffa::field_path!("uint64","lte"), rule_id: ::std::borrow::Cow::Borrowed("uint64.lte"), message: ::std::borrow::Cow::Owned(::std::format!("value must be <= {} (got {})", #upper, #val)), for_key: false }); } });
    }
    out
}

// ─── required ────────────────────────────────────────────────────────────────

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

// ─── string ──────────────────────────────────────────────────────────────────

/// String rules family metadata: outer field number in FieldRules is 14.
/// Inner rule numbers (from validate.proto StringRules):
///   const=1, min_len=2, max_len=3, min_bytes=4, max_bytes=5, pattern=6,
///   prefix=7, suffix=8, contains=9, in=10, not_in=11, len=19, len_bytes=20,
///   not_contains=23.
const STR_OUTER: i32 = 14;
fn str_field_path(name: &str, number: i32) -> TokenStream {
    field_path_scalar(name, number, "String")
}
fn str_rule_path(inner: &str, inner_num: i32) -> TokenStream {
    rule_path_scalar("string", STR_OUTER, inner, inner_num, "String")
}
fn str_rule_path_ty(inner: &str, inner_num: i32, ty: &str) -> TokenStream {
    rule_path_scalar("string", STR_OUTER, inner, inner_num, ty)
}

fn emit_string(
    accessor: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    s: &StringStandard,
) -> Vec<TokenStream> {
    // well_known string format flags — each is a `Bool` rule on StringRules.
    // The oneof field numbers come from validate.proto.
    fn wk_rule(inner: &str, inner_num: i32) -> TokenStream {
        rule_path_scalar("string", 14, inner, inner_num, "Bool")
    }
    let mut out: Vec<TokenStream> = Vec::new();

    if let Some(n) = s.min_len {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        let field = str_field_path(name_lit, field_number);
        let rule = str_rule_path_ty("min_len", 2, "Uint64");
        out.push(quote! {
            if self.#accessor.chars().count() < #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.min_len"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value length must be at least {} characters", #n_usize
                    )),
                    for_key: false,
                });
            }
        });
    }

    if let Some(n) = s.max_len {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        let field = str_field_path(name_lit, field_number);
        let rule = str_rule_path_ty("max_len", 3, "Uint64");
        out.push(quote! {
            if self.#accessor.chars().count() > #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.max_len"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value length must be at most {} characters", #n_usize
                    )),
                    for_key: false,
                });
            }
        });
    }

    if let Some(pat) = &s.pattern {
        let pat_str = pat.as_str();
        let cache_ident = format_ident!("RE_{}", accessor.to_string().to_uppercase());
        let field = str_field_path(name_lit, field_number);
        let rule = str_rule_path("pattern", 6);
        out.push(quote! {
            {
                static #cache_ident: ::std::sync::OnceLock<::protovalidate_buffa::regex::Regex> =
                    ::std::sync::OnceLock::new();
                let re = #cache_ident.get_or_init(|| {
                    ::protovalidate_buffa::regex::Regex::new(#pat_str)
                        .expect("pattern regex compiled at code-gen time")
                });
                if !re.is_match(&self.#accessor) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("string.pattern"),
                        message: ::std::borrow::Cow::Owned(::std::format!(
                            "value must match pattern /{}/", #pat_str
                        )),
                        for_key: false,
                    });
                }
            }
        });
    }

    let wk_flag = |out: &mut Vec<TokenStream>,
                   flag: Option<bool>,
                   inner_name: &str,
                   inner_num: i32,
                   rule_id: &str,
                   fn_path: TokenStream,
                   msg: &str| {
        if flag == Some(true) {
            let field = str_field_path(name_lit, field_number);
            let rule = wk_rule(inner_name, inner_num);
            let rid = rule_id.to_string();
            let m = msg.to_string();
            out.push(quote! {
                if !#fn_path(&self.#accessor) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed(#rid),
                        message: ::std::borrow::Cow::Borrowed(#m),
                        for_key: false,
                    });
                }
            });
        }
    };
    // uuid/tuuid/ulid: protovalidate differentiates empty input with a
    // `_empty` rule_id suffix.
    let empty_aware = |out: &mut Vec<TokenStream>,
                       flag: Option<bool>,
                       inner_name: &str,
                       inner_num: i32,
                       base_id: &str,
                       fn_path: TokenStream| {
        if flag != Some(true) {
            return;
        }
        let field = str_field_path(name_lit, field_number);
        let field2 = str_field_path(name_lit, field_number);
        let rule = wk_rule(inner_name, inner_num);
        let rule2 = wk_rule(inner_name, inner_num);
        let id_empty = format!("{base_id}_empty");
        let id_base = base_id.to_string();
        out.push(quote! {
            if self.#accessor.is_empty() {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#id_empty),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            } else if !#fn_path(&self.#accessor) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field2, rule: #rule2,
                    rule_id: ::std::borrow::Cow::Borrowed(#id_base),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        });
    };
    empty_aware(
        &mut out,
        s.uuid,
        "uuid",
        22,
        "string.uuid",
        quote! { ::protovalidate_buffa::rules::string::is_uuid },
    );
    empty_aware(
        &mut out,
        s.tuuid,
        "tuuid",
        33,
        "string.tuuid",
        quote! { ::protovalidate_buffa::rules::string::is_tuuid },
    );
    empty_aware(
        &mut out,
        s.ulid,
        "ulid",
        35,
        "string.ulid",
        quote! { ::protovalidate_buffa::rules::string::is_ulid },
    );
    empty_aware(
        &mut out,
        s.ip,
        "ip",
        14,
        "string.ip",
        quote! { ::protovalidate_buffa::rules::string::is_ip },
    );
    empty_aware(
        &mut out,
        s.ipv4,
        "ipv4",
        15,
        "string.ipv4",
        quote! { ::protovalidate_buffa::rules::string::is_ipv4 },
    );
    empty_aware(
        &mut out,
        s.ipv6,
        "ipv6",
        16,
        "string.ipv6",
        quote! { ::protovalidate_buffa::rules::string::is_ipv6 },
    );
    empty_aware(
        &mut out,
        s.ip_with_prefixlen,
        "ip_with_prefixlen",
        26,
        "string.ip_with_prefixlen",
        quote! { ::protovalidate_buffa::rules::string::is_ip_with_prefixlen },
    );
    empty_aware(
        &mut out,
        s.ipv4_with_prefixlen,
        "ipv4_with_prefixlen",
        27,
        "string.ipv4_with_prefixlen",
        quote! { ::protovalidate_buffa::rules::string::is_ipv4_with_prefixlen },
    );
    empty_aware(
        &mut out,
        s.ipv6_with_prefixlen,
        "ipv6_with_prefixlen",
        28,
        "string.ipv6_with_prefixlen",
        quote! { ::protovalidate_buffa::rules::string::is_ipv6_with_prefixlen },
    );
    empty_aware(
        &mut out,
        s.ip_prefix,
        "ip_prefix",
        29,
        "string.ip_prefix",
        quote! { ::protovalidate_buffa::rules::string::is_ip_prefix },
    );
    empty_aware(
        &mut out,
        s.ipv4_prefix,
        "ipv4_prefix",
        30,
        "string.ipv4_prefix",
        quote! { ::protovalidate_buffa::rules::string::is_ipv4_prefix },
    );
    empty_aware(
        &mut out,
        s.ipv6_prefix,
        "ipv6_prefix",
        31,
        "string.ipv6_prefix",
        quote! { ::protovalidate_buffa::rules::string::is_ipv6_prefix },
    );
    empty_aware(
        &mut out,
        s.hostname,
        "hostname",
        13,
        "string.hostname",
        quote! { ::protovalidate_buffa::rules::string::is_hostname },
    );
    empty_aware(
        &mut out,
        s.host_and_port,
        "host_and_port",
        32,
        "string.host_and_port",
        quote! { ::protovalidate_buffa::rules::string::is_host_and_port },
    );
    empty_aware(
        &mut out,
        s.email,
        "email",
        12,
        "string.email",
        quote! { ::protovalidate_buffa::rules::string::is_email },
    );
    empty_aware(
        &mut out,
        s.uri,
        "uri",
        17,
        "string.uri",
        quote! { ::protovalidate_buffa::rules::string::is_uri },
    );
    wk_flag(
        &mut out,
        s.uri_ref,
        "uri_ref",
        18,
        "string.uri_ref",
        quote! { ::protovalidate_buffa::rules::string::is_uri_ref },
        "value must be a valid URI reference",
    );
    empty_aware(
        &mut out,
        s.address,
        "address",
        21,
        "string.address",
        quote! { ::protovalidate_buffa::rules::string::is_address },
    );
    empty_aware(
        &mut out,
        s.protobuf_fqn,
        "protobuf_fqn",
        37,
        "string.protobuf_fqn",
        quote! { ::protovalidate_buffa::rules::string::is_protobuf_fqn },
    );
    empty_aware(
        &mut out,
        s.protobuf_dot_fqn,
        "protobuf_dot_fqn",
        38,
        "string.protobuf_dot_fqn",
        quote! { ::protovalidate_buffa::rules::string::is_protobuf_dot_fqn },
    );
    if let Some(wkr) = s.well_known_regex {
        let strict = s.strict_regex.unwrap_or(true);
        let field_a = str_field_path(name_lit, field_number);
        let field_b = str_field_path(name_lit, field_number);
        let rule_a = str_rule_path_ty("well_known_regex", 24, "Enum");
        let rule_b = str_rule_path_ty("well_known_regex", 24, "Enum");
        // Only header_name has a distinct empty-rule_id (empty is invalid).
        // header_value allows empty strings.
        let (fn_path, rule_id, empty_rule_id): (TokenStream, &str, Option<&str>) = match wkr {
            1 => (
                quote! { |v: &::std::string::String| ::protovalidate_buffa::rules::string::is_header_name(v, #strict) },
                "string.well_known_regex.header_name",
                Some("string.well_known_regex.header_name_empty"),
            ),
            2 => (
                quote! { |v: &::std::string::String| ::protovalidate_buffa::rules::string::is_header_value(v, #strict) },
                "string.well_known_regex.header_value",
                None,
            ),
            _ => (
                quote! { |_v: &::std::string::String| true },
                "string.well_known_regex",
                None,
            ),
        };
        let rid = rule_id.to_string();
        if let Some(re) = empty_rule_id {
            let rid_empty = re.to_string();
            out.push(quote! {
                if self.#accessor.is_empty() {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field_a, rule: #rule_a,
                        rule_id: ::std::borrow::Cow::Borrowed(#rid_empty),
                        message: ::std::borrow::Cow::Borrowed(""),
                        for_key: false,
                    });
                } else if !(#fn_path)(&self.#accessor) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field_b, rule: #rule_b,
                        rule_id: ::std::borrow::Cow::Borrowed(#rid),
                        message: ::std::borrow::Cow::Borrowed(""),
                        for_key: false,
                    });
                }
            });
        } else {
            let _ = field_a;
            let _ = rule_a;
            out.push(quote! {
                if !self.#accessor.is_empty() && !(#fn_path)(&self.#accessor) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field_b, rule: #rule_b,
                        rule_id: ::std::borrow::Cow::Borrowed(#rid),
                        message: ::std::borrow::Cow::Borrowed(""),
                        for_key: false,
                    });
                }
            });
        }
    }

    if !s.in_set.is_empty() {
        let set = &s.in_set;
        let field = str_field_path(name_lit, field_number);
        let rule = str_rule_path("in", 10);
        out.push(quote! {
            {
                const ALLOWED: &[&str] = &[ #( #set ),* ];
                if !ALLOWED.iter().any(|candidate| *candidate == self.#accessor.as_str()) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("string.in"),
                        message: ::std::borrow::Cow::Owned(::std::format!(
                            "value must be one of [{}]", ALLOWED.join(", ")
                        )),
                        for_key: false,
                    });
                }
            }
        });
    }

    if !s.not_in_set.is_empty() {
        let set = &s.not_in_set;
        let field = str_field_path(name_lit, field_number);
        let rule = str_rule_path("not_in", 11);
        out.push(quote! {
            {
                const DISALLOWED: &[&str] = &[ #( #set ),* ];
                if DISALLOWED.iter().any(|candidate| *candidate == self.#accessor.as_str()) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("string.not_in"),
                        message: ::std::borrow::Cow::Owned(::std::format!(
                            "value must not be one of [{}]", DISALLOWED.join(", ")
                        )),
                        for_key: false,
                    });
                }
            }
        });
    }

    if let Some(prefix) = &s.prefix {
        let field = str_field_path(name_lit, field_number);
        let rule = str_rule_path("prefix", 7);
        out.push(quote! {
            if !self.#accessor.starts_with(#prefix) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.prefix"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must have prefix {:?}", #prefix
                    )),
                    for_key: false,
                });
            }
        });
    }

    if let Some(suffix) = &s.suffix {
        let field = str_field_path(name_lit, field_number);
        let rule = str_rule_path("suffix", 8);
        out.push(quote! {
            if !self.#accessor.ends_with(#suffix) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.suffix"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must have suffix {:?}", #suffix
                    )),
                    for_key: false,
                });
            }
        });
    }

    if let Some(contains) = &s.contains {
        let field = str_field_path(name_lit, field_number);
        let rule = str_rule_path("contains", 9);
        out.push(quote! {
            if !self.#accessor.contains(#contains) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.contains"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must contain {:?}", #contains
                    )),
                    for_key: false,
                });
            }
        });
    }

    if let Some(not_contains) = &s.not_contains {
        let field = str_field_path(name_lit, field_number);
        let rule = str_rule_path("not_contains", 23);
        out.push(quote! {
            if self.#accessor.contains(#not_contains) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.not_contains"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must not contain {:?}", #not_contains
                    )),
                    for_key: false,
                });
            }
        });
    }

    if let Some(n) = s.len {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        let field = str_field_path(name_lit, field_number);
        let rule = str_rule_path_ty("len", 19, "Uint64");
        out.push(quote! {
            if self.#accessor.chars().count() != #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.len"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value length must be {} characters", #n_usize
                    )),
                    for_key: false,
                });
            }
        });
    }

    if let Some(n) = s.min_bytes {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        let field = str_field_path(name_lit, field_number);
        let rule = str_rule_path_ty("min_bytes", 4, "Uint64");
        out.push(quote! {
            if self.#accessor.len() < #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.min_bytes"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must be at least {} bytes", #n_usize
                    )),
                    for_key: false,
                });
            }
        });
    }

    if let Some(n) = s.max_bytes {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        let field = str_field_path(name_lit, field_number);
        let rule = str_rule_path_ty("max_bytes", 5, "Uint64");
        out.push(quote! {
            if self.#accessor.len() > #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.max_bytes"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must be at most {} bytes", #n_usize
                    )),
                    for_key: false,
                });
            }
        });
    }

    if let Some(n) = s.len_bytes {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        let field = str_field_path(name_lit, field_number);
        let rule = str_rule_path_ty("len_bytes", 20, "Uint64");
        out.push(quote! {
            if self.#accessor.len() != #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.len_bytes"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must be exactly {} bytes", #n_usize
                    )),
                    for_key: false,
                });
            }
        });
    }

    if let Some(r#const) = &s.r#const {
        let field = str_field_path(name_lit, field_number);
        let rule = str_rule_path("const", 1);
        out.push(quote! {
            if self.#accessor != #r#const {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.const"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must equal {:?}", #r#const
                    )),
                    for_key: false,
                });
            }
        });
    }

    out
}

// ─── bytes ───────────────────────────────────────────────────────────────────

/// BytesRules inner numbers: const=1, len=13, min_len=2, max_len=3, pattern=4,
/// prefix=5, suffix=6, contains=7, in=8, not_in=9.
const BYTES_OUTER: i32 = 15;
fn bytes_field_path(name: &str, number: i32) -> TokenStream {
    field_path_scalar(name, number, "Bytes")
}
fn bytes_rule_path(inner: &str, inner_num: i32) -> TokenStream {
    rule_path_scalar("bytes", BYTES_OUTER, inner, inner_num, "Bytes")
}
fn bytes_rule_path_ty(inner: &str, inner_num: i32, ty: &str) -> TokenStream {
    rule_path_scalar("bytes", BYTES_OUTER, inner, inner_num, ty)
}

fn emit_bytes(
    accessor: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    b: &BytesStandard,
) -> Vec<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    let fp = || bytes_field_path(name_lit, field_number);

    // bytes.ip = 4 or 16 bytes; bytes.ipv4 = 4 bytes; bytes.ipv6 = 16 bytes.
    if b.ip == Some(true) {
        let field = fp();
        let rule = bytes_rule_path_ty("ip", 10, "Bool");
        out.push(quote! {
            if self.#accessor.len() != 4 && self.#accessor.len() != 16 {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("bytes.ip"),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        });
    }
    if b.ipv4 == Some(true) {
        let field = fp();
        let rule = bytes_rule_path_ty("ipv4", 11, "Bool");
        out.push(quote! {
            if self.#accessor.len() != 4 {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("bytes.ipv4"),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        });
    }
    if b.ipv6 == Some(true) {
        let field = fp();
        let rule = bytes_rule_path_ty("ipv6", 12, "Bool");
        out.push(quote! {
            if self.#accessor.len() != 16 {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("bytes.ipv6"),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        });
    }
    // bytes.uuid expects raw 16 bytes, not a hex string.
    if b.uuid == Some(true) {
        let field = fp();
        let rule = bytes_rule_path_ty("uuid", 15, "Bool");
        out.push(quote! {
            {
                // Empty is a special-cased _empty rule.
                if self.#accessor.is_empty() {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field.clone(), rule: #rule.clone(),
                        rule_id: ::std::borrow::Cow::Borrowed("bytes.uuid_empty"),
                        message: ::std::borrow::Cow::Borrowed(""),
                        for_key: false,
                    });
                } else if self.#accessor.len() != 16 {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("bytes.uuid"),
                        message: ::std::borrow::Cow::Borrowed(""),
                        for_key: false,
                    });
                }
            }
        });
    }

    if let Some(c) = &b.r#const {
        let set: Vec<u8> = c.clone();
        let field = fp();
        let rule = bytes_rule_path("const", 1);
        out.push(quote! {
            {
                const EXPECTED: &[u8] = &[ #( #set ),* ];
                if self.#accessor.as_slice() != EXPECTED {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("bytes.const"),
                        message: ::std::borrow::Cow::Borrowed("value does not match expected bytes"),
                        for_key: false,
                    });
                }
            }
        });
    }

    if let Some(n) = b.min_len {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        let field = fp();
        let rule = bytes_rule_path_ty("min_len", 2, "Uint64");
        out.push(quote! {
            if self.#accessor.len() < #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("bytes.min_len"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value length must be at least {} bytes (got {})",
                        #n_usize, self.#accessor.len()
                    )),
                    for_key: false,
                });
            }
        });
    }

    if let Some(n) = b.len {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        let field = fp();
        let rule = bytes_rule_path_ty("len", 13, "Uint64");
        out.push(quote! {
            if self.#accessor.len() != #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("bytes.len"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must be exactly {} bytes (got {})",
                        #n_usize, self.#accessor.len()
                    )),
                    for_key: false,
                });
            }
        });
    }

    if let Some(n) = b.max_len {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        let field = fp();
        let rule = bytes_rule_path_ty("max_len", 3, "Uint64");
        out.push(quote! {
            if self.#accessor.len() > #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("bytes.max_len"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value length must be at most {} bytes (got {})",
                        #n_usize, self.#accessor.len()
                    )),
                    for_key: false,
                });
            }
        });
    }

    if let Some(pat) = &b.pattern {
        let pat_str = pat.as_str();
        let cache_ident = format_ident!("RE_BYTES_{}", accessor.to_string().to_uppercase());
        let field = fp();
        let rule = bytes_rule_path_ty("pattern", 4, "String");
        out.push(quote! {
            {
                static #cache_ident: ::std::sync::OnceLock<::protovalidate_buffa::regex::Regex> =
                    ::std::sync::OnceLock::new();
                let re = #cache_ident.get_or_init(|| {
                    ::protovalidate_buffa::regex::Regex::new(#pat_str)
                        .expect("pattern regex compiled at code-gen time")
                });
                match ::std::str::from_utf8(&self.#accessor) {
                    Ok(s) => {
                        if !re.is_match(s) {
                            violations.push(::protovalidate_buffa::Violation {
                                field: #field, rule: #rule,
                                rule_id: ::std::borrow::Cow::Borrowed("bytes.pattern"),
                                message: ::std::borrow::Cow::Owned(::std::format!(
                                    "value must match pattern /{}/", #pat_str
                                )),
                                for_key: false,
                            });
                        }
                    }
                    Err(_) => {
                        return ::core::result::Result::Err(
                            ::protovalidate_buffa::ValidationError {
                                runtime_error: ::core::option::Option::Some(
                                    ::std::string::String::from("value must be valid UTF-8 to apply regexp"),
                                ),
                                ..::core::default::Default::default()
                            },
                        );
                    }
                }
            }
        });
    }

    if let Some(prefix) = &b.prefix {
        let p: Vec<u8> = prefix.clone();
        let field = fp();
        let rule = bytes_rule_path("prefix", 5);
        out.push(quote! {
            {
                const PREFIX: &[u8] = &[ #( #p ),* ];
                if !self.#accessor.starts_with(PREFIX) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("bytes.prefix"),
                        message: ::std::borrow::Cow::Borrowed("value does not have required prefix"),
                        for_key: false,
                    });
                }
            }
        });
    }

    if let Some(suffix) = &b.suffix {
        let p: Vec<u8> = suffix.clone();
        let field = fp();
        let rule = bytes_rule_path("suffix", 6);
        out.push(quote! {
            {
                const SUFFIX: &[u8] = &[ #( #p ),* ];
                if !self.#accessor.ends_with(SUFFIX) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("bytes.suffix"),
                        message: ::std::borrow::Cow::Borrowed("value does not have required suffix"),
                        for_key: false,
                    });
                }
            }
        });
    }

    if let Some(contains) = &b.contains {
        let p: Vec<u8> = contains.clone();
        let field = fp();
        let rule = bytes_rule_path("contains", 7);
        out.push(quote! {
            {
                const NEEDLE: &[u8] = &[ #( #p ),* ];
                if !self.#accessor.windows(NEEDLE.len()).any(|w| w == NEEDLE) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("bytes.contains"),
                        message: ::std::borrow::Cow::Borrowed("value does not contain required bytes"),
                        for_key: false,
                    });
                }
            }
        });
    }

    if !b.in_set.is_empty() {
        // We emit a simple any() match.
        let bytes_lits: Vec<TokenStream> = b
            .in_set
            .iter()
            .map(|v| {
                let bs: Vec<u8> = v.clone();
                quote! { &[ #( #bs ),* ][..] }
            })
            .collect();
        let field = fp();
        let rule = bytes_rule_path("in", 8);
        out.push(quote! {
            {
                let allowed: &[&[u8]] = &[ #( #bytes_lits ),* ];
                if !allowed.iter().any(|a| *a == self.#accessor.as_slice()) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("bytes.in"),
                        message: ::std::borrow::Cow::Borrowed("value not in allowed set"),
                        for_key: false,
                    });
                }
            }
        });
    }

    if !b.not_in_set.is_empty() {
        let bytes_lits: Vec<TokenStream> = b
            .not_in_set
            .iter()
            .map(|v| {
                let bs: Vec<u8> = v.clone();
                quote! { &[ #( #bs ),* ][..] }
            })
            .collect();
        let field = fp();
        let rule = bytes_rule_path("not_in", 9);
        out.push(quote! {
            {
                let disallowed: &[&[u8]] = &[ #( #bytes_lits ),* ];
                if disallowed.iter().any(|a| *a == self.#accessor.as_slice()) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("bytes.not_in"),
                        message: ::std::borrow::Cow::Borrowed("value is in forbidden set"),
                        for_key: false,
                    });
                }
            }
        });
    }

    out
}

// ─── int32 ───────────────────────────────────────────────────────────────────

fn emit_int32(
    accessor: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    fam: NumFamily,
    n: &Int32Standard,
) -> Vec<TokenStream> {
    emit_num_i32_like(accessor, name_lit, field_number, fam, n)
}

fn emit_num_i32_like(
    accessor: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    fam: NumFamily,
    n: &Int32Standard,
) -> Vec<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    let fp = || field_path_scalar(name_lit, field_number, fam.scalar_ty);

    if let (Some(lower), Some(upper)) = (n.gt, n.lt) {
        out.push(range_check(
            &fp(),
            fam,
            false,
            &quote! { #lower },
            &quote! { #upper },
            &quote! { self.#accessor },
            upper < lower,
        ));
        return out;
    }
    if let (Some(lower), Some(upper)) = (n.gte, n.lte) {
        out.push(range_check(
            &fp(),
            fam,
            true,
            &quote! { #lower },
            &quote! { #upper },
            &quote! { self.#accessor },
            upper < lower,
        ));
        return out;
    }

    if let Some(c) = n.r#const {
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "const",
            INNER_CONST,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.const", fam.family);
        out.push(quote! {
            if self.#accessor != #c {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field,
                    rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must equal {} (got {})", #c, self.#accessor
                    )),
                    for_key: false,
                });
            }
        });
    }
    if let Some(lower) = n.gt {
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "gt", INNER_GT, fam.scalar_ty);
        let rule_id = format!("{}.gt", fam.family);
        out.push(quote! {
            if self.#accessor <= #lower {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field,
                    rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must be > {} (got {})", #lower, self.#accessor
                    )),
                    for_key: false,
                });
            }
        });
    }
    if let Some(lower) = n.gte {
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "gte",
            INNER_GTE,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.gte", fam.family);
        out.push(quote! {
            if self.#accessor < #lower {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field,
                    rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must be >= {} (got {})", #lower, self.#accessor
                    )),
                    for_key: false,
                });
            }
        });
    }
    if let Some(upper) = n.lt {
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "lt", INNER_LT, fam.scalar_ty);
        let rule_id = format!("{}.lt", fam.family);
        out.push(quote! {
            if self.#accessor >= #upper {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field,
                    rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must be < {} (got {})", #upper, self.#accessor
                    )),
                    for_key: false,
                });
            }
        });
    }
    if let Some(upper) = n.lte {
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "lte",
            INNER_LTE,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.lte", fam.family);
        out.push(quote! {
            if self.#accessor > #upper {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field,
                    rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must be <= {} (got {})", #upper, self.#accessor
                    )),
                    for_key: false,
                });
            }
        });
    }
    if !n.in_set.is_empty() {
        let set = &n.in_set;
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "in", INNER_IN, fam.scalar_ty);
        let rule_id = format!("{}.in", fam.family);
        out.push(quote! {
            {
                const ALLOWED: &[i32] = &[ #( #set ),* ];
                if !ALLOWED.contains(&self.#accessor) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field,
                        rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                        message: ::std::borrow::Cow::Owned(::std::format!(
                            "value must be in {:?}", ALLOWED
                        )),
                        for_key: false,
                    });
                }
            }
        });
    }
    if !n.not_in.is_empty() {
        let set = &n.not_in;
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "not_in",
            INNER_NOT_IN,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.not_in", fam.family);
        out.push(quote! {
            {
                const DISALLOWED: &[i32] = &[ #( #set ),* ];
                if DISALLOWED.contains(&self.#accessor) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field,
                        rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                        message: ::std::borrow::Cow::Owned(::std::format!(
                            "value must not be in {:?}", DISALLOWED
                        )),
                        for_key: false,
                    });
                }
            }
        });
    }
    out
}

// ─── int64 ───────────────────────────────────────────────────────────────────

fn emit_int64(
    accessor: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    fam: NumFamily,
    n: &Int64Standard,
) -> Vec<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    let fp = || field_path_scalar(name_lit, field_number, fam.scalar_ty);

    if let (Some(lower), Some(upper)) = (n.gt, n.lt) {
        out.push(range_check(
            &fp(),
            fam,
            false,
            &quote! { #lower },
            &quote! { #upper },
            &quote! { self.#accessor },
            upper < lower,
        ));
        return out;
    }
    if let (Some(lower), Some(upper)) = (n.gte, n.lte) {
        out.push(range_check(
            &fp(),
            fam,
            true,
            &quote! { #lower },
            &quote! { #upper },
            &quote! { self.#accessor },
            upper < lower,
        ));
        return out;
    }

    if let Some(c) = n.r#const {
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "const",
            INNER_CONST,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.const", fam.family);
        out.push(quote! {
            if self.#accessor != #c {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must equal {} (got {})", #c, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(lower) = n.gt {
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "gt", INNER_GT, fam.scalar_ty);
        let rule_id = format!("{}.gt", fam.family);
        out.push(quote! {
            if self.#accessor <= #lower {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be > {} (got {})", #lower, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(lower) = n.gte {
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "gte",
            INNER_GTE,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.gte", fam.family);
        out.push(quote! {
            if self.#accessor < #lower {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be >= {} (got {})", #lower, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(upper) = n.lt {
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "lt", INNER_LT, fam.scalar_ty);
        let rule_id = format!("{}.lt", fam.family);
        out.push(quote! {
            if self.#accessor >= #upper {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be < {} (got {})", #upper, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(upper) = n.lte {
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "lte",
            INNER_LTE,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.lte", fam.family);
        out.push(quote! {
            if self.#accessor > #upper {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be <= {} (got {})", #upper, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if !n.in_set.is_empty() {
        let set = &n.in_set;
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "in", INNER_IN, fam.scalar_ty);
        let rule_id = format!("{}.in", fam.family);
        out.push(quote! {
            {
                const ALLOWED: &[i64] = &[ #( #set ),* ];
                if !ALLOWED.contains(&self.#accessor) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                        message: ::std::borrow::Cow::Owned(::std::format!("value must be in {:?}", ALLOWED)),
                        for_key: false,
                    });
                }
            }
        });
    }
    if !n.not_in.is_empty() {
        let set = &n.not_in;
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "not_in",
            INNER_NOT_IN,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.not_in", fam.family);
        out.push(quote! {
            {
                const DISALLOWED: &[i64] = &[ #( #set ),* ];
                if DISALLOWED.contains(&self.#accessor) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                        message: ::std::borrow::Cow::Owned(::std::format!("value must not be in {:?}", DISALLOWED)),
                        for_key: false,
                    });
                }
            }
        });
    }
    out
}

// ─── uint32 ──────────────────────────────────────────────────────────────────

fn emit_uint32(
    accessor: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    fam: NumFamily,
    n: &Uint32Standard,
) -> Vec<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    let fp = || field_path_scalar(name_lit, field_number, fam.scalar_ty);

    if let (Some(lower), Some(upper)) = (n.gt, n.lt) {
        out.push(range_check(
            &fp(),
            fam,
            false,
            &quote! { #lower },
            &quote! { #upper },
            &quote! { self.#accessor },
            upper < lower,
        ));
        return out;
    }
    if let (Some(lower), Some(upper)) = (n.gte, n.lte) {
        out.push(range_check(
            &fp(),
            fam,
            true,
            &quote! { #lower },
            &quote! { #upper },
            &quote! { self.#accessor },
            upper < lower,
        ));
        return out;
    }

    if let Some(c) = n.r#const {
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "const",
            INNER_CONST,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.const", fam.family);
        out.push(quote! {
            if self.#accessor != #c {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must equal {} (got {})", #c, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(lower) = n.gt {
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "gt", INNER_GT, fam.scalar_ty);
        let rule_id = format!("{}.gt", fam.family);
        out.push(quote! {
            if self.#accessor <= #lower {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be > {} (got {})", #lower, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(lower) = n.gte {
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "gte",
            INNER_GTE,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.gte", fam.family);
        out.push(quote! {
            if self.#accessor < #lower {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be >= {} (got {})", #lower, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(upper) = n.lt {
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "lt", INNER_LT, fam.scalar_ty);
        let rule_id = format!("{}.lt", fam.family);
        out.push(quote! {
            if self.#accessor >= #upper {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be < {} (got {})", #upper, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(upper) = n.lte {
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "lte",
            INNER_LTE,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.lte", fam.family);
        out.push(quote! {
            if self.#accessor > #upper {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be <= {} (got {})", #upper, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if !n.in_set.is_empty() {
        let set = &n.in_set;
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "in", INNER_IN, fam.scalar_ty);
        let rule_id = format!("{}.in", fam.family);
        out.push(quote! {
            {
                const ALLOWED: &[u32] = &[ #( #set ),* ];
                if !ALLOWED.contains(&self.#accessor) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                        message: ::std::borrow::Cow::Owned(::std::format!("value must be in {:?}", ALLOWED)),
                        for_key: false,
                    });
                }
            }
        });
    }
    if !n.not_in.is_empty() {
        let set = &n.not_in;
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "not_in",
            INNER_NOT_IN,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.not_in", fam.family);
        out.push(quote! {
            {
                const DISALLOWED: &[u32] = &[ #( #set ),* ];
                if DISALLOWED.contains(&self.#accessor) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                        message: ::std::borrow::Cow::Owned(::std::format!("value must not be in {:?}", DISALLOWED)),
                        for_key: false,
                    });
                }
            }
        });
    }
    out
}

// ─── uint64 ──────────────────────────────────────────────────────────────────

fn emit_uint64(
    accessor: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    fam: NumFamily,
    n: &Uint64Standard,
) -> Vec<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    let fp = || field_path_scalar(name_lit, field_number, fam.scalar_ty);

    if let (Some(lower), Some(upper)) = (n.gt, n.lt) {
        out.push(range_check(
            &fp(),
            fam,
            false,
            &quote! { #lower },
            &quote! { #upper },
            &quote! { self.#accessor },
            upper < lower,
        ));
        return out;
    }
    if let (Some(lower), Some(upper)) = (n.gte, n.lte) {
        out.push(range_check(
            &fp(),
            fam,
            true,
            &quote! { #lower },
            &quote! { #upper },
            &quote! { self.#accessor },
            upper < lower,
        ));
        return out;
    }

    if let Some(c) = n.r#const {
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "const",
            INNER_CONST,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.const", fam.family);
        out.push(quote! {
            if self.#accessor != #c {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must equal {} (got {})", #c, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(lower) = n.gt {
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "gt", INNER_GT, fam.scalar_ty);
        let rule_id = format!("{}.gt", fam.family);
        out.push(quote! {
            if self.#accessor <= #lower {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be > {} (got {})", #lower, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(lower) = n.gte {
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "gte",
            INNER_GTE,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.gte", fam.family);
        out.push(quote! {
            if self.#accessor < #lower {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be >= {} (got {})", #lower, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(upper) = n.lt {
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "lt", INNER_LT, fam.scalar_ty);
        let rule_id = format!("{}.lt", fam.family);
        out.push(quote! {
            if self.#accessor >= #upper {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be < {} (got {})", #upper, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(upper) = n.lte {
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "lte",
            INNER_LTE,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.lte", fam.family);
        out.push(quote! {
            if self.#accessor > #upper {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be <= {} (got {})", #upper, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if !n.in_set.is_empty() {
        let set = &n.in_set;
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "in", INNER_IN, fam.scalar_ty);
        let rule_id = format!("{}.in", fam.family);
        out.push(quote! {
            {
                const ALLOWED: &[u64] = &[ #( #set ),* ];
                if !ALLOWED.contains(&self.#accessor) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                        message: ::std::borrow::Cow::Owned(::std::format!("value must be in {:?}", ALLOWED)),
                        for_key: false,
                    });
                }
            }
        });
    }
    if !n.not_in.is_empty() {
        let set = &n.not_in;
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "not_in",
            INNER_NOT_IN,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.not_in", fam.family);
        out.push(quote! {
            {
                const DISALLOWED: &[u64] = &[ #( #set ),* ];
                if DISALLOWED.contains(&self.#accessor) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                        message: ::std::borrow::Cow::Owned(::std::format!("value must not be in {:?}", DISALLOWED)),
                        for_key: false,
                    });
                }
            }
        });
    }
    out
}

// ─── float ───────────────────────────────────────────────────────────────────

pub(crate) const FLOAT_FAM: NumFamily = NumFamily {
    family: "float",
    outer_number: 1,
    scalar_ty: "Float",
};
pub(crate) const DOUBLE_FAM: NumFamily = NumFamily {
    family: "double",
    outer_number: 2,
    scalar_ty: "Double",
};
const INNER_FINITE: i32 = 8;

fn emit_float(
    accessor: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    f: &FloatStandard,
) -> Vec<TokenStream> {
    let fam = FLOAT_FAM;
    let mut out: Vec<TokenStream> = Vec::new();
    let fp = || field_path_scalar(name_lit, field_number, fam.scalar_ty);

    if let (Some(lower), Some(upper)) = (f.gt, f.lt) {
        out.push(range_check_fp(
            &fp(),
            fam,
            false,
            &quote! { #lower },
            &quote! { #upper },
            &quote! { self.#accessor },
            upper < lower,
        ));
        return out;
    }
    if let (Some(lower), Some(upper)) = (f.gte, f.lte) {
        out.push(range_check_fp(
            &fp(),
            fam,
            true,
            &quote! { #lower },
            &quote! { #upper },
            &quote! { self.#accessor },
            upper < lower,
        ));
        return out;
    }

    if let Some(c) = f.r#const {
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "const",
            INNER_CONST,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.const", fam.family);
        out.push(quote! {
            if self.#accessor != #c {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must equal {} (got {})", #c, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(lower) = f.gt {
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "gt", INNER_GT, fam.scalar_ty);
        let rule_id = format!("{}.gt", fam.family);
        out.push(quote! {
            if !(self.#accessor > #lower) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be > {} (got {})", #lower, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(lower) = f.gte {
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "gte",
            INNER_GTE,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.gte", fam.family);
        out.push(quote! {
            if !(self.#accessor >= #lower) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be >= {} (got {})", #lower, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(upper) = f.lt {
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "lt", INNER_LT, fam.scalar_ty);
        let rule_id = format!("{}.lt", fam.family);
        out.push(quote! {
            if !(self.#accessor < #upper) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be < {} (got {})", #upper, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(upper) = f.lte {
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "lte",
            INNER_LTE,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.lte", fam.family);
        out.push(quote! {
            if !(self.#accessor <= #upper) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be <= {} (got {})", #upper, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if !f.in_set.is_empty() {
        let set = &f.in_set;
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "in", INNER_IN, fam.scalar_ty);
        let rule_id = format!("{}.in", fam.family);
        out.push(quote! {
            {
                const ALLOWED: &[f32] = &[ #( #set ),* ];
                if !ALLOWED.iter().any(|c| *c == self.#accessor) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                        message: ::std::borrow::Cow::Owned(::std::format!("value must be in {:?}", ALLOWED)),
                        for_key: false,
                    });
                }
            }
        });
    }
    if !f.not_in.is_empty() {
        let set = &f.not_in;
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "not_in",
            INNER_NOT_IN,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.not_in", fam.family);
        out.push(quote! {
            {
                const DISALLOWED: &[f32] = &[ #( #set ),* ];
                if DISALLOWED.iter().any(|c| *c == self.#accessor) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                        message: ::std::borrow::Cow::Owned(::std::format!("value must not be in {:?}", DISALLOWED)),
                        for_key: false,
                    });
                }
            }
        });
    }
    if f.finite {
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "finite", INNER_FINITE, "Bool");
        let rule_id = format!("{}.finite", fam.family);
        out.push(quote! {
            if !::protovalidate_buffa::rules::float::is_finite_f32(self.#accessor) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Borrowed("value must be finite"),
                    for_key: false,
                });
            }
        });
    }
    out
}

// ─── double ──────────────────────────────────────────────────────────────────

fn emit_double(
    accessor: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    d: &DoubleStandard,
) -> Vec<TokenStream> {
    let fam = DOUBLE_FAM;
    let mut out: Vec<TokenStream> = Vec::new();
    let fp = || field_path_scalar(name_lit, field_number, fam.scalar_ty);

    if let (Some(lower), Some(upper)) = (d.gt, d.lt) {
        out.push(range_check_fp(
            &fp(),
            fam,
            false,
            &quote! { #lower },
            &quote! { #upper },
            &quote! { self.#accessor },
            upper < lower,
        ));
        return out;
    }
    if let (Some(lower), Some(upper)) = (d.gte, d.lte) {
        out.push(range_check_fp(
            &fp(),
            fam,
            true,
            &quote! { #lower },
            &quote! { #upper },
            &quote! { self.#accessor },
            upper < lower,
        ));
        return out;
    }

    if let Some(c) = d.r#const {
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "const",
            INNER_CONST,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.const", fam.family);
        out.push(quote! {
            if self.#accessor != #c {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must equal {} (got {})", #c, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(lower) = d.gt {
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "gt", INNER_GT, fam.scalar_ty);
        let rule_id = format!("{}.gt", fam.family);
        out.push(quote! {
            if !(self.#accessor > #lower) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be > {} (got {})", #lower, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(lower) = d.gte {
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "gte",
            INNER_GTE,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.gte", fam.family);
        out.push(quote! {
            if !(self.#accessor >= #lower) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be >= {} (got {})", #lower, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(upper) = d.lt {
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "lt", INNER_LT, fam.scalar_ty);
        let rule_id = format!("{}.lt", fam.family);
        out.push(quote! {
            if !(self.#accessor < #upper) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be < {} (got {})", #upper, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if let Some(upper) = d.lte {
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "lte",
            INNER_LTE,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.lte", fam.family);
        out.push(quote! {
            if !(self.#accessor <= #upper) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must be <= {} (got {})", #upper, self.#accessor)),
                    for_key: false,
                });
            }
        });
    }
    if !d.in_set.is_empty() {
        let set = &d.in_set;
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "in", INNER_IN, fam.scalar_ty);
        let rule_id = format!("{}.in", fam.family);
        out.push(quote! {
            {
                const ALLOWED: &[f64] = &[ #( #set ),* ];
                if !ALLOWED.iter().any(|c| *c == self.#accessor) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                        message: ::std::borrow::Cow::Owned(::std::format!("value must be in {:?}", ALLOWED)),
                        for_key: false,
                    });
                }
            }
        });
    }
    if !d.not_in.is_empty() {
        let set = &d.not_in;
        let field = fp();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            "not_in",
            INNER_NOT_IN,
            fam.scalar_ty,
        );
        let rule_id = format!("{}.not_in", fam.family);
        out.push(quote! {
            {
                const DISALLOWED: &[f64] = &[ #( #set ),* ];
                if DISALLOWED.iter().any(|c| *c == self.#accessor) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                        message: ::std::borrow::Cow::Owned(::std::format!("value must not be in {:?}", DISALLOWED)),
                        for_key: false,
                    });
                }
            }
        });
    }
    if d.finite {
        let field = fp();
        let rule = rule_path_scalar(fam.family, fam.outer_number, "finite", INNER_FINITE, "Bool");
        let rule_id = format!("{}.finite", fam.family);
        out.push(quote! {
            if !::protovalidate_buffa::rules::float::is_finite_f64(self.#accessor) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Borrowed("value must be finite"),
                    for_key: false,
                });
            }
        });
    }
    out
}

// ─── enum ────────────────────────────────────────────────────────────────────

fn emit_enum(
    accessor: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    e: &EnumStandard,
    full_name: &str,
) -> Result<Vec<TokenStream>> {
    // EnumRules outer field number = 16; inner: const=1 (TYPE_INT32),
    // defined_only=2 (TYPE_BOOL), in=3 (TYPE_INT32), not_in=4 (TYPE_INT32).
    let fp = || field_path_scalar(name_lit, field_number, "Enum");
    let rule_path =
        |inner: &str, inner_num: i32, ty: &str| rule_path_scalar("enum", 16, inner, inner_num, ty);
    let mut out: Vec<TokenStream> = Vec::new();

    if let Some(c) = e.r#const {
        let field = fp();
        let rule = rule_path("const", 1, "Int32");
        out.push(quote! {
            {
                let raw_val: i32 = self.#accessor.to_i32();
                if raw_val != #c {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("enum.const"),
                        message: ::std::borrow::Cow::Owned(::std::format!(
                            "value {} must equal {}", raw_val, #c
                        )),
                        for_key: false,
                    });
                }
            }
        });
    }

    if e.defined_only == Some(true) {
        let enum_type = resolve_local_type(full_name)?;
        let field = fp();
        let rule = rule_path("defined_only", 2, "Bool");
        out.push(quote! {
            {
                let raw_val: i32 = self.#accessor.to_i32();
                if <#enum_type as ::buffa::Enumeration>::from_i32(raw_val).is_none() {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("enum.defined_only"),
                        message: ::std::borrow::Cow::Owned(::std::format!(
                            "value {} is not a defined enum value", raw_val
                        )),
                        for_key: false,
                    });
                }
            }
        });
    }

    if !e.in_set.is_empty() {
        let set = &e.in_set;
        let field = fp();
        let rule = rule_path("in", 3, "Int32");
        out.push(quote! {
            {
                const ALLOWED: &[i32] = &[ #( #set ),* ];
                let raw_val: i32 = self.#accessor.to_i32();
                if !ALLOWED.contains(&raw_val) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("enum.in"),
                        message: ::std::borrow::Cow::Owned(::std::format!(
                            "value {} must be in {:?}", raw_val, ALLOWED
                        )),
                        for_key: false,
                    });
                }
            }
        });
    }

    if !e.not_in.is_empty() {
        let set = &e.not_in;
        let field = fp();
        let rule = rule_path("not_in", 4, "Int32");
        out.push(quote! {
            {
                const DISALLOWED: &[i32] = &[ #( #set ),* ];
                let raw_val: i32 = self.#accessor.to_i32();
                if DISALLOWED.contains(&raw_val) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("enum.not_in"),
                        message: ::std::borrow::Cow::Owned(::std::format!(
                            "value {} must not be in {:?}", raw_val, DISALLOWED
                        )),
                        for_key: false,
                    });
                }
            }
        });
    }

    Ok(out)
}

/// Resolve a proto fully-qualified name to a local Rust type path.
///
/// E.g. `"example.v1.Foo"` → `syn::Path` for `ClothingType` (the last
/// segment). The generated file is included inside the correct module so the
/// local name resolves via the `use super::*;` at the top of the file.
///
/// Nested types (e.g. `"example.v1.Outer.InnerEnum"`) resolve through
/// [`resolve_type_from_package`], which lowers parent PascalCase segments
/// into the snake_case module names buffa emits (`outer::InnerEnum`).
fn resolve_local_type(full_name: &str) -> Result<syn::Path> {
    resolve_type_from_package(full_name, "")
}

/// Resolve a proto fully-qualified type name into the Rust path that's valid
/// from within `cur_package`'s module. Buffa places each proto package at
/// `crate::<pkg_segments_separated_by_::>`, with nested message/enum parents
/// lowered into snake_case modules. `cur_package` is the current proto
/// package (e.g. `buf.validate.conformance.cases`). If the target type lives
/// in a descendant or sibling package, the returned path walks through the
/// appropriate module segments.
fn resolve_type_from_package(full_name: &str, cur_package: &str) -> Result<syn::Path> {
    let stripped = full_name.strip_prefix('.').unwrap_or(full_name);
    let segments: Vec<&str> = stripped.split('.').collect();
    if segments.is_empty() {
        anyhow::bail!("empty type name: {full_name:?}");
    }

    // Split into (package_segments, type_segments). Walk from the end; every
    // trailing PascalCase segment is a type; the rest is the package.
    let split = segments
        .iter()
        .rposition(|s| !s.chars().next().is_some_and(char::is_uppercase))
        .map_or(0, |i| i + 1);
    let pkg_segments: &[&str] = &segments[..split];
    let type_segments: &[&str] = &segments[split..];
    if type_segments.is_empty() {
        anyhow::bail!("no type segment in: {full_name:?}");
    }

    // Determine the relative package path from cur_package to target package.
    let cur: Vec<&str> = if cur_package.is_empty() {
        Vec::new()
    } else {
        cur_package.split('.').collect()
    };
    let common = cur
        .iter()
        .zip(pkg_segments.iter())
        .take_while(|(a, b)| a == b)
        .count();
    // Buffa's module structure: each package segment is its own `pub mod`.
    // If target is a descendant of current, we walk down. If a sibling /
    // ancestor, we'd need to walk up — but from inside a package module
    // the parent modules are accessible (the package module is inside `buf::...`),
    // however `use super::*;` brings only the immediate parent's items into
    // scope. A safer approach: always reference via absolute `crate::...`.
    // But our emitted code uses `use super::*;` and we don't know what path
    // `crate` points to from the consumer's perspective. As a workaround,
    // prefer descending references via package module names when the target
    // is deeper, and otherwise emit a relative path that goes up through
    // `super::`.
    let mut path = String::new();
    let descend = &pkg_segments[common..];
    let ascend_count = cur.len() - common;
    for _ in 0..ascend_count {
        path.push_str("super::");
    }
    for seg in descend {
        path.push_str(seg);
        path.push_str("::");
    }
    let last_idx = type_segments.len() - 1;
    for (i, s) in type_segments.iter().enumerate() {
        if i == last_idx {
            path.push_str(s);
        } else {
            path.push_str(&to_snake_case(s));
            path.push_str("::");
        }
    }
    syn::parse_str::<syn::Path>(&path).map_err(Into::into)
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

/// Build an Ident that's safe to use as a Rust identifier. If the input
/// collides with a Rust keyword (e.g. `in`, `type`, `self`, `fn`), the
/// returned Ident is a raw identifier (`r#in`), matching buffa's generated
/// accessor for fields whose names are keywords.
/// Convert a FieldKind to the FieldType variant name used in the runtime
/// enum. Composite kinds (Repeated/Map/Optional/Message) map to the closest
/// approximation — primarily used for element-type metadata on repeated/map
/// entries where the inner scalar type is known.
/// Wrapper-specific: the outer field (in the rule path) is TYPE_MESSAGE
/// (the wrapper), not the inner scalar.
fn emit_wrapper_inner(
    name_lit: &str,
    field_number: i32,
    inner: &FieldKind,
    field: &FieldValidator,
) -> Vec<TokenStream> {
    let v = format_ident!("v");
    let fam = match inner {
        FieldKind::Int32 => Some(NUM_INT32),
        FieldKind::Int64 => Some(NUM_INT64),
        FieldKind::Uint32 => Some(NUM_UINT32),
        FieldKind::Uint64 => Some(NUM_UINT64),
        FieldKind::Float => Some(FLOAT_FAM),
        FieldKind::Double => Some(DOUBLE_FAM),
        FieldKind::Bool => None,
        FieldKind::String | FieldKind::Bytes => None,
        _ => None,
    };
    let field_path_expr = field_path_scalar(name_lit, field_number, "Message");
    let mut out: Vec<TokenStream> = Vec::new();
    if let Some(fam) = fam {
        let push_cmp = |out: &mut Vec<TokenStream>,
                        inner_name: &str,
                        inner_num: i32,
                        rule_id: String,
                        cond: TokenStream| {
            let field = field_path_expr.clone();
            let rule = rule_path_scalar(
                fam.family,
                fam.outer_number,
                inner_name,
                inner_num,
                fam.scalar_ty,
            );
            out.push(quote! {
                if #cond {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                        message: ::std::borrow::Cow::Borrowed(""),
                        for_key: false,
                    });
                }
            });
        };
        let std = &field.standard;
        match inner {
            FieldKind::Int32 => {
                if let Some(n) = &std.int32 {
                    if let Some(lo) = n.gt {
                        push_cmp(
                            &mut out,
                            "gt",
                            INNER_GT,
                            format!("{}.gt", fam.family),
                            quote! { #v <= #lo },
                        );
                    }
                    if let Some(lo) = n.gte {
                        push_cmp(
                            &mut out,
                            "gte",
                            INNER_GTE,
                            format!("{}.gte", fam.family),
                            quote! { #v < #lo },
                        );
                    }
                    if let Some(hi) = n.lt {
                        push_cmp(
                            &mut out,
                            "lt",
                            INNER_LT,
                            format!("{}.lt", fam.family),
                            quote! { #v >= #hi },
                        );
                    }
                    if let Some(hi) = n.lte {
                        push_cmp(
                            &mut out,
                            "lte",
                            INNER_LTE,
                            format!("{}.lte", fam.family),
                            quote! { #v > #hi },
                        );
                    }
                    if let Some(c) = n.r#const {
                        push_cmp(
                            &mut out,
                            "const",
                            INNER_CONST,
                            format!("{}.const", fam.family),
                            quote! { #v != #c },
                        );
                    }
                }
            }
            FieldKind::Int64 => {
                if let Some(n) = &std.int64 {
                    if let Some(lo) = n.gt {
                        push_cmp(
                            &mut out,
                            "gt",
                            INNER_GT,
                            format!("{}.gt", fam.family),
                            quote! { #v <= #lo },
                        );
                    }
                    if let Some(lo) = n.gte {
                        push_cmp(
                            &mut out,
                            "gte",
                            INNER_GTE,
                            format!("{}.gte", fam.family),
                            quote! { #v < #lo },
                        );
                    }
                    if let Some(hi) = n.lt {
                        push_cmp(
                            &mut out,
                            "lt",
                            INNER_LT,
                            format!("{}.lt", fam.family),
                            quote! { #v >= #hi },
                        );
                    }
                    if let Some(hi) = n.lte {
                        push_cmp(
                            &mut out,
                            "lte",
                            INNER_LTE,
                            format!("{}.lte", fam.family),
                            quote! { #v > #hi },
                        );
                    }
                    if let Some(c) = n.r#const {
                        push_cmp(
                            &mut out,
                            "const",
                            INNER_CONST,
                            format!("{}.const", fam.family),
                            quote! { #v != #c },
                        );
                    }
                }
            }
            FieldKind::Uint32 => {
                if let Some(n) = &std.uint32 {
                    if let Some(lo) = n.gt {
                        push_cmp(
                            &mut out,
                            "gt",
                            INNER_GT,
                            format!("{}.gt", fam.family),
                            quote! { #v <= #lo },
                        );
                    }
                    if let Some(lo) = n.gte {
                        push_cmp(
                            &mut out,
                            "gte",
                            INNER_GTE,
                            format!("{}.gte", fam.family),
                            quote! { #v < #lo },
                        );
                    }
                    if let Some(hi) = n.lt {
                        push_cmp(
                            &mut out,
                            "lt",
                            INNER_LT,
                            format!("{}.lt", fam.family),
                            quote! { #v >= #hi },
                        );
                    }
                    if let Some(hi) = n.lte {
                        push_cmp(
                            &mut out,
                            "lte",
                            INNER_LTE,
                            format!("{}.lte", fam.family),
                            quote! { #v > #hi },
                        );
                    }
                    if let Some(c) = n.r#const {
                        push_cmp(
                            &mut out,
                            "const",
                            INNER_CONST,
                            format!("{}.const", fam.family),
                            quote! { #v != #c },
                        );
                    }
                }
            }
            FieldKind::Uint64 => {
                if let Some(n) = &std.uint64 {
                    if let Some(lo) = n.gt {
                        push_cmp(
                            &mut out,
                            "gt",
                            INNER_GT,
                            format!("{}.gt", fam.family),
                            quote! { #v <= #lo },
                        );
                    }
                    if let Some(lo) = n.gte {
                        push_cmp(
                            &mut out,
                            "gte",
                            INNER_GTE,
                            format!("{}.gte", fam.family),
                            quote! { #v < #lo },
                        );
                    }
                    if let Some(hi) = n.lt {
                        push_cmp(
                            &mut out,
                            "lt",
                            INNER_LT,
                            format!("{}.lt", fam.family),
                            quote! { #v >= #hi },
                        );
                    }
                    if let Some(hi) = n.lte {
                        push_cmp(
                            &mut out,
                            "lte",
                            INNER_LTE,
                            format!("{}.lte", fam.family),
                            quote! { #v > #hi },
                        );
                    }
                    if let Some(c) = n.r#const {
                        push_cmp(
                            &mut out,
                            "const",
                            INNER_CONST,
                            format!("{}.const", fam.family),
                            quote! { #v != #c },
                        );
                    }
                }
            }
            FieldKind::Float => {
                if let Some(f) = &std.float {
                    if let Some(lo) = f.gt {
                        push_cmp(
                            &mut out,
                            "gt",
                            INNER_GT,
                            format!("{}.gt", fam.family),
                            quote! { !(#v > #lo) },
                        );
                    }
                    if let Some(lo) = f.gte {
                        push_cmp(
                            &mut out,
                            "gte",
                            INNER_GTE,
                            format!("{}.gte", fam.family),
                            quote! { !(#v >= #lo) },
                        );
                    }
                    if let Some(hi) = f.lt {
                        push_cmp(
                            &mut out,
                            "lt",
                            INNER_LT,
                            format!("{}.lt", fam.family),
                            quote! { !(#v < #hi) },
                        );
                    }
                    if let Some(hi) = f.lte {
                        push_cmp(
                            &mut out,
                            "lte",
                            INNER_LTE,
                            format!("{}.lte", fam.family),
                            quote! { !(#v <= #hi) },
                        );
                    }
                }
            }
            FieldKind::Double => {
                if let Some(d) = &std.double {
                    if let Some(lo) = d.gt {
                        push_cmp(
                            &mut out,
                            "gt",
                            INNER_GT,
                            format!("{}.gt", fam.family),
                            quote! { !(#v > #lo) },
                        );
                    }
                    if let Some(lo) = d.gte {
                        push_cmp(
                            &mut out,
                            "gte",
                            INNER_GTE,
                            format!("{}.gte", fam.family),
                            quote! { !(#v >= #lo) },
                        );
                    }
                    if let Some(hi) = d.lt {
                        push_cmp(
                            &mut out,
                            "lt",
                            INNER_LT,
                            format!("{}.lt", fam.family),
                            quote! { !(#v < #hi) },
                        );
                    }
                    if let Some(hi) = d.lte {
                        push_cmp(
                            &mut out,
                            "lte",
                            INNER_LTE,
                            format!("{}.lte", fam.family),
                            quote! { !(#v <= #hi) },
                        );
                    }
                }
            }
            _ => {}
        }
    } else {
        // String/Bytes/Bool wrappers: emit minimal checks with TYPE_MESSAGE
        // outer field path + proper inner rule path.
        let std = &field.standard;
        let push_v = |out: &mut Vec<TokenStream>,
                      rule_family: &str,
                      outer_num: i32,
                      inner_name: &str,
                      inner_num: i32,
                      inner_ty: &str,
                      rule_id: &str,
                      cond: TokenStream| {
            let field_path = field_path_scalar(name_lit, field_number, "Message");
            let rule = rule_path_scalar(rule_family, outer_num, inner_name, inner_num, inner_ty);
            let id = rule_id.to_string();
            out.push(quote! {
                if #cond {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field_path, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed(#id),
                        message: ::std::borrow::Cow::Borrowed(""),
                        for_key: false,
                    });
                }
            });
        };
        match inner {
            FieldKind::String => {
                if let Some(s) = &std.string {
                    if let Some(c) = &s.r#const {
                        push_v(
                            &mut out,
                            "string",
                            14,
                            "const",
                            1,
                            "String",
                            "string.const",
                            quote! { &#v != #c },
                        );
                    }
                    if let Some(n) = s.min_len {
                        let n_usize = usize::try_from(n).expect("len fits in usize");
                        push_v(
                            &mut out,
                            "string",
                            14,
                            "min_len",
                            2,
                            "Uint64",
                            "string.min_len",
                            quote! { #v.chars().count() < #n_usize },
                        );
                    }
                    if let Some(n) = s.max_len {
                        let n_usize = usize::try_from(n).expect("len fits in usize");
                        push_v(
                            &mut out,
                            "string",
                            14,
                            "max_len",
                            3,
                            "Uint64",
                            "string.max_len",
                            quote! { #v.chars().count() > #n_usize },
                        );
                    }
                    if let Some(pre) = &s.prefix {
                        push_v(
                            &mut out,
                            "string",
                            14,
                            "prefix",
                            7,
                            "String",
                            "string.prefix",
                            quote! { !#v.starts_with(#pre) },
                        );
                    }
                    if let Some(suf) = &s.suffix {
                        push_v(
                            &mut out,
                            "string",
                            14,
                            "suffix",
                            8,
                            "String",
                            "string.suffix",
                            quote! { !#v.ends_with(#suf) },
                        );
                    }
                    if let Some(cn) = &s.contains {
                        push_v(
                            &mut out,
                            "string",
                            14,
                            "contains",
                            9,
                            "String",
                            "string.contains",
                            quote! { !#v.contains(#cn) },
                        );
                    }
                    if s.uuid == Some(true) {
                        push_v(
                            &mut out,
                            "string",
                            14,
                            "uuid",
                            22,
                            "Bool",
                            "string.uuid",
                            quote! { !::protovalidate_buffa::rules::string::is_uuid(&#v) },
                        );
                    }
                }
            }
            FieldKind::Bytes => {
                if let Some(b) = &std.bytes {
                    if let Some(n) = b.min_len {
                        let n_usize = usize::try_from(n).expect("len fits in usize");
                        push_v(
                            &mut out,
                            "bytes",
                            15,
                            "min_len",
                            2,
                            "Uint64",
                            "bytes.min_len",
                            quote! { #v.len() < #n_usize },
                        );
                    }
                    if let Some(n) = b.max_len {
                        let n_usize = usize::try_from(n).expect("len fits in usize");
                        push_v(
                            &mut out,
                            "bytes",
                            15,
                            "max_len",
                            3,
                            "Uint64",
                            "bytes.max_len",
                            quote! { #v.len() > #n_usize },
                        );
                    }
                }
            }
            FieldKind::Bool => {
                if let Some(b) = &std.bool_rules {
                    if let Some(c) = b.r#const {
                        push_v(
                            &mut out,
                            "bool",
                            13,
                            "const",
                            1,
                            "Bool",
                            "bool.const",
                            quote! { #v != #c },
                        );
                    }
                }
            }
            _ => {}
        }
        return out;
    }
    out
}

/// Emit metadata-bearing numeric checks that operate on an arbitrary value
/// expression `v` (owned copy for Copy types like i32 etc.). Used by oneof
/// variant emission.
pub(crate) fn emit_numeric_checks_on(
    v: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    kind: &FieldKind,
    std: &crate::scan::StandardRules,
) -> Vec<TokenStream> {
    let fam = match kind {
        FieldKind::Int32 => NUM_INT32,
        FieldKind::Sint32 => NUM_SINT32,
        FieldKind::Sfixed32 => NUM_SFIXED32,
        FieldKind::Int64 => NUM_INT64,
        FieldKind::Sint64 => NUM_SINT64,
        FieldKind::Sfixed64 => NUM_SFIXED64,
        FieldKind::Uint32 => NUM_UINT32,
        FieldKind::Fixed32 => NUM_FIXED32,
        FieldKind::Uint64 => NUM_UINT64,
        FieldKind::Fixed64 => NUM_FIXED64,
        FieldKind::Float => FLOAT_FAM,
        FieldKind::Double => DOUBLE_FAM,
        _ => return Vec::new(),
    };
    let field_path_expr = field_path_scalar(name_lit, field_number, fam.scalar_ty);
    let mut out: Vec<TokenStream> = Vec::new();
    let push_cmp = |out: &mut Vec<TokenStream>,
                    inner_name: &str,
                    inner_num: i32,
                    rule_id: String,
                    cond: TokenStream| {
        let field = field_path_expr.clone();
        let rule = rule_path_scalar(
            fam.family,
            fam.outer_number,
            inner_name,
            inner_num,
            fam.scalar_ty,
        );
        out.push(quote! {
            if #cond {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        });
    };
    let is_float = matches!(kind, FieldKind::Float | FieldKind::Double);
    match kind {
        FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32 => {
            if let Some(n) = &std.int32 {
                if let Some(c) = n.r#const {
                    push_cmp(
                        &mut out,
                        "const",
                        INNER_CONST,
                        format!("{}.const", fam.family),
                        quote! { #v != #c },
                    );
                }
                if let Some(lo) = n.gt {
                    push_cmp(
                        &mut out,
                        "gt",
                        INNER_GT,
                        format!("{}.gt", fam.family),
                        quote! { #v <= #lo },
                    );
                }
                if let Some(lo) = n.gte {
                    push_cmp(
                        &mut out,
                        "gte",
                        INNER_GTE,
                        format!("{}.gte", fam.family),
                        quote! { #v < #lo },
                    );
                }
                if let Some(hi) = n.lt {
                    push_cmp(
                        &mut out,
                        "lt",
                        INNER_LT,
                        format!("{}.lt", fam.family),
                        quote! { #v >= #hi },
                    );
                }
                if let Some(hi) = n.lte {
                    push_cmp(
                        &mut out,
                        "lte",
                        INNER_LTE,
                        format!("{}.lte", fam.family),
                        quote! { #v > #hi },
                    );
                }
            }
        }
        FieldKind::Int64 | FieldKind::Sint64 | FieldKind::Sfixed64 => {
            if let Some(n) = &std.int64 {
                if let Some(c) = n.r#const {
                    push_cmp(
                        &mut out,
                        "const",
                        INNER_CONST,
                        format!("{}.const", fam.family),
                        quote! { #v != #c },
                    );
                }
                if let Some(lo) = n.gt {
                    push_cmp(
                        &mut out,
                        "gt",
                        INNER_GT,
                        format!("{}.gt", fam.family),
                        quote! { #v <= #lo },
                    );
                }
                if let Some(lo) = n.gte {
                    push_cmp(
                        &mut out,
                        "gte",
                        INNER_GTE,
                        format!("{}.gte", fam.family),
                        quote! { #v < #lo },
                    );
                }
                if let Some(hi) = n.lt {
                    push_cmp(
                        &mut out,
                        "lt",
                        INNER_LT,
                        format!("{}.lt", fam.family),
                        quote! { #v >= #hi },
                    );
                }
                if let Some(hi) = n.lte {
                    push_cmp(
                        &mut out,
                        "lte",
                        INNER_LTE,
                        format!("{}.lte", fam.family),
                        quote! { #v > #hi },
                    );
                }
            }
        }
        FieldKind::Uint32 | FieldKind::Fixed32 => {
            if let Some(n) = &std.uint32 {
                if let Some(c) = n.r#const {
                    push_cmp(
                        &mut out,
                        "const",
                        INNER_CONST,
                        format!("{}.const", fam.family),
                        quote! { #v != #c },
                    );
                }
                if let Some(lo) = n.gt {
                    push_cmp(
                        &mut out,
                        "gt",
                        INNER_GT,
                        format!("{}.gt", fam.family),
                        quote! { #v <= #lo },
                    );
                }
                if let Some(lo) = n.gte {
                    push_cmp(
                        &mut out,
                        "gte",
                        INNER_GTE,
                        format!("{}.gte", fam.family),
                        quote! { #v < #lo },
                    );
                }
                if let Some(hi) = n.lt {
                    push_cmp(
                        &mut out,
                        "lt",
                        INNER_LT,
                        format!("{}.lt", fam.family),
                        quote! { #v >= #hi },
                    );
                }
                if let Some(hi) = n.lte {
                    push_cmp(
                        &mut out,
                        "lte",
                        INNER_LTE,
                        format!("{}.lte", fam.family),
                        quote! { #v > #hi },
                    );
                }
            }
        }
        FieldKind::Uint64 | FieldKind::Fixed64 => {
            if let Some(n) = &std.uint64 {
                if let Some(c) = n.r#const {
                    push_cmp(
                        &mut out,
                        "const",
                        INNER_CONST,
                        format!("{}.const", fam.family),
                        quote! { #v != #c },
                    );
                }
                if let Some(lo) = n.gt {
                    push_cmp(
                        &mut out,
                        "gt",
                        INNER_GT,
                        format!("{}.gt", fam.family),
                        quote! { #v <= #lo },
                    );
                }
                if let Some(lo) = n.gte {
                    push_cmp(
                        &mut out,
                        "gte",
                        INNER_GTE,
                        format!("{}.gte", fam.family),
                        quote! { #v < #lo },
                    );
                }
                if let Some(hi) = n.lt {
                    push_cmp(
                        &mut out,
                        "lt",
                        INNER_LT,
                        format!("{}.lt", fam.family),
                        quote! { #v >= #hi },
                    );
                }
                if let Some(hi) = n.lte {
                    push_cmp(
                        &mut out,
                        "lte",
                        INNER_LTE,
                        format!("{}.lte", fam.family),
                        quote! { #v > #hi },
                    );
                }
            }
        }
        FieldKind::Float => {
            if let Some(f) = &std.float {
                if let Some(c) = f.r#const {
                    push_cmp(
                        &mut out,
                        "const",
                        INNER_CONST,
                        format!("{}.const", fam.family),
                        quote! { #v != #c },
                    );
                }
                if let Some(lo) = f.gt {
                    push_cmp(
                        &mut out,
                        "gt",
                        INNER_GT,
                        format!("{}.gt", fam.family),
                        quote! { !(#v > #lo) },
                    );
                }
                if let Some(lo) = f.gte {
                    push_cmp(
                        &mut out,
                        "gte",
                        INNER_GTE,
                        format!("{}.gte", fam.family),
                        quote! { !(#v >= #lo) },
                    );
                }
                if let Some(hi) = f.lt {
                    push_cmp(
                        &mut out,
                        "lt",
                        INNER_LT,
                        format!("{}.lt", fam.family),
                        quote! { !(#v < #hi) },
                    );
                }
                if let Some(hi) = f.lte {
                    push_cmp(
                        &mut out,
                        "lte",
                        INNER_LTE,
                        format!("{}.lte", fam.family),
                        quote! { !(#v <= #hi) },
                    );
                }
            }
        }
        FieldKind::Double => {
            if let Some(d) = &std.double {
                if let Some(c) = d.r#const {
                    push_cmp(
                        &mut out,
                        "const",
                        INNER_CONST,
                        format!("{}.const", fam.family),
                        quote! { #v != #c },
                    );
                }
                if let Some(lo) = d.gt {
                    push_cmp(
                        &mut out,
                        "gt",
                        INNER_GT,
                        format!("{}.gt", fam.family),
                        quote! { !(#v > #lo) },
                    );
                }
                if let Some(lo) = d.gte {
                    push_cmp(
                        &mut out,
                        "gte",
                        INNER_GTE,
                        format!("{}.gte", fam.family),
                        quote! { !(#v >= #lo) },
                    );
                }
                if let Some(hi) = d.lt {
                    push_cmp(
                        &mut out,
                        "lt",
                        INNER_LT,
                        format!("{}.lt", fam.family),
                        quote! { !(#v < #hi) },
                    );
                }
                if let Some(hi) = d.lte {
                    push_cmp(
                        &mut out,
                        "lte",
                        INNER_LTE,
                        format!("{}.lte", fam.family),
                        quote! { !(#v <= #hi) },
                    );
                }
            }
        }
        _ => {}
    }
    let _ = is_float;
    out
}

pub(crate) const fn kind_to_field_type(k: &FieldKind) -> &'static str {
    match k {
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
        FieldKind::Repeated(_) | FieldKind::Map { .. } | FieldKind::Optional(_) => "Message",
    }
}

fn safe_ident(name: &str) -> syn::Ident {
    if syn::parse_str::<syn::Ident>(name).is_ok() {
        format_ident!("{}", name)
    } else {
        syn::Ident::new_raw(name, proc_macro2::Span::call_site())
    }
}

/// Metadata describing a numeric rule family (e.g. int32, sint32, ...).
/// Drives FieldPath/Rule path metadata emission.
#[derive(Clone, Copy)]
pub(crate) struct NumFamily {
    /// Rule family name used in `rule_id` (e.g. "int32").
    pub family: &'static str,
    /// FieldRules outer field number for this family (validate.proto).
    pub outer_number: i32,
    /// FieldType variant name for the element (e.g. "Int32", "Sint32").
    pub scalar_ty: &'static str,
}

pub(crate) const NUM_INT32: NumFamily = NumFamily {
    family: "int32",
    outer_number: 3,
    scalar_ty: "Int32",
};
pub(crate) const NUM_INT64: NumFamily = NumFamily {
    family: "int64",
    outer_number: 4,
    scalar_ty: "Int64",
};
pub(crate) const NUM_UINT32: NumFamily = NumFamily {
    family: "uint32",
    outer_number: 5,
    scalar_ty: "Uint32",
};
pub(crate) const NUM_UINT64: NumFamily = NumFamily {
    family: "uint64",
    outer_number: 6,
    scalar_ty: "Uint64",
};
pub(crate) const NUM_SINT32: NumFamily = NumFamily {
    family: "sint32",
    outer_number: 7,
    scalar_ty: "Sint32",
};
pub(crate) const NUM_SINT64: NumFamily = NumFamily {
    family: "sint64",
    outer_number: 8,
    scalar_ty: "Sint64",
};
pub(crate) const NUM_FIXED32: NumFamily = NumFamily {
    family: "fixed32",
    outer_number: 9,
    scalar_ty: "Fixed32",
};
pub(crate) const NUM_FIXED64: NumFamily = NumFamily {
    family: "fixed64",
    outer_number: 10,
    scalar_ty: "Fixed64",
};
pub(crate) const NUM_SFIXED32: NumFamily = NumFamily {
    family: "sfixed32",
    outer_number: 11,
    scalar_ty: "Sfixed32",
};
pub(crate) const NUM_SFIXED64: NumFamily = NumFamily {
    family: "sfixed64",
    outer_number: 12,
    scalar_ty: "Sfixed64",
};

/// FieldRules inner rule numbers, shared across all scalar numeric families.
const INNER_CONST: i32 = 1;
const INNER_LT: i32 = 2;
const INNER_LTE: i32 = 3;
const INNER_GT: i32 = 4;
const INNER_GTE: i32 = 5;
const INNER_IN: i32 = 6;
const INNER_NOT_IN: i32 = 7;

fn emit_bool(
    accessor: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    b: &BoolStandard,
) -> Vec<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    if let Some(c) = b.r#const {
        let field_path = field_path_scalar(name_lit, field_number, "Bool");
        let rule_path = rule_path_scalar("bool", 13, "const", 1, "Bool");
        out.push(quote! {
            if self.#accessor != #c {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field_path,
                    rule: #rule_path,
                    rule_id: ::std::borrow::Cow::Borrowed("bool.const"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must equal {} (got {})", #c, self.#accessor
                    )),
                    for_key: false,
                });
            }
        });
    }
    out
}

/// Build a single-element FieldPath for a scalar field whose descriptor
/// field number and proto type are both known.
fn field_path_scalar(name: &str, number: i32, type_variant: &str) -> TokenStream {
    let ty = format_ident!("{}", type_variant);
    quote! {
        ::protovalidate_buffa::FieldPath {
            elements: ::std::vec![
                ::protovalidate_buffa::FieldPathElement {
                    field_number: Some(#number),
                    field_name: Some(::std::borrow::Cow::Borrowed(#name)),
                    field_type: Some(::protovalidate_buffa::FieldType::#ty),
                    key_type: None,
                    value_type: None,
                    subscript: None,
                },
            ],
        }
    }
}

/// Float/double variant of `range_check`: uses negated satisfaction checks so
/// NaN values correctly violate (since `NaN op X` is always false in IEEE).
fn range_check_fp(
    field: &TokenStream,
    fam: NumFamily,
    inclusive_bounds: bool,
    lower: &TokenStream,
    upper: &TokenStream,
    val: &TokenStream,
    is_exclusive: bool,
) -> TokenStream {
    let (lo_name, lo_num, rule_id_base) = if inclusive_bounds {
        ("gte", INNER_GTE, format!("{}.gte_lte", fam.family))
    } else {
        ("gt", INNER_GT, format!("{}.gt_lt", fam.family))
    };
    let rule_path = rule_path_scalar(fam.family, fam.outer_number, lo_name, lo_num, fam.scalar_ty);
    let rule_id = if is_exclusive {
        format!("{rule_id_base}_exclusive")
    } else {
        rule_id_base
    };
    let cond = if is_exclusive {
        // Exclusive: value must be OUTSIDE the range. Use negated form so
        // NaN (fails all comparisons) correctly violates.
        if inclusive_bounds {
            // gte/lte exclusive: endpoints satisfy (val >= gt_val OR val <= lt_val).
            quote! { !((#val) >= (#lower) || (#val) <= (#upper)) }
        } else {
            // gt/lt exclusive: endpoints violate (val > gt_val OR val < lt_val).
            quote! { !((#val) > (#lower) || (#val) < (#upper)) }
        }
    } else if inclusive_bounds {
        quote! { !((#val) >= (#lower) && (#val) <= (#upper)) }
    } else {
        quote! { !((#val) > (#lower) && (#val) < (#upper)) }
    };
    quote! {
        if #cond {
            violations.push(::protovalidate_buffa::Violation {
                field: #field, rule: #rule_path,
                rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                message: ::std::borrow::Cow::Owned(::std::format!("value out of range (got {})", #val)),
                for_key: false,
            });
        }
    }
}

/// Emit a combined-range check. `inclusive_bounds=true` uses gte/lte; otherwise
/// gt/lt. `is_exclusive=true` means the value must be OUTSIDE the range
/// (upper < lower).
fn range_check(
    field: &TokenStream,
    fam: NumFamily,
    inclusive_bounds: bool,
    lower: &TokenStream,
    upper: &TokenStream,
    val: &TokenStream,
    is_exclusive: bool,
) -> TokenStream {
    let (lo_name, lo_num, rule_id_base) = if inclusive_bounds {
        ("gte", INNER_GTE, format!("{}.gte_lte", fam.family))
    } else {
        ("gt", INNER_GT, format!("{}.gt_lt", fam.family))
    };
    let rule_path = rule_path_scalar(fam.family, fam.outer_number, lo_name, lo_num, fam.scalar_ty);
    let rule_id = if is_exclusive {
        format!("{rule_id_base}_exclusive")
    } else {
        rule_id_base
    };
    let cond = if is_exclusive {
        // Exclusive: value must be OUTSIDE the (upper, lower) range.
        // Violate when value is inside the forbidden interval.
        // - `gte`/`lte` (inclusive_bounds=true): endpoints satisfy the rule,
        //   so violation uses strict interior: (upper, lower).
        // - `gt`/`lt` (inclusive_bounds=false): endpoints violate, so violation
        //   interval is closed: [upper, lower].
        if inclusive_bounds {
            quote! { (#val) > (#upper) && (#val) < (#lower) }
        } else {
            quote! { (#val) >= (#upper) && (#val) <= (#lower) }
        }
    } else if inclusive_bounds {
        quote! { (#val) < (#lower) || (#val) > (#upper) }
    } else {
        quote! { (#val) <= (#lower) || (#val) >= (#upper) }
    };
    quote! {
        if #cond {
            violations.push(::protovalidate_buffa::Violation {
                field: #field, rule: #rule_path,
                rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                message: ::std::borrow::Cow::Owned(::std::format!("value out of range (got {})", #val)),
                for_key: false,
            });
        }
    }
}

/// Build a two-element rule path like `bool.const`: the outer field of
/// FieldRules (always TYPE_MESSAGE) plus the inner scalar rule field.
fn rule_path_scalar(
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

use crate::scan::{DurationStandard, TimestampStandard};

/// Convert a (seconds, nanos) pair to an i128 total-nanoseconds representation
/// so comparisons are exact.
fn emit_duration_rules(
    accessor: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    d: &DurationStandard,
) -> Vec<TokenStream> {
    let fp = || field_path_scalar(name_lit, field_number, "Message");
    let rp = |inner: &str, inner_num: i32, inner_ty: &str| {
        rule_path_scalar("duration", 21, inner, inner_num, inner_ty)
    };
    let ns = |p: (i64, i32)| -> TokenStream {
        let secs = p.0 as i128;
        let nanos = p.1 as i128;
        let total = secs * 1_000_000_000 + nanos;
        let total_i128 = proc_macro2::Literal::i128_suffixed(total);
        quote! { #total_i128 }
    };
    let v = quote! { (self.#accessor.as_option().map_or(0i128, |d| (d.seconds as i128) * 1_000_000_000 + (d.nanos as i128))) };
    let has_v = quote! { self.#accessor.is_set() };

    let mut out: Vec<TokenStream> = Vec::new();
    let push = |out: &mut Vec<TokenStream>,
                inner: &str,
                inner_num: i32,
                ty: &str,
                rule_id: &str,
                cond: TokenStream| {
        let f = fp();
        let r = rp(inner, inner_num, ty);
        let rid = rule_id.to_string();
        out.push(quote! {
            if #has_v && #cond {
                violations.push(::protovalidate_buffa::Violation {
                    field: #f, rule: #r,
                    rule_id: ::std::borrow::Cow::Borrowed(#rid),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        });
    };

    // Combined ranges: gt+lt => gt_lt/_exclusive, gte+lte => gte_lte/_exclusive.
    if let (Some(lo), Some(hi)) = (d.gt, d.lt) {
        let lo_ns = ns(lo);
        let hi_ns = ns(hi);
        let is_excl = ns_cmp_lt(hi, lo);
        let (base, strict) = ("duration.gt_lt", true);
        let rule_id = if is_excl {
            format!("{base}_exclusive")
        } else {
            base.to_string()
        };
        let cond = if is_excl {
            quote! { #v >= #hi_ns && #v <= #lo_ns }
        } else {
            quote! { #v <= #lo_ns || #v >= #hi_ns }
        };
        let _ = strict;
        let f = fp();
        let r = rp("gt", 5, "Message");
        out.push(quote! {
            if #has_v && #cond {
                violations.push(::protovalidate_buffa::Violation {
                    field: #f, rule: #r,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        });
        return out;
    }
    if let (Some(lo), Some(hi)) = (d.gte, d.lte) {
        let lo_ns = ns(lo);
        let hi_ns = ns(hi);
        let is_excl = ns_cmp_lt(hi, lo);
        let rule_id = if is_excl {
            "duration.gte_lte_exclusive".to_string()
        } else {
            "duration.gte_lte".to_string()
        };
        let cond = if is_excl {
            quote! { #v > #hi_ns && #v < #lo_ns }
        } else {
            quote! { #v < #lo_ns || #v > #hi_ns }
        };
        let f = fp();
        let r = rp("gte", 6, "Message");
        out.push(quote! {
            if #has_v && #cond {
                violations.push(::protovalidate_buffa::Violation {
                    field: #f, rule: #r,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        });
        return out;
    }

    if let Some(c) = d.r#const {
        let c_ns = ns(c);
        push(
            &mut out,
            "const",
            2,
            "Message",
            "duration.const",
            quote! { #v != #c_ns },
        );
    }
    if let Some(hi) = d.lt {
        let hi_ns = ns(hi);
        push(
            &mut out,
            "lt",
            3,
            "Message",
            "duration.lt",
            quote! { #v >= #hi_ns },
        );
    }
    if let Some(hi) = d.lte {
        let hi_ns = ns(hi);
        push(
            &mut out,
            "lte",
            4,
            "Message",
            "duration.lte",
            quote! { #v > #hi_ns },
        );
    }
    if let Some(lo) = d.gt {
        let lo_ns = ns(lo);
        push(
            &mut out,
            "gt",
            5,
            "Message",
            "duration.gt",
            quote! { #v <= #lo_ns },
        );
    }
    if let Some(lo) = d.gte {
        let lo_ns = ns(lo);
        push(
            &mut out,
            "gte",
            6,
            "Message",
            "duration.gte",
            quote! { #v < #lo_ns },
        );
    }
    if !d.in_set.is_empty() {
        let vals: Vec<TokenStream> = d.in_set.iter().map(|&p| ns(p)).collect();
        let f = fp();
        let r = rp("in", 7, "Message");
        out.push(quote! {
            if #has_v {
                let actual = #v;
                const ALLOWED: &[i128] = &[ #( #vals ),* ];
                if !ALLOWED.iter().any(|x| *x == actual) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #f, rule: #r,
                        rule_id: ::std::borrow::Cow::Borrowed("duration.in"),
                        message: ::std::borrow::Cow::Borrowed(""),
                        for_key: false,
                    });
                }
            }
        });
    }
    if !d.not_in.is_empty() {
        let vals: Vec<TokenStream> = d.not_in.iter().map(|&p| ns(p)).collect();
        let f = fp();
        let r = rp("not_in", 8, "Message");
        out.push(quote! {
            if #has_v {
                let actual = #v;
                const DISALLOWED: &[i128] = &[ #( #vals ),* ];
                if DISALLOWED.iter().any(|x| *x == actual) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #f, rule: #r,
                        rule_id: ::std::borrow::Cow::Borrowed("duration.not_in"),
                        message: ::std::borrow::Cow::Borrowed(""),
                        for_key: false,
                    });
                }
            }
        });
    }
    out
}

fn emit_timestamp_rules(
    accessor: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    t: &TimestampStandard,
) -> Vec<TokenStream> {
    let fp = || field_path_scalar(name_lit, field_number, "Message");
    let rp = |inner: &str, inner_num: i32, inner_ty: &str| {
        rule_path_scalar("timestamp", 22, inner, inner_num, inner_ty)
    };
    let ns = |p: (i64, i32)| -> TokenStream {
        let total = (p.0 as i128) * 1_000_000_000 + (p.1 as i128);
        let total_i128 = proc_macro2::Literal::i128_suffixed(total);
        quote! { #total_i128 }
    };
    let v = quote! { (self.#accessor.as_option().map_or(0i128, |ts| (ts.seconds as i128) * 1_000_000_000 + (ts.nanos as i128))) };
    let has_v = quote! { self.#accessor.is_set() };

    let mut out: Vec<TokenStream> = Vec::new();
    let push = |out: &mut Vec<TokenStream>,
                inner: &str,
                inner_num: i32,
                ty: &str,
                rule_id: &str,
                cond: TokenStream| {
        let f = fp();
        let r = rp(inner, inner_num, ty);
        let rid = rule_id.to_string();
        out.push(quote! {
            if #has_v && #cond {
                violations.push(::protovalidate_buffa::Violation {
                    field: #f, rule: #r,
                    rule_id: ::std::borrow::Cow::Borrowed(#rid),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        });
    };
    // Combined ranges.
    if let (Some(lo), Some(hi)) = (t.gt, t.lt) {
        let lo_ns = ns(lo);
        let hi_ns = ns(hi);
        let is_excl = ns_cmp_lt(hi, lo);
        let rule_id = if is_excl {
            "timestamp.gt_lt_exclusive".to_string()
        } else {
            "timestamp.gt_lt".to_string()
        };
        let cond = if is_excl {
            quote! { #v >= #hi_ns && #v <= #lo_ns }
        } else {
            quote! { #v <= #lo_ns || #v >= #hi_ns }
        };
        let f = fp();
        let r = rp("gt", 5, "Message");
        out.push(quote! {
            if #has_v && #cond {
                violations.push(::protovalidate_buffa::Violation {
                    field: #f, rule: #r,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        });
        return out;
    }
    if let (Some(lo), Some(hi)) = (t.gte, t.lte) {
        let lo_ns = ns(lo);
        let hi_ns = ns(hi);
        let is_excl = ns_cmp_lt(hi, lo);
        let rule_id = if is_excl {
            "timestamp.gte_lte_exclusive".to_string()
        } else {
            "timestamp.gte_lte".to_string()
        };
        let cond = if is_excl {
            quote! { #v > #hi_ns && #v < #lo_ns }
        } else {
            quote! { #v < #lo_ns || #v > #hi_ns }
        };
        let f = fp();
        let r = rp("gte", 6, "Message");
        out.push(quote! {
            if #has_v && #cond {
                violations.push(::protovalidate_buffa::Violation {
                    field: #f, rule: #r,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        });
        return out;
    }

    if let Some(c) = t.r#const {
        let c_ns = ns(c);
        push(
            &mut out,
            "const",
            2,
            "Message",
            "timestamp.const",
            quote! { #v != #c_ns },
        );
    }
    if let Some(lo) = t.gt {
        let lo_ns = ns(lo);
        push(
            &mut out,
            "gt",
            5,
            "Message",
            "timestamp.gt",
            quote! { #v <= #lo_ns },
        );
    }
    if let Some(lo) = t.gte {
        let lo_ns = ns(lo);
        push(
            &mut out,
            "gte",
            6,
            "Message",
            "timestamp.gte",
            quote! { #v < #lo_ns },
        );
    }
    if let Some(hi) = t.lt {
        let hi_ns = ns(hi);
        push(
            &mut out,
            "lt",
            3,
            "Message",
            "timestamp.lt",
            quote! { #v >= #hi_ns },
        );
    }
    if let Some(hi) = t.lte {
        let hi_ns = ns(hi);
        push(
            &mut out,
            "lte",
            4,
            "Message",
            "timestamp.lte",
            quote! { #v > #hi_ns },
        );
    }
    if t.lt_now {
        let f = fp();
        let r = rp("lt_now", 7, "Bool");
        out.push(quote! {
            if #has_v {
                let now_ns = ::std::time::SystemTime::now().duration_since(::std::time::UNIX_EPOCH).map_or(0i128, |d| d.as_nanos() as i128);
                if #v >= now_ns {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #f, rule: #r,
                        rule_id: ::std::borrow::Cow::Borrowed("timestamp.lt_now"),
                        message: ::std::borrow::Cow::Borrowed(""),
                        for_key: false,
                    });
                }
            }
        });
    }
    if t.gt_now {
        let f = fp();
        let r = rp("gt_now", 8, "Bool");
        out.push(quote! {
            if #has_v {
                let now_ns = ::std::time::SystemTime::now().duration_since(::std::time::UNIX_EPOCH).map_or(0i128, |d| d.as_nanos() as i128);
                if #v <= now_ns {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #f, rule: #r,
                        rule_id: ::std::borrow::Cow::Borrowed("timestamp.gt_now"),
                        message: ::std::borrow::Cow::Borrowed(""),
                        for_key: false,
                    });
                }
            }
        });
    }
    if let Some(w) = t.within {
        let w_ns = ns(w);
        let f = fp();
        let r = rp("within", 9, "Message");
        out.push(quote! {
            if #has_v {
                let now_ns = ::std::time::SystemTime::now().duration_since(::std::time::UNIX_EPOCH).map_or(0i128, |d| d.as_nanos() as i128);
                let delta = (#v - now_ns).abs();
                if delta > #w_ns {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #f, rule: #r,
                        rule_id: ::std::borrow::Cow::Borrowed("timestamp.within"),
                        message: ::std::borrow::Cow::Borrowed(""),
                        for_key: false,
                    });
                }
            }
        });
    }
    out
}

const fn ns_cmp_lt(a: (i64, i32), b: (i64, i32)) -> bool {
    let an = (a.0 as i128) * 1_000_000_000 + (a.1 as i128);
    let bn = (b.0 as i128) * 1_000_000_000 + (b.1 as i128);
    an < bn
}

/// Metadata-bearing string rule checks on an arbitrary `v: &String` (used
/// by oneof variant emission).
pub(crate) fn emit_string_checks_on(
    v: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    s: &StringStandard,
) -> Vec<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    let fp = || field_path_scalar(name_lit, field_number, "String");
    let rp = |inner: &str, inner_num: i32, ty: &str| {
        rule_path_scalar("string", 14, inner, inner_num, ty)
    };
    let push = |out: &mut Vec<TokenStream>,
                inner: &str,
                inner_num: i32,
                ty: &str,
                rule_id: &str,
                cond: TokenStream| {
        let field = fp();
        let rule = rp(inner, inner_num, ty);
        let rid = rule_id.to_string();
        out.push(quote! {
            if #cond {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rid),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        });
    };
    if let Some(c) = &s.r#const {
        push(
            &mut out,
            "const",
            1,
            "String",
            "string.const",
            quote! { #v != #c },
        );
    }
    if let Some(n) = s.min_len {
        let n_usize = usize::try_from(n).expect("len fits in usize");
        push(
            &mut out,
            "min_len",
            2,
            "Uint64",
            "string.min_len",
            quote! { #v.chars().count() < #n_usize },
        );
    }
    if let Some(n) = s.max_len {
        let n_usize = usize::try_from(n).expect("len fits in usize");
        push(
            &mut out,
            "max_len",
            3,
            "Uint64",
            "string.max_len",
            quote! { #v.chars().count() > #n_usize },
        );
    }
    if let Some(n) = s.min_bytes {
        let n_usize = usize::try_from(n).expect("len fits in usize");
        push(
            &mut out,
            "min_bytes",
            4,
            "Uint64",
            "string.min_bytes",
            quote! { #v.len() < #n_usize },
        );
    }
    if let Some(n) = s.max_bytes {
        let n_usize = usize::try_from(n).expect("len fits in usize");
        push(
            &mut out,
            "max_bytes",
            5,
            "Uint64",
            "string.max_bytes",
            quote! { #v.len() > #n_usize },
        );
    }
    if let Some(pre) = &s.prefix {
        push(
            &mut out,
            "prefix",
            7,
            "String",
            "string.prefix",
            quote! { !#v.starts_with(#pre) },
        );
    }
    if let Some(suf) = &s.suffix {
        push(
            &mut out,
            "suffix",
            8,
            "String",
            "string.suffix",
            quote! { !#v.ends_with(#suf) },
        );
    }
    if let Some(cn) = &s.contains {
        push(
            &mut out,
            "contains",
            9,
            "String",
            "string.contains",
            quote! { !#v.contains(#cn) },
        );
    }
    if let Some(nc) = &s.not_contains {
        push(
            &mut out,
            "not_contains",
            23,
            "String",
            "string.not_contains",
            quote! { #v.contains(#nc) },
        );
    }
    if !s.in_set.is_empty() {
        let set = &s.in_set;
        let field = fp();
        let rule = rp("in", 10, "String");
        out.push(quote! {
            {
                const ALLOWED: &[&str] = &[ #( #set ),* ];
                if !ALLOWED.iter().any(|c| *c == #v.as_str()) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("string.in"),
                        message: ::std::borrow::Cow::Borrowed(""),
                        for_key: false,
                    });
                }
            }
        });
    }
    if !s.not_in_set.is_empty() {
        let set = &s.not_in_set;
        let field = fp();
        let rule = rp("not_in", 11, "String");
        out.push(quote! {
            {
                const DISALLOWED: &[&str] = &[ #( #set ),* ];
                if DISALLOWED.iter().any(|c| *c == #v.as_str()) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("string.not_in"),
                        message: ::std::borrow::Cow::Borrowed(""),
                        for_key: false,
                    });
                }
            }
        });
    }
    if let Some(pat) = &s.pattern {
        let pat_str = pat.as_str();
        let field = fp();
        let rule = rp("pattern", 6, "String");
        let cache_ident = format_ident!(
            "RE_ONEOF_{}",
            name_lit
                .to_uppercase()
                .replace(|c: char| !c.is_alphanumeric(), "_")
        );
        out.push(quote! {
            {
                static #cache_ident: ::std::sync::OnceLock<::protovalidate_buffa::regex::Regex> =
                    ::std::sync::OnceLock::new();
                let re = #cache_ident.get_or_init(|| {
                    ::protovalidate_buffa::regex::Regex::new(#pat_str)
                        .expect("pattern regex compiled at code-gen time")
                });
                if !re.is_match(#v) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("string.pattern"),
                        message: ::std::borrow::Cow::Borrowed(""),
                        for_key: false,
                    });
                }
            }
        });
    }
    out
}
