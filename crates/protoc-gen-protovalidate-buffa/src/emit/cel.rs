//! Native CEL emission.
//!
//! For each `(buf.validate.*)` CEL rule on a message, attempts to transpile
//! the expression to direct Rust at codegen time. On success emits a tight
//! `if/match` block that pushes the violation only when the rule fails. On
//! failure (unsupported construct or a rule that always raises a CEL
//! runtime error), emits a `__cel_runtime_error__` violation marker so the
//! runtime no longer needs an interpreter.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::{
    emit::cel_compile::{
        Binding, CelType, CompileOutput, Compiler, FallbackKind, MapTy, MessageFieldEntry,
        MessageSchema, RustScalar, SchemaFieldKind,
    },
    scan::{FieldKind, FieldValidator, MessageValidators},
};

/// Emit the per-message `(message).cel`, `(field).cel`, and predefined CEL
/// rules as native Rust checks plus the optional fallback runtime-error
/// markers.
///
/// Returns `(statics, calls)` — statics go outside the impl block, calls go
/// inside the `validate` body after field/oneof blocks.
#[must_use]
pub fn emit_message_level(
    msg: &MessageValidators,
    schemas: &SchemaIndex,
) -> (Vec<TokenStream>, Vec<TokenStream>) {
    let statics = Vec::new();
    let mut calls = Vec::new();
    let msg_schema = build_message_schema(msg);
    for rule in &msg.message_cel {
        if let Some(native) = try_emit_native_message_cel(rule, &msg_schema, schemas) {
            calls.push(native);
            continue;
        }
        // Unsupported CEL — emit a runtime-error violation so users see a
        // clear runtime signal that the rule couldn't be transpiled.
        calls.push(emit_runtime_error_violation(
            &rule.id,
            &format!("unsupported CEL: {}", rule.expression),
        ));
    }
    // Field-level CEL rules (`(field).cel = {...}`): evaluate with `this` bound to
    // the field value, not the outer message.
    for f in &msg.field_rules {
        if f.cel.is_empty() {
            continue;
        }
        if f.oneof_name.is_some() {
            continue;
        }
        if matches!(f.ignore, crate::scan::Ignore::Always) {
            continue;
        }
        if is_unsupported_wkt_field_for_cel(&f.field_type) {
            continue;
        }
        let field_ident = format_ident!("{}", f.field_name);
        let field_name = &f.field_name;
        let fnum = f.field_number;
        // For repeated scalars the CEL rule path uses the element type; for
        // messages it's Message (Group if proto3/editions TYPE_GROUP field).
        // Optional<T> also unwraps to T.
        let field_ty_variant = if f.is_group {
            "Group"
        } else {
            match &f.field_type {
                crate::scan::FieldKind::Repeated(inner)
                | crate::scan::FieldKind::Optional(inner) => {
                    crate::emit::field::kind_to_field_type(inner)
                }
                _ => crate::emit::field::kind_to_field_type(&f.field_type),
            }
        };
        let ty_ident = format_ident!("{}", field_ty_variant);
        let field_path = quote! {
            ::protovalidate_buffa::FieldPath {
                elements: ::std::vec![
                    ::protovalidate_buffa::FieldPathElement {
                        field_number: Some(#fnum),
                        field_name: Some(::std::borrow::Cow::Borrowed(#field_name)),
                        field_type: Some(::protovalidate_buffa::FieldType::#ty_ident),
                        key_type: None,
                        value_type: None,
                        subscript: None,
                    },
                ],
            }
        };
        let mut cel_idx: u64 = 0;
        let mut expr_idx: u64 = 0;
        for rule in &f.cel {
            let fp = field_path.clone();
            // `idx_lit` is the slot index in the rule path: `cel[idx]` or
            // `cel_expression[idx]` depending on which list the rule came
            // from.
            let idx_lit = if rule.is_cel_expression {
                let i = expr_idx;
                expr_idx += 1;
                i
            } else {
                let i = cel_idx;
                cel_idx += 1;
                i
            };
            // Try compile-time expansion first; on failure emit a
            // runtime-error marker so the unsupported rule surfaces
            // clearly at validate-time.
            if let Some(native_call) =
                try_emit_native_field_cel(f, rule, &fp, idx_lit, &field_ident, schemas)
            {
                calls.push(native_call);
                continue;
            }
            calls.push(emit_runtime_error_violation(
                &rule.id,
                &format!("unsupported CEL: {}", rule.expression),
            ));
        }
    }
    // Predefined (extension-based) CEL rules.
    for f in &msg.field_rules {
        if f.standard.predefined.is_empty() {
            continue;
        }
        if f.oneof_name.is_some() {
            continue;
        }
        if matches!(f.ignore, crate::scan::Ignore::Always) {
            continue;
        }
        let default_family = predef_family_for(&f.field_type);
        let field_ident = format_ident!("{}", f.field_name);
        let field_name = &f.field_name;
        let fnum = f.field_number;
        for rule in &f.standard.predefined {
            let family = match rule.family_override {
                Some((name, number)) => Family { name, number },
                None => match default_family {
                    Some(f) => f,
                    None => continue,
                },
            };
            let family_name = family.name;
            let family_num = family.number;
            let family_fty = format_ident!("Message");
            let ext_fty = format_ident!("{}", rule.ext_field_type);
            let ext_bracketed = format!("[buf.validate.conformance.cases.{}]", rule.ext_name);
            let ext_num = rule.ext_number;
            // For Optional<T> (proto2 / editions explicit) or Repeated<T>,
            // the field path uses inner scalar type. Wrapper/Map keep
            // TYPE_MESSAGE.
            let field_ty_variant = match &f.field_type {
                crate::scan::FieldKind::Optional(inner)
                | crate::scan::FieldKind::Repeated(inner) => {
                    crate::emit::field::kind_to_field_type(inner)
                }
                _ => crate::emit::field::kind_to_field_type(&f.field_type),
            };
            let field_ty_ident = format_ident!("{}", field_ty_variant);
            // Try compile-time expansion; emit a runtime-error marker when
            // anything in the expression isn't transpilable.
            let predef_rule_path = quote! {
                ::protovalidate_buffa::FieldPath {
                    elements: ::std::vec![
                        ::protovalidate_buffa::FieldPathElement {
                            field_number: Some(#family_num),
                            field_name: Some(::std::borrow::Cow::Borrowed(#family_name)),
                            field_type: Some(::protovalidate_buffa::FieldType::#family_fty),
                            key_type: None, value_type: None, subscript: None,
                        },
                        ::protovalidate_buffa::FieldPathElement {
                            field_number: Some(#ext_num),
                            field_name: Some(::std::borrow::Cow::Borrowed(#ext_bracketed)),
                            field_type: Some(::protovalidate_buffa::FieldType::#ext_fty),
                            key_type: None, value_type: None, subscript: None,
                        },
                    ],
                }
            };
            let predef_field_path = quote! {
                ::protovalidate_buffa::FieldPath {
                    elements: ::std::vec![
                        ::protovalidate_buffa::FieldPathElement {
                            field_number: Some(#fnum),
                            field_name: Some(::std::borrow::Cow::Borrowed(#field_name)),
                            field_type: Some(::protovalidate_buffa::FieldType::#field_ty_ident),
                            key_type: None, value_type: None, subscript: None,
                        },
                    ],
                }
            };
            if let Some(native_call) = try_emit_native_predefined(
                f,
                rule,
                &field_ident,
                &predef_field_path,
                &predef_rule_path,
            ) {
                calls.push(native_call);
                continue;
            }
            calls.push(emit_runtime_error_violation(
                &rule.id,
                &format!("unsupported CEL: {}", rule.expression),
            ));
        }
    }
    (statics, calls)
}

#[derive(Clone, Copy)]
pub(crate) struct Family {
    pub name: &'static str,
    pub number: i32,
}

pub(crate) fn predef_family_for(kind: &crate::scan::FieldKind) -> Option<Family> {
    use crate::scan::FieldKind;
    let underlying = match kind {
        FieldKind::Optional(i) | FieldKind::Wrapper(i) | FieldKind::Repeated(i) => i.as_ref(),
        other => other,
    };
    match underlying {
        FieldKind::Float => Some(Family {
            name: "float",
            number: 1,
        }),
        FieldKind::Double => Some(Family {
            name: "double",
            number: 2,
        }),
        FieldKind::Int32 => Some(Family {
            name: "int32",
            number: 3,
        }),
        FieldKind::Int64 => Some(Family {
            name: "int64",
            number: 4,
        }),
        FieldKind::Uint32 => Some(Family {
            name: "uint32",
            number: 5,
        }),
        FieldKind::Uint64 => Some(Family {
            name: "uint64",
            number: 6,
        }),
        FieldKind::Sint32 => Some(Family {
            name: "sint32",
            number: 7,
        }),
        FieldKind::Sint64 => Some(Family {
            name: "sint64",
            number: 8,
        }),
        FieldKind::Fixed32 => Some(Family {
            name: "fixed32",
            number: 9,
        }),
        FieldKind::Fixed64 => Some(Family {
            name: "fixed64",
            number: 10,
        }),
        FieldKind::Sfixed32 => Some(Family {
            name: "sfixed32",
            number: 11,
        }),
        FieldKind::Sfixed64 => Some(Family {
            name: "sfixed64",
            number: 12,
        }),
        FieldKind::Bool => Some(Family {
            name: "bool",
            number: 13,
        }),
        FieldKind::String => Some(Family {
            name: "string",
            number: 14,
        }),
        FieldKind::Bytes => Some(Family {
            name: "bytes",
            number: 15,
        }),
        FieldKind::Enum { .. } => Some(Family {
            name: "enum",
            number: 16,
        }),
        FieldKind::Message { full_name } => match full_name.as_str() {
            "google.protobuf.Duration" => Some(Family {
                name: "duration",
                number: 21,
            }),
            "google.protobuf.Timestamp" => Some(Family {
                name: "timestamp",
                number: 22,
            }),
            "google.protobuf.Any" => Some(Family {
                name: "any",
                number: 20,
            }),
            "google.protobuf.FieldMask" => Some(Family {
                name: "field_mask",
                number: 28,
            }),
            "google.protobuf.FloatValue" => Some(Family {
                name: "float",
                number: 1,
            }),
            "google.protobuf.DoubleValue" => Some(Family {
                name: "double",
                number: 2,
            }),
            "google.protobuf.Int32Value" => Some(Family {
                name: "int32",
                number: 3,
            }),
            "google.protobuf.Int64Value" => Some(Family {
                name: "int64",
                number: 4,
            }),
            "google.protobuf.UInt32Value" => Some(Family {
                name: "uint32",
                number: 5,
            }),
            "google.protobuf.UInt64Value" => Some(Family {
                name: "uint64",
                number: 6,
            }),
            "google.protobuf.BoolValue" => Some(Family {
                name: "bool",
                number: 13,
            }),
            "google.protobuf.StringValue" => Some(Family {
                name: "string",
                number: 14,
            }),
            "google.protobuf.BytesValue" => Some(Family {
                name: "bytes",
                number: 15,
            }),
            _ => None,
        },
        _ => None,
    }
}

fn is_unsupported_wkt_field_for_cel(kind: &FieldKind) -> bool {
    match kind {
        FieldKind::Message { full_name } => is_unsupported_wkt_for_cel(full_name),
        FieldKind::Repeated(inner) | FieldKind::Optional(inner) => {
            is_unsupported_wkt_field_for_cel(inner)
        }
        _ => false,
    }
}

pub(crate) fn is_unsupported_wkt_for_cel(full_name: &str) -> bool {
    full_name.starts_with("google.protobuf.") && !cel_supports_wkt(full_name)
}

/// True for the small set of `google.protobuf.*` well-known types that
/// have first-class CEL semantics in protovalidate (`Any`, `Empty`,
/// `FieldMask`, `Duration`, `Timestamp`). Other WKTs are skipped when
/// emitting `(field).cel` / `(message).cel` rules.
pub(crate) const fn cel_supports_wkt(full_name: &str) -> bool {
    matches!(
        full_name.as_bytes(),
        b"google.protobuf.Any"
            | b"google.protobuf.Empty"
            | b"google.protobuf.FieldMask"
            | b"google.protobuf.Timestamp"
            | b"google.protobuf.Duration"
    )
}

/// Attempt to emit a `(field).cel` rule as native Rust. Returns `None` if the
/// expression can't be transpiled — the caller responds by emitting a
/// `__cel_runtime_error__` violation marker via `emit_runtime_error_violation`.
/// `Some(tokens)` splices straight into the validate body.
pub(crate) fn try_emit_native_field_cel(
    f: &FieldValidator,
    rule: &crate::scan::CelRule,
    field_path: &TokenStream,
    idx_lit: u64,
    field_ident: &syn::Ident,
    schemas: &SchemaIndex,
) -> Option<TokenStream> {
    // First, try the message-typed `this` binding for fields whose type is
    // a known sub-message (e.g., `optional Inner val = 1` with a CEL rule
    // like `this.val == 'foo'`). Falls back to the scalar path below.
    if let Some(out) = try_emit_native_field_cel_message(f, rule, field_path, field_ident, schemas)
    {
        return Some(out);
    }
    let this_ty = scalar_this_for_with(&f.field_type, Some(schemas))?;
    let access = field_this_access(f, field_ident, &this_ty)?;
    let mut compiler = Compiler::new();
    compiler.bind(
        "this",
        Binding {
            rust_expr: quote! { (__cel_this) },
            ty: this_ty,
            constant: None,
        },
    );
    let CompileOutput {
        tokens,
        ty,
        needs_now,
    } = compiler.compile(&rule.expression).ok()?;
    let now_prelude = if needs_now {
        quote! { let now = ::protovalidate_buffa::cel::now_local(); }
    } else {
        quote! {}
    };
    let rule_path = rule_path_for_field_cel(rule.is_cel_expression, idx_lit);
    let fp = field_path.clone();
    let id_lit = &rule.id;
    let msg_lit = &rule.message;
    let check = match ty {
        CelType::Bool => quote! {
            if !(#tokens) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #fp,
                    rule: #rule_path,
                    rule_id: ::std::borrow::Cow::Borrowed(#id_lit),
                    message: ::std::borrow::Cow::Borrowed(#msg_lit),
                    for_key: false,
                });
            }
        },
        CelType::Str { owned: true } => quote! {
            {
                let __cel_result: ::std::string::String = (#tokens);
                if !__cel_result.is_empty() {
                    let __msg: ::std::borrow::Cow<'static, str> = if (#msg_lit as &str).is_empty() {
                        ::std::borrow::Cow::Owned(__cel_result)
                    } else {
                        ::std::borrow::Cow::Borrowed(#msg_lit)
                    };
                    violations.push(::protovalidate_buffa::Violation {
                        field: #fp,
                        rule: #rule_path,
                        rule_id: ::std::borrow::Cow::Borrowed(#id_lit),
                        message: __msg,
                        for_key: false,
                    });
                }
            }
        },
        CelType::Str { owned: false } => quote! {
            {
                let __cel_result: &str = (#tokens);
                if !__cel_result.is_empty() {
                    let __msg: ::std::borrow::Cow<'static, str> = if (#msg_lit as &str).is_empty() {
                        ::std::borrow::Cow::Owned(__cel_result.to_owned())
                    } else {
                        ::std::borrow::Cow::Borrowed(#msg_lit)
                    };
                    violations.push(::protovalidate_buffa::Violation {
                        field: #fp,
                        rule: #rule_path,
                        rule_id: ::std::borrow::Cow::Borrowed(#id_lit),
                        message: __msg,
                        for_key: false,
                    });
                }
            }
        },
        _ => return None,
    };
    let body = quote! {
        let __cel_this = #access;
        #now_prelude
        #check
    };
    Some(match &f.field_type {
        FieldKind::Optional(_) => quote! {
            if let ::core::option::Option::Some(__cel_inner) = self.#field_ident.as_ref() {
                #body
            }
        },
        FieldKind::Wrapper(_) => quote! {
            if let ::core::option::Option::Some(__cel_inner) = self.#field_ident.as_option() {
                #body
            }
        },
        FieldKind::Message { full_name }
            if full_name == "google.protobuf.Duration"
                || full_name == "google.protobuf.Timestamp" =>
        {
            quote! {
                if let ::core::option::Option::Some(__cel_inner) = self.#field_ident.as_option() {
                    #body
                }
            }
        }
        _ => quote! { { #body } },
    })
}

/// Map a `FieldKind` to the underlying Rust scalar / wrapper type. Returns
/// `None` for kinds that don't have a concrete scalar representation
/// (messages, nested maps, optional wrappers).
const fn rust_scalar_for_kind(kind: &FieldKind) -> Option<RustScalar> {
    Some(match kind {
        FieldKind::String => RustScalar::Str,
        FieldKind::Bytes => RustScalar::Bytes,
        FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32 => RustScalar::I32,
        FieldKind::Int64 | FieldKind::Sint64 | FieldKind::Sfixed64 => RustScalar::I64,
        FieldKind::Uint32 | FieldKind::Fixed32 => RustScalar::U32,
        FieldKind::Uint64 | FieldKind::Fixed64 => RustScalar::U64,
        FieldKind::Float => RustScalar::F32,
        FieldKind::Double => RustScalar::F64,
        FieldKind::Bool => RustScalar::Bool,
        FieldKind::Enum { .. } => RustScalar::I32,
        _ => return None,
    })
}

/// Decide whether a field's CEL `this` binding can be rendered as a scalar
/// (not a message). For an Optional/Wrapper inner type, the binding pulls the
/// inner value directly — code wrapping the access in `if let Some(...)` is
/// handled separately by [`field_this_access`].
fn scalar_this_for(kind: &FieldKind) -> Option<CelType> {
    scalar_this_for_with(kind, None)
}

/// Variant of [`scalar_this_for`] that resolves Message-typed contents
/// against a `SchemaIndex`. With `Some(schemas)`, Message-typed repeated /
/// map elements become `CelType::Message(<schema>)` so the transpiler can
/// emit nested field selects.
fn scalar_this_for_with(kind: &FieldKind, schemas: Option<&SchemaIndex>) -> Option<CelType> {
    let inner = match kind {
        FieldKind::Optional(i) | FieldKind::Wrapper(i) => i.as_ref(),
        FieldKind::Message { full_name } if full_name == "google.protobuf.Duration" => {
            return Some(CelType::Duration);
        }
        FieldKind::Message { full_name } if full_name == "google.protobuf.Timestamp" => {
            return Some(CelType::Timestamp);
        }
        FieldKind::Message { full_name } => {
            // For a Message-typed element we need the schema of that
            // message to compile nested selects. Without a schema, fall
            // back.
            let schema = schemas?.get(full_name)?.clone();
            return Some(CelType::Message(Box::new(schema)));
        }
        FieldKind::Map { key, value } => {
            let key_cel = scalar_this_for_with(key, schemas)?;
            let value_cel = scalar_this_for_with(value, schemas)?;
            let key_rust = rust_scalar_for_kind(key)?;
            // Map values may be messages, in which case the rust kind
            // lookup returns None. Use a sentinel so the index op can
            // still emit access.
            let value_rust = rust_scalar_for_kind(value).unwrap_or(RustScalar::Bool);
            return Some(CelType::Map(Box::new(MapTy {
                key_cel,
                value_cel,
                key_rust,
                value_rust,
            })));
        }
        other => other,
    };
    let cel_ty = match inner {
        FieldKind::String => CelType::Str { owned: false },
        FieldKind::Bytes => CelType::Bytes { owned: false },
        FieldKind::Int32
        | FieldKind::Int64
        | FieldKind::Sint32
        | FieldKind::Sint64
        | FieldKind::Sfixed32
        | FieldKind::Sfixed64 => CelType::Int,
        FieldKind::Uint32 | FieldKind::Uint64 | FieldKind::Fixed32 | FieldKind::Fixed64 => {
            CelType::UInt
        }
        FieldKind::Float | FieldKind::Double => CelType::Double,
        FieldKind::Bool => CelType::Bool,
        FieldKind::Enum { .. } => CelType::Int,
        FieldKind::Repeated(elem) => {
            let elem_ty = scalar_this_for_with(elem, schemas)?;
            CelType::List(Box::new(elem_ty))
        }
        _ => return None,
    };
    Some(cel_ty)
}

/// Build the Rust expression that yields the CEL `this` binding's value for
/// a given field. Optional/Wrapper presence is handled by the caller, which
/// wraps the entire check in `if let Some(__cel_inner) = …`.
fn field_this_access(
    f: &FieldValidator,
    field_ident: &syn::Ident,
    cel_ty: &CelType,
) -> Option<TokenStream> {
    match &f.field_type {
        FieldKind::Optional(inner) => Some(match (cel_ty, inner.as_ref()) {
            (CelType::Str { .. }, _) => quote! { __cel_inner.as_str() },
            (CelType::Bytes { .. }, _) => quote! { __cel_inner.as_slice() },
            (CelType::Int, FieldKind::Enum { .. }) => quote! {
                ({
                    use ::buffa::Enumeration as _;
                    (*__cel_inner).to_i32() as i64
                })
            },
            (CelType::Int, _) => quote! { ((*__cel_inner) as i64) },
            (CelType::UInt, _) => quote! { ((*__cel_inner) as u64) },
            (CelType::Double, _) => quote! { ((*__cel_inner) as f64) },
            (CelType::Bool, _) => quote! { (*__cel_inner) },
            _ => return None,
        }),
        FieldKind::Wrapper(_) => Some(match cel_ty {
            CelType::Str { .. } => quote! { __cel_inner.value.as_str() },
            CelType::Bytes { .. } => quote! { __cel_inner.value.as_slice() },
            CelType::Int => quote! { (__cel_inner.value as i64) },
            CelType::UInt => quote! { (__cel_inner.value as u64) },
            CelType::Double => quote! { (__cel_inner.value as f64) },
            CelType::Bool => quote! { (__cel_inner.value) },
            _ => return None,
        }),
        FieldKind::Enum { .. } => Some(quote! {
            ({
                use ::buffa::Enumeration as _;
                self.#field_ident.to_i32() as i64
            })
        }),
        FieldKind::String => Some(quote! { self.#field_ident.as_str() }),
        FieldKind::Bytes => Some(quote! { self.#field_ident.as_slice() }),
        FieldKind::Repeated(_) => Some(quote! { self.#field_ident.as_slice() }),
        FieldKind::Map { .. } => Some(quote! { (&self.#field_ident) }),
        FieldKind::Float
        | FieldKind::Double
        | FieldKind::Int32
        | FieldKind::Int64
        | FieldKind::Sint32
        | FieldKind::Sint64
        | FieldKind::Sfixed32
        | FieldKind::Sfixed64
        | FieldKind::Uint32
        | FieldKind::Uint64
        | FieldKind::Fixed32
        | FieldKind::Fixed64
        | FieldKind::Bool => Some(match cel_ty {
            CelType::Int => quote! { (self.#field_ident as i64) },
            CelType::UInt => quote! { (self.#field_ident as u64) },
            CelType::Double => quote! { (self.#field_ident as f64) },
            CelType::Bool => quote! { self.#field_ident },
            _ => return None,
        }),
        FieldKind::Message { full_name } if full_name == "google.protobuf.Duration" => {
            // Caller wraps in `if let Some(__cel_inner) = self.x.as_option()`.
            Some(quote! {
                ::protovalidate_buffa::cel::duration_from_secs_nanos(
                    __cel_inner.seconds,
                    __cel_inner.nanos,
                )
            })
        }
        FieldKind::Message { full_name } if full_name == "google.protobuf.Timestamp" => {
            Some(quote! {
                ::protovalidate_buffa::cel::timestamp_from_secs_nanos(
                    __cel_inner.seconds,
                    __cel_inner.nanos,
                )
            })
        }
        FieldKind::Message { .. } => None,
    }
}

/// Index of every emitted message's `MessageSchema`, keyed by proto FQN.
pub type SchemaIndex = std::collections::BTreeMap<String, MessageSchema>;

/// Build the `SchemaIndex` for every message the plugin is emitting.
#[must_use]
pub fn build_schema_index(messages: &[MessageValidators]) -> SchemaIndex {
    messages
        .iter()
        .map(|m| (m.proto_name.clone(), build_message_schema(m)))
        .collect()
}

/// Try the message-typed `this` shape: when `(field).cel` targets a
/// sub-message field, bind `this` to that message's schema so accesses like
/// `this.foo` work natively.
fn try_emit_native_field_cel_message(
    f: &FieldValidator,
    rule: &crate::scan::CelRule,
    field_path: &TokenStream,
    field_ident: &syn::Ident,
    schemas: &SchemaIndex,
) -> Option<TokenStream> {
    let inner_full_name = match &f.field_type {
        FieldKind::Message { full_name } => full_name.clone(),
        FieldKind::Optional(inner) | FieldKind::Wrapper(inner) => match inner.as_ref() {
            FieldKind::Message { full_name } => full_name.clone(),
            _ => return None,
        },
        _ => return None,
    };
    // Skip well-known types — they need their own CEL semantics handled by
    // the runtime impls.
    if inner_full_name.starts_with("google.protobuf.") {
        return None;
    }
    let inner_schema = schemas.get(&inner_full_name)?.clone();
    let mut compiler = Compiler::new();
    compiler.bind(
        "this",
        Binding {
            rust_expr: quote! { __cel_inner },
            ty: CelType::Message(Box::new(inner_schema)),
            constant: None,
        },
    );
    let CompileOutput {
        tokens,
        ty,
        needs_now,
    } = compiler.compile(&rule.expression).ok()?;
    let now_prelude = if needs_now {
        quote! { let now = ::protovalidate_buffa::cel::now_local(); }
    } else {
        quote! {}
    };
    let rule_path = rule_path_for_field_cel(rule.is_cel_expression, 0);
    let fp = field_path.clone();
    let id_lit = &rule.id;
    let msg_lit = &rule.message;
    let check = match ty {
        CelType::Bool => quote! {
            if !(#tokens) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #fp,
                    rule: #rule_path,
                    rule_id: ::std::borrow::Cow::Borrowed(#id_lit),
                    message: ::std::borrow::Cow::Borrowed(#msg_lit),
                    for_key: false,
                });
            }
        },
        CelType::Str { owned: true } => quote! {
            {
                let __cel_result: ::std::string::String = (#tokens);
                if !__cel_result.is_empty() {
                    let __msg: ::std::borrow::Cow<'static, str> = if (#msg_lit as &str).is_empty() {
                        ::std::borrow::Cow::Owned(__cel_result)
                    } else {
                        ::std::borrow::Cow::Borrowed(#msg_lit)
                    };
                    violations.push(::protovalidate_buffa::Violation {
                        field: #fp,
                        rule: #rule_path,
                        rule_id: ::std::borrow::Cow::Borrowed(#id_lit),
                        message: __msg,
                        for_key: false,
                    });
                }
            }
        },
        _ => return None,
    };
    let body = quote! {
        #now_prelude
        #check
    };
    // For `Message`-typed fields buffa exposes `MessageField<T>`; for
    // proto2/editions `optional Msg` it's also `MessageField<T>` (via
    // `as_option()`). For both we gate on `.as_option()` to honor
    // "skip on unset".
    Some(quote! {
        if let ::core::option::Option::Some(__cel_inner) = self.#field_ident.as_option() {
            #body
        }
    })
}

/// Emit a `__cel_runtime_error__` violation marker.
///
/// Matches the shape the runtime previously produced for CEL runtime
/// errors. The enclosing `validate()` method lifts these into the
/// `runtime_error` slot of `ValidationError`. `rule_id` is included in
/// the message for diagnosability.
pub(crate) fn emit_runtime_error_violation(rule_id: &str, reason: &str) -> TokenStream {
    let msg = format!("cel runtime error in rule {rule_id:?}: {reason}");
    quote! {
        violations.push(::protovalidate_buffa::Violation {
            field: ::protovalidate_buffa::FieldPath::default(),
            rule: ::protovalidate_buffa::FieldPath::default(),
            rule_id: ::std::borrow::Cow::Borrowed("__cel_runtime_error__"),
            message: ::std::borrow::Cow::Borrowed(#msg),
            for_key: false,
        });
    }
}

/// Try to compile a CEL expression natively with a pre-built `this` binding.
///
/// `this_expr` is the Rust expression substituted everywhere `this` appears.
/// `this_ty` describes the CEL type of that expression. `rule_const` is
/// `Some(_)` only for predefined rules, where it folds `rule` references
/// into compile-time literals.
///
/// Returns the violation-pushing check, ready to splice inside any loop /
/// guard the caller supplies. Returns `None` when the expression isn't
/// transpilable, leaving the caller to decide between emitting a
/// runtime-error marker or skipping the rule entirely.
#[expect(
    clippy::too_many_arguments,
    reason = "each parameter directly maps to a piece of state the transpiler needs; collapsing into a builder would obscure rather than simplify the call sites"
)]
pub(crate) fn try_compile_cel_check(
    expression: &str,
    rule_id: &str,
    static_msg: &str,
    this_expr: TokenStream,
    this_ty: CelType,
    rule_const: Option<&crate::scan::RuleConst>,
    field_path: &TokenStream,
    rule_path: &TokenStream,
    for_key: bool,
) -> Option<TokenStream> {
    let mut compiler = Compiler::new();
    compiler.bind(
        "this",
        Binding {
            rust_expr: this_expr,
            ty: this_ty,
            constant: None,
        },
    );
    if let Some(rc) = rule_const {
        compiler.bind_rule_const("rule", rc);
        compiler.bind_rule_const("rules", rc);
    }
    let CompileOutput {
        tokens,
        ty,
        needs_now,
    } = compiler.compile(expression).ok()?;
    let now_prelude = if needs_now {
        quote! { let now = ::protovalidate_buffa::cel::now_local(); }
    } else {
        quote! {}
    };
    let fp = field_path.clone();
    let rp = rule_path.clone();
    let for_key_lit = for_key;
    let check = match ty {
        CelType::Bool => quote! {
            if !(#tokens) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #fp,
                    rule: #rp,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Borrowed(#static_msg),
                    for_key: #for_key_lit,
                });
            }
        },
        CelType::Str { owned: true } => quote! {
            {
                let __cel_result: ::std::string::String = (#tokens);
                if !__cel_result.is_empty() {
                    let __msg: ::std::borrow::Cow<'static, str> = if (#static_msg as &str).is_empty() {
                        ::std::borrow::Cow::Owned(__cel_result)
                    } else {
                        ::std::borrow::Cow::Borrowed(#static_msg)
                    };
                    violations.push(::protovalidate_buffa::Violation {
                        field: #fp,
                        rule: #rp,
                        rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                        message: __msg,
                        for_key: #for_key_lit,
                    });
                }
            }
        },
        CelType::Str { owned: false } => quote! {
            {
                let __cel_result: &str = (#tokens);
                if !__cel_result.is_empty() {
                    let __msg: ::std::borrow::Cow<'static, str> = if (#static_msg as &str).is_empty() {
                        ::std::borrow::Cow::Owned(__cel_result.to_owned())
                    } else {
                        ::std::borrow::Cow::Borrowed(#static_msg)
                    };
                    violations.push(::protovalidate_buffa::Violation {
                        field: #fp,
                        rule: #rp,
                        rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                        message: __msg,
                        for_key: #for_key_lit,
                    });
                }
            }
        },
        _ => return None,
    };
    Some(quote! {
        #now_prelude
        #check
    })
}

/// Derive the `(this_expr, CelType)` to bind for a single proto field /
/// element of a given `FieldKind`. The `operand` is the Rust expression
/// already producing a value of the field's underlying Rust type (e.g.
/// `elem` for `&i32`, `self.foo` for direct access). Returns `None` when the
/// field kind isn't transpilable as a scalar `this`.
pub(crate) fn this_binding_for_kind(
    kind: &FieldKind,
    operand: &TokenStream,
) -> Option<(TokenStream, CelType)> {
    this_binding_for_kind_with(kind, operand, None)
}

/// Variant of [`this_binding_for_kind`] that resolves Message-typed
/// elements against a `SchemaIndex`. When provided, items.cel / values.cel
/// rules on repeated / map elements whose element type is a known
/// sub-message bind `this` to that message's schema.
pub(crate) fn this_binding_for_kind_with(
    kind: &FieldKind,
    operand: &TokenStream,
    schemas: Option<&SchemaIndex>,
) -> Option<(TokenStream, CelType)> {
    if let FieldKind::Message { full_name } = kind
        && let Some(s) = schemas
        && let Some(schema) = s.get(full_name).cloned()
    {
        return Some((quote! { (#operand) }, CelType::Message(Box::new(schema))));
    }
    match kind {
        FieldKind::String => Some((quote! { (#operand) }, CelType::Str { owned: false })),
        FieldKind::Bytes => Some((quote! { (#operand) }, CelType::Bytes { owned: false })),
        FieldKind::Int32
        | FieldKind::Int64
        | FieldKind::Sint32
        | FieldKind::Sint64
        | FieldKind::Sfixed32
        | FieldKind::Sfixed64 => Some((
            quote! { (::protovalidate_buffa::cel::CelScalar::cel_int(#operand)) },
            CelType::Int,
        )),
        FieldKind::Uint32 | FieldKind::Uint64 | FieldKind::Fixed32 | FieldKind::Fixed64 => Some((
            quote! { (::protovalidate_buffa::cel::CelScalar::cel_uint(#operand)) },
            CelType::UInt,
        )),
        FieldKind::Float | FieldKind::Double => Some((
            quote! { (::protovalidate_buffa::cel::CelScalar::cel_double(#operand)) },
            CelType::Double,
        )),
        FieldKind::Bool => Some((quote! { (#operand) }, CelType::Bool)),
        FieldKind::Enum { .. } => Some((
            quote! { (::protovalidate_buffa::cel::CelScalar::cel_int(#operand)) },
            CelType::Int,
        )),
        _ => None,
    }
}

/// Build a schema describing every top-level proto field of a message,
/// suitable for the transpiler's `Message` binding.
fn build_message_schema(msg: &MessageValidators) -> MessageSchema {
    let fields = msg
        .field_rules
        .iter()
        .filter(|f| f.field_number != -1)
        .filter_map(field_to_schema_entry)
        .collect();
    MessageSchema { fields }
}

fn field_to_schema_entry(f: &FieldValidator) -> Option<MessageFieldEntry> {
    let proto_name = f.field_name.clone();
    let rust_ident = f.field_name.clone();
    let (ty, kind) = match &f.field_type {
        FieldKind::String => (CelType::Str { owned: false }, SchemaFieldKind::StringLike),
        FieldKind::Bytes => (CelType::Bytes { owned: false }, SchemaFieldKind::StringLike),
        FieldKind::Int32
        | FieldKind::Int64
        | FieldKind::Sint32
        | FieldKind::Sint64
        | FieldKind::Sfixed32
        | FieldKind::Sfixed64 => (CelType::Int, SchemaFieldKind::Scalar),
        FieldKind::Uint32 | FieldKind::Uint64 | FieldKind::Fixed32 | FieldKind::Fixed64 => {
            (CelType::UInt, SchemaFieldKind::Scalar)
        }
        FieldKind::Float | FieldKind::Double => (CelType::Double, SchemaFieldKind::Scalar),
        FieldKind::Bool => (CelType::Bool, SchemaFieldKind::Scalar),
        FieldKind::Enum { .. } => (CelType::Int, SchemaFieldKind::Scalar),
        FieldKind::Optional(inner) => {
            let inner_ty = scalar_this_for(inner)?;
            (inner_ty, SchemaFieldKind::Optional)
        }
        FieldKind::Wrapper(inner) => {
            let inner_ty = scalar_this_for(inner)?;
            (inner_ty, SchemaFieldKind::Wrapper)
        }
        FieldKind::Repeated(inner) => {
            let elem = scalar_this_for(inner)?;
            (CelType::List(Box::new(elem)), SchemaFieldKind::Repeated)
        }
        // Sub-messages and maps: marked as Message kind so `has()` works
        // but field-selection on them isn't yet supported (the transpiler
        // falls back when descending into them).
        FieldKind::Message { full_name } => (
            CelType::Dyn,
            SchemaFieldKind::Message {
                proto_fqn: Some(full_name.clone()),
            },
        ),
        FieldKind::Map { .. } => (CelType::Dyn, SchemaFieldKind::Message { proto_fqn: None }),
    };
    Some(MessageFieldEntry {
        proto_name,
        rust_ident,
        ty,
        kind,
    })
}

fn try_emit_native_message_cel(
    rule: &crate::scan::CelRule,
    schema: &MessageSchema,
    schemas: &SchemaIndex,
) -> Option<TokenStream> {
    let mut compiler = Compiler::new().with_schemas(schemas);
    compiler.bind(
        "this",
        Binding {
            rust_expr: quote! { self },
            ty: CelType::Message(Box::new(schema.clone())),
            constant: None,
        },
    );
    let CompileOutput {
        tokens,
        ty,
        needs_now,
    } = match compiler.compile(&rule.expression) {
        Ok(c) => c,
        Err(e) if e.kind == FallbackKind::RuntimeError => {
            return Some(emit_runtime_error_violation(&rule.id, &e.message));
        }
        Err(_) => return None,
    };
    let now_prelude = if needs_now {
        quote! { let now = ::protovalidate_buffa::cel::now_local(); }
    } else {
        quote! {}
    };
    let id_lit = &rule.id;
    let msg_lit = &rule.message;
    // Wrap the body in a closure that returns `Option<T>` so nested
    // sub-message accesses (`this.e.a == this.f.a`) can short-circuit via
    // `?` when a sub-message is unset. Mirrors protovalidate's
    // `NoSuchKey => skip` semantics for `(message).cel` rules.
    let check = match ty {
        CelType::Bool => quote! {
            let __cel_result: ::core::option::Option<bool> =
                (|| -> ::core::option::Option<bool> { ::core::option::Option::Some(#tokens) })();
            if ::core::matches!(__cel_result, ::core::option::Option::Some(false)) {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::FieldPath::default(),
                    rule: ::protovalidate_buffa::FieldPath::default(),
                    rule_id: ::std::borrow::Cow::Borrowed(#id_lit),
                    message: ::std::borrow::Cow::Borrowed(#msg_lit),
                    for_key: false,
                });
            }
        },
        CelType::Str { owned: true } => quote! {
            let __cel_result: ::core::option::Option<::std::string::String> =
                (|| -> ::core::option::Option<::std::string::String> {
                    ::core::option::Option::Some((#tokens))
                })();
            if let ::core::option::Option::Some(__cel_s) = __cel_result {
                if !__cel_s.is_empty() {
                    let __msg: ::std::borrow::Cow<'static, str> = if (#msg_lit as &str).is_empty() {
                        ::std::borrow::Cow::Owned(__cel_s)
                    } else {
                        ::std::borrow::Cow::Borrowed(#msg_lit)
                    };
                    violations.push(::protovalidate_buffa::Violation {
                        field: ::protovalidate_buffa::FieldPath::default(),
                        rule: ::protovalidate_buffa::FieldPath::default(),
                        rule_id: ::std::borrow::Cow::Borrowed(#id_lit),
                        message: __msg,
                        for_key: false,
                    });
                }
            }
        },
        CelType::Str { owned: false } => quote! {
            // Borrowed-string result captures `self` so it can't escape a
            // closure without lifetime gymnastics. Inline the check
            // directly — borrowed-string results never reference sub-
            // messages that might be unset (only literals + receiver
            // access), so no `?` short-circuit is needed.
            {
                let __cel_result: &str = (#tokens);
                if !__cel_result.is_empty() {
                    let __msg: ::std::borrow::Cow<'static, str> = if (#msg_lit as &str).is_empty() {
                        ::std::borrow::Cow::Owned(__cel_result.to_owned())
                    } else {
                        ::std::borrow::Cow::Borrowed(#msg_lit)
                    };
                    violations.push(::protovalidate_buffa::Violation {
                        field: ::protovalidate_buffa::FieldPath::default(),
                        rule: ::protovalidate_buffa::FieldPath::default(),
                        rule_id: ::std::borrow::Cow::Borrowed(#id_lit),
                        message: __msg,
                        for_key: false,
                    });
                }
            }
        },
        _ => return None,
    };
    Some(quote! {
        {
            #now_prelude
            #check
        }
    })
}

/// Attempt to emit a predefined-rule CEL expression natively. `rule` is
/// bound from the extension's typed value (see `RuleConst`), `this` from the
/// field's value. Returns `None` when the expression can't be transpiled —
/// the caller then emits a `__cel_runtime_error__` violation marker.
pub(crate) fn try_emit_native_predefined(
    f: &FieldValidator,
    rule: &crate::scan::PredefinedCel,
    field_ident: &syn::Ident,
    field_path: &TokenStream,
    rule_path: &TokenStream,
) -> Option<TokenStream> {
    let rule_const = rule.rule_const.as_ref()?;
    let this_ty = scalar_this_for(&f.field_type)?;
    let access = field_this_access(f, field_ident, &this_ty)?;
    let mut compiler = Compiler::new();
    compiler.bind(
        "this",
        Binding {
            rust_expr: quote! { (__cel_this) },
            ty: this_ty,
            constant: None,
        },
    );
    compiler.bind_rule_const("rule", rule_const);
    // The runtime also exposes "rules" as a built-in alias in some
    // protovalidate setups. Bind both so transpiled expressions work either
    // way.
    compiler.bind_rule_const("rules", rule_const);
    let CompileOutput {
        tokens,
        ty,
        needs_now,
    } = compiler.compile(&rule.expression).ok()?;
    let now_prelude = if needs_now {
        quote! { let now = ::protovalidate_buffa::cel::now_local(); }
    } else {
        quote! {}
    };
    let fp = field_path.clone();
    let rp = rule_path.clone();
    let id_lit = &rule.id;
    let msg_lit = &rule.message;
    let check = match ty {
        CelType::Bool => quote! {
            if !(#tokens) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #fp,
                    rule: #rp,
                    rule_id: ::std::borrow::Cow::Borrowed(#id_lit),
                    message: ::std::borrow::Cow::Borrowed(#msg_lit),
                    for_key: false,
                });
            }
        },
        CelType::Str { owned: true } => quote! {
            {
                let __cel_result: ::std::string::String = (#tokens);
                if !__cel_result.is_empty() {
                    let __msg: ::std::borrow::Cow<'static, str> = if (#msg_lit as &str).is_empty() {
                        ::std::borrow::Cow::Owned(__cel_result)
                    } else {
                        ::std::borrow::Cow::Borrowed(#msg_lit)
                    };
                    violations.push(::protovalidate_buffa::Violation {
                        field: #fp,
                        rule: #rp,
                        rule_id: ::std::borrow::Cow::Borrowed(#id_lit),
                        message: __msg,
                        for_key: false,
                    });
                }
            }
        },
        CelType::Str { owned: false } => quote! {
            {
                let __cel_result: &str = (#tokens);
                if !__cel_result.is_empty() {
                    let __msg: ::std::borrow::Cow<'static, str> = if (#msg_lit as &str).is_empty() {
                        ::std::borrow::Cow::Owned(__cel_result.to_owned())
                    } else {
                        ::std::borrow::Cow::Borrowed(#msg_lit)
                    };
                    violations.push(::protovalidate_buffa::Violation {
                        field: #fp,
                        rule: #rp,
                        rule_id: ::std::borrow::Cow::Borrowed(#id_lit),
                        message: __msg,
                        for_key: false,
                    });
                }
            }
        },
        _ => return None,
    };
    let body = quote! {
        let __cel_this = #access;
        #now_prelude
        #check
    };
    Some(match &f.field_type {
        FieldKind::Optional(_) => quote! {
            if let ::core::option::Option::Some(__cel_inner) = self.#field_ident.as_ref() {
                #body
            }
        },
        FieldKind::Wrapper(_) => quote! {
            if let ::core::option::Option::Some(__cel_inner) = self.#field_ident.as_option() {
                #body
            }
        },
        FieldKind::Message { full_name }
            if full_name == "google.protobuf.Duration"
                || full_name == "google.protobuf.Timestamp" =>
        {
            quote! {
                if let ::core::option::Option::Some(__cel_inner) = self.#field_ident.as_option() {
                    #body
                }
            }
        }
        _ => quote! { { #body } },
    })
}

fn rule_path_for_field_cel(is_cel_expression: bool, idx_lit: u64) -> TokenStream {
    if is_cel_expression {
        quote! {
            ::protovalidate_buffa::FieldPath {
                elements: ::std::vec![::protovalidate_buffa::FieldPathElement {
                    field_number: Some(29),
                    field_name: Some(::std::borrow::Cow::Borrowed("cel_expression")),
                    field_type: Some(::protovalidate_buffa::FieldType::String),
                    key_type: None, value_type: None,
                    subscript: Some(::protovalidate_buffa::Subscript::Index(#idx_lit)),
                }],
            }
        }
    } else {
        quote! {
            ::protovalidate_buffa::FieldPath {
                elements: ::std::vec![::protovalidate_buffa::FieldPathElement {
                    field_number: Some(23),
                    field_name: Some(::std::borrow::Cow::Borrowed("cel")),
                    field_type: Some(::protovalidate_buffa::FieldType::Message),
                    key_type: None, value_type: None,
                    subscript: Some(::protovalidate_buffa::Subscript::Index(#idx_lit)),
                }],
            }
        }
    }
}
