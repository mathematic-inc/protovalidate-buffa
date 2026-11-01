//! Native CEL emission.
//!
//! For each `(buf.validate.*)` CEL rule on a message, attempts to transpile
//! the expression to direct Rust at codegen time. On success emits a tight
//! `if/match` block that pushes the violation only when the rule fails. On
//! failure (unsupported construct or a rule that always raises a CEL
//! runtime error), emits a `__cel_runtime_error__` violation marker so the
//! runtime no longer needs an interpreter.

use proc_macro2::TokenStream;
use quote::quote;

use crate::{
    emit::cel_compile::{
        Binding, CelType, CompileOutput, Compiler, FallbackKind, MapTy, MessageFieldEntry,
        MessageSchema, RustScalar, SchemaFieldKind, wkt_value,
    },
    scan::{FieldKind, FieldValidator, MessageValidators},
};

/// Emit message-level CEL; field and item rules use the shared value engine.
///
/// Returns `(statics, calls)` — statics go outside the impl block, calls go
/// inside the `validate` body after field/oneof blocks.
#[must_use]
pub(crate) fn emit_message_level(
    msg: &MessageValidators,
    schemas: &SchemaIndex,
    shape: crate::emit::Shape,
) -> (Vec<TokenStream>, Vec<TokenStream>) {
    let statics = Vec::new();
    let mut calls = Vec::new();
    let mut msg_schema = build_message_schema(msg);
    let mut shaped_schemas = schemas.clone();
    if matches!(shape, crate::emit::Shape::View) {
        for schema in std::iter::once(&mut msg_schema).chain(shaped_schemas.values_mut()) {
            for entry in &mut schema.fields {
                if let SchemaFieldKind::Oneof { view, .. } = &mut entry.kind {
                    *view = true;
                }
            }
        }
    }
    let schemas = &shaped_schemas;
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
/// handled by the caller.
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
            // Keep message references when building the schema index. Resolving
            // them lazily supports repeated and cyclic message declarations.
            return Some(schemas.and_then(|index| index.get(full_name)).map_or_else(
                || CelType::MessageRef(full_name.clone()),
                |schema| CelType::Message(Box::new(schema.clone())),
            ));
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

/// Bind a whole collection for the shared custom-rule emitter.
pub(super) fn collection_binding(
    field: &FieldValidator,
    accessor: &syn::Ident,
    schemas: &SchemaIndex,
    shape: super::Shape,
) -> Option<(TokenStream, CelType)> {
    let access = match field.field_type {
        FieldKind::Repeated(_) => quote! { (&self.#accessor) },
        FieldKind::Map { .. } => shape.map_access(accessor, field.field_number),
        _ => return None,
    };
    let ty = scalar_this_for_with(&field.field_type, Some(schemas))?;
    Some((access, ty))
}

/// Index of message schemas, including FieldMask, keyed by proto FQN.
pub type SchemaIndex = std::collections::BTreeMap<String, MessageSchema>;

/// Build the `SchemaIndex` for emitted messages and the FieldMask well-known type.
#[must_use]
pub fn build_schema_index(messages: &[MessageValidators]) -> SchemaIndex {
    let mut index: SchemaIndex = messages
        .iter()
        .map(|m| (m.proto_name.clone(), build_message_schema(m)))
        .collect();
    // FieldMask retains its protobuf message shape in CEL, but its imported
    // descriptor is not normally among the messages being emitted.
    index
        .entry("google.protobuf.FieldMask".to_owned())
        .or_insert_with(|| MessageSchema {
            fields: vec![MessageFieldEntry {
                proto_name: "paths".to_owned(),
                rust_ident: "paths".to_owned(),
                ty: CelType::List(Box::new(CelType::Str { owned: false })),
                kind: SchemaFieldKind::Repeated,
            }],
        });
    index
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

/// Declare the `__cel_error` cell a compiled check records CEL runtime errors
/// in, when it can raise any. A recorded error replaces the violations the
/// check pushed with a `__cel_runtime_error__` marker, since the rule has no
/// result.
fn catch_runtime_errors(compiler: &Compiler<'_>, rule_id: &str, check: TokenStream) -> TokenStream {
    if !compiler.raises_runtime_errors() {
        return check;
    }
    let prefix = format!("cel runtime error in rule {rule_id:?}: ");
    quote! {
        {
            let __cel_error =
                ::core::cell::Cell::new(::core::option::Option::<&'static str>::None);
            let __cel_violations = violations.len();
            #check
            if let ::core::option::Option::Some(__cel_reason) = __cel_error.take() {
                violations.truncate(__cel_violations);
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::FieldPath::default(),
                    rule: ::protovalidate_buffa::FieldPath::default(),
                    rule_id: ::std::borrow::Cow::Borrowed("__cel_runtime_error__"),
                    message: ::std::borrow::Cow::Owned(::std::format!("{}{}", #prefix, __cel_reason)),
                    for_key: false,
                });
            }
        }
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
    schemas: &SchemaIndex,
) -> Option<TokenStream> {
    let mut compiler = Compiler::new().with_schemas(schemas);
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
    let check = catch_runtime_errors(&compiler, rule_id, check);
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
pub(crate) fn this_binding_for_kind_with(
    kind: &FieldKind,
    operand: &TokenStream,
    schemas: Option<&SchemaIndex>,
) -> Option<(TokenStream, CelType)> {
    if let Some(ty) = scalar_this_for(kind)
        && let Some(value) = wkt_value(&ty, operand)
    {
        return Some((value, ty));
    }
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
            quote! {{
                #[allow(unused_imports, reason = "closed enums need the Enumeration trait")]
                use ::buffa::Enumeration as _;
                i64::from((#operand).to_i32())
            }},
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
        .filter_map(|field| {
            let mut entry = field_to_schema_entry(field)?;
            if let Some(oneof) = msg.oneof_rules.iter().find(|oneof| {
                oneof
                    .fields
                    .iter()
                    .any(|candidate| candidate.field_number == field.field_number)
            }) {
                entry.kind = SchemaFieldKind::Oneof {
                    accessor: oneof.rust_name.clone(),
                    parent_msg_name: oneof.parent_msg_name.clone(),
                    enumeration: super::oneof::to_pascal_case(&oneof.name),
                    variant: super::oneof::to_pascal_case(&field.field_name),
                    view: false,
                };
            }
            Some(entry)
        })
        .collect();
    MessageSchema { fields }
}

fn field_to_schema_entry(f: &FieldValidator) -> Option<MessageFieldEntry> {
    let proto_name = f.field_name.clone();
    let rust_ident = f.rust_name.clone();
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
        // Preserve message presence for `has()`, including WKTs whose CEL
        // values are timestamps or durations rather than message references.
        FieldKind::Message { full_name } => (
            scalar_this_for(&f.field_type).unwrap_or(CelType::Dyn),
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
    let check = match ty {
        CelType::Bool => quote! {
            if !(#tokens) {
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
            let __cel_s: ::std::string::String = (#tokens);
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
    let check = catch_runtime_errors(&compiler, &rule.id, check);
    Some(quote! {
        {
            #now_prelude
            #check
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_messages_remain_available_to_message_cel() {
        let kind = FieldKind::Repeated(Box::new(FieldKind::Message {
            full_name: "test.Child".to_owned(),
        }));
        let ty = scalar_this_for(&kind).expect("repeated message is a CEL list");
        assert_eq!(
            ty,
            CelType::List(Box::new(CelType::MessageRef("test.Child".to_owned())))
        );
        let child = MessageSchema {
            fields: vec![MessageFieldEntry {
                proto_name: "id".to_owned(),
                rust_ident: "id".to_owned(),
                ty: CelType::Str { owned: false },
                kind: SchemaFieldKind::StringLike,
            }],
        };
        let parent = MessageSchema {
            fields: vec![MessageFieldEntry {
                proto_name: "children".to_owned(),
                rust_ident: "children".to_owned(),
                ty,
                kind: SchemaFieldKind::Repeated,
            }],
        };
        let schemas = SchemaIndex::from([("test.Child".to_owned(), child)]);
        for expression in [
            "this.children.size() == 0",
            "this.children.all(s, this.children.filter(t, t.id == s.id).size() == 1)",
            "this.children.filter(c, c.id != \"\").all(c, this.children.filter(t, t.id == c.id).size() == 1)",
        ] {
            let mut compiler = Compiler::new().with_schemas(&schemas);
            compiler.bind(
                "this",
                Binding {
                    rust_expr: quote! { self },
                    ty: CelType::Message(Box::new(parent.clone())),
                    constant: None,
                },
            );
            let output = compiler
                .compile(expression)
                .expect("message-list CEL compiles");
            assert_eq!(output.ty, CelType::Bool);
        }
    }
}
