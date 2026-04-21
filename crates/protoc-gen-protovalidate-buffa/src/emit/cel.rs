//! CEL constraint emission: static `CelConstraint` declarations and `AsCelValue` impls.

use anyhow::Result;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::Path;

use crate::scan::{FieldKind, FieldValidator, MessageValidators};

/// Emit `static CEL_<MESSAGE>_<ID>: CelConstraint = ...` declarations plus the
/// invocation calls to be placed inside `validate()`.
///
/// Returns `(statics, calls)` — statics go outside the impl block, calls go
/// inside the `validate` body after field/oneof blocks.
#[must_use]
pub fn emit_message_level(msg: &MessageValidators) -> (Vec<TokenStream>, Vec<TokenStream>) {
    let mut statics = Vec::new();
    let mut calls = Vec::new();
    for rule in &msg.message_cel {
        let ident = const_ident(&msg.proto_name, &rule.id);
        let id = &rule.id;
        let message = &rule.message;
        let expr = &rule.expression;
        statics.push(quote! {
            static #ident: ::protovalidate_buffa::cel::CelConstraint =
                ::protovalidate_buffa::cel::CelConstraint::new(#id, #message, #expr);
        });
        calls.push(quote! {
            if let Err(v) = #ident.eval(self) {
                violations.push(v);
            }
        });
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
        if let crate::scan::FieldKind::Message { full_name } = &f.field_type {
            if full_name.starts_with("google.protobuf.") {
                continue;
            }
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
            let ident = const_ident(&format!("{}_{}", msg.proto_name, f.field_name), &rule.id);
            let id = &rule.id;
            let message = &rule.message;
            let expr = &rule.expression;
            statics.push(quote! {
                static #ident: ::protovalidate_buffa::cel::CelConstraint =
                    ::protovalidate_buffa::cel::CelConstraint::new(#id, #message, #expr);
            });
            let fp = field_path.clone();
            let (idx_lit, method) = if rule.is_cel_expression {
                let i = expr_idx;
                expr_idx += 1;
                (i, format_ident!("eval_expr_value_at"))
            } else {
                let i = cel_idx;
                cel_idx += 1;
                (i, format_ident!("eval_value_at"))
            };
            let call = match &f.field_type {
                crate::scan::FieldKind::Message { .. } | crate::scan::FieldKind::Wrapper(_) => {
                    quote! {
                        if let Some(inner) = self.#field_ident.as_option() {
                            if let Err(v) = #ident.#method(
                                ::protovalidate_buffa::cel::AsCelValue::as_cel_value(inner),
                                #fp,
                                #idx_lit,
                            ) {
                                violations.push(v);
                            }
                        }
                    }
                }
                crate::scan::FieldKind::Optional(_) => quote! {
                    if let Some(ref v) = self.#field_ident {
                        if let Err(viol) = #ident.#method(
                            ::protovalidate_buffa::cel::to_cel_value(v),
                            #fp,
                            #idx_lit,
                        ) {
                            violations.push(viol);
                        }
                    }
                },
                _ => quote! {
                    if let Err(v) = #ident.#method(
                        ::protovalidate_buffa::cel::to_cel_value(&self.#field_ident),
                        #fp,
                        #idx_lit,
                    ) {
                        violations.push(v);
                    }
                },
            };
            calls.push(call);
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
        let default_family = predef_family_for(&f.field_type, &f.standard);
        let field_ident = format_ident!("{}", f.field_name);
        let field_name = &f.field_name;
        let fnum = f.field_number;
        for (pi, rule) in f.standard.predefined.iter().enumerate() {
            let family = match rule.family_override {
                Some((name, number)) => Family { name, number },
                None => match default_family {
                    Some(f) => f,
                    None => continue,
                },
            };
            // Use full sanitized proto_name to avoid collisions between
            // same-named nested types in different parent messages.
            let full = msg
                .proto_name
                .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
                .to_uppercase();
            let ident_str = format!(
                "CEL_{}_{}_PRED{}_{}_{}",
                full,
                f.field_name.to_uppercase(),
                pi,
                rule.ext_number,
                rule.id
                    .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
                    .to_uppercase(),
            );
            let ident = format_ident!("{}", ident_str);
            let id = &rule.id;
            let message = &rule.message;
            let expr = &rule.expression;
            statics.push(quote! {
                static #ident: ::protovalidate_buffa::cel::CelConstraint =
                    ::protovalidate_buffa::cel::CelConstraint::new(#id, #message, #expr);
            });
            let family_name = family.name;
            let family_num = family.number;
            let family_fty = format_ident!("Message");
            let ext_fty = format_ident!("{}", rule.ext_field_type);
            let ext_bracketed = format!("[buf.validate.conformance.cases.{}]", rule.ext_name);
            let ext_num = rule.ext_number;
            // Rule value as a CEL Value expression.
            let rule_value: TokenStream = syn::parse_str(&rule.rule_value_expr)
                .unwrap_or_else(|_| quote! { ::protovalidate_buffa::cel_interpreter::Value::Null });
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
            let rule_path = quote! {
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
            let field_path = quote! {
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
            let this_expr: TokenStream = match &f.field_type {
                crate::scan::FieldKind::Wrapper(inner) => {
                    let _ = inner;
                    let inner_access =
                        quote! { ::protovalidate_buffa::cel::to_cel_value(&w.value) };
                    quote! {
                        match self.#field_ident.as_option() {
                            Some(w) => #inner_access,
                            None => ::protovalidate_buffa::cel_interpreter::Value::Null,
                        }
                    }
                }
                crate::scan::FieldKind::Message { full_name }
                    if full_name == "google.protobuf.Duration" =>
                {
                    quote! {
                        match self.#field_ident.as_option() {
                            Some(d) => ::protovalidate_buffa::cel_interpreter::Value::Duration(
                                ::protovalidate_buffa::cel::duration_from_secs_nanos(d.seconds, d.nanos)
                            ),
                            None => ::protovalidate_buffa::cel_interpreter::Value::Null,
                        }
                    }
                }
                crate::scan::FieldKind::Message { full_name }
                    if full_name == "google.protobuf.Timestamp" =>
                {
                    quote! {
                        match self.#field_ident.as_option() {
                            Some(t) => ::protovalidate_buffa::cel_interpreter::Value::Timestamp(
                                ::protovalidate_buffa::cel::timestamp_from_secs_nanos(t.seconds, t.nanos)
                            ),
                            None => ::protovalidate_buffa::cel_interpreter::Value::Null,
                        }
                    }
                }
                crate::scan::FieldKind::Message { .. } => quote! {
                    match self.#field_ident.as_option() {
                        Some(inner) => ::protovalidate_buffa::cel::AsCelValue::as_cel_value(inner),
                        None => ::protovalidate_buffa::cel_interpreter::Value::Null,
                    }
                },
                crate::scan::FieldKind::Optional(inner) => {
                    if matches!(inner.as_ref(), crate::scan::FieldKind::Enum { .. }) {
                        quote! {
                            match self.#field_ident.as_ref() {
                                Some(v) => ::protovalidate_buffa::cel_interpreter::Value::Int({
                                    use ::buffa::Enumeration as _;
                                    let vv = *v;
                                    vv.to_i32() as i64
                                }),
                                None => ::protovalidate_buffa::cel_interpreter::Value::Null,
                            }
                        }
                    } else {
                        quote! {
                            match self.#field_ident.as_ref() {
                                Some(v) => ::protovalidate_buffa::cel::to_cel_value(v),
                                None => ::protovalidate_buffa::cel_interpreter::Value::Null,
                            }
                        }
                    }
                }
                crate::scan::FieldKind::Enum { .. } => quote! {
                    ::protovalidate_buffa::cel_interpreter::Value::Int({
                        use ::buffa::Enumeration as _;
                        let v = self.#field_ident;
                        v.to_i32() as i64
                    })
                },
                _ => quote! { ::protovalidate_buffa::cel::to_cel_value(&self.#field_ident) },
            };
            calls.push(quote! {
                if let Err(v) = #ident.eval_predefined(
                    #this_expr,
                    #rule_value,
                    #field_path,
                    #rule_path,
                ) {
                    violations.push(v);
                }
            });
        }
    }
    (statics, calls)
}

#[derive(Clone, Copy)]
pub(crate) struct Family {
    pub name: &'static str,
    pub number: i32,
}

pub(crate) fn predef_family_for(
    kind: &crate::scan::FieldKind,
    _standard: &crate::scan::StandardRules,
) -> Option<Family> {
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

/// Emit `impl AsCelValue for <Type>` that builds a CEL Map from every field.
///
/// The generated code calls `::protovalidate_buffa::cel::to_cel_value(&self.<field>)`
/// for scalar/string/bytes fields, and uses explicit `as_cel_value()` calls for
/// message-typed fields to avoid requiring downstream `ToCelValue` bounds on
/// proto-generated structs.
///
/// WKT fields (`google.protobuf.*`) are skipped — they do not implement `AsCelValue`.
/// Repeated WKT fields are also skipped.
///
/// # Errors
///
/// Returns an error if a field's Rust path cannot be parsed from the proto type name.
pub fn emit_as_cel_value(msg: &MessageValidators, rust_path: &Path) -> Result<TokenStream> {
    let inserts: Vec<TokenStream> = msg
        .field_rules
        .iter()
        // Skip inner-only synthetic validators (field_number == -1 means no real field).
        .filter(|f| f.field_number != -1)
        // Skip oneof-member fields: they're represented as `Option<XxxOneof>` enums
        // in buffa, not as flat struct fields, so `self.<field>` would not compile.
        .filter(|f| f.oneof_name.is_none())
        // Skip WKT message fields — no AsCelValue impl for google.protobuf.*
        .filter(|f| !is_wkt_field(&f.field_type))
        .map(|f| {
            let field_ident = format_ident!("{}", f.field_name);
            let field_name = &f.field_name;
            // For fields with explicit presence (Optional scalar / Message),
            // skip the insert when unset so CEL's has() reports false.
            match &f.field_type {
                FieldKind::Optional(_) => quote! {
                    if let Some(ref v) = self.#field_ident {
                        map.insert(
                            ::std::string::String::from(#field_name),
                            ::protovalidate_buffa::cel::to_cel_value(v),
                        );
                    }
                },
                FieldKind::Message { .. } => quote! {
                    if let Some(v) = self.#field_ident.as_option() {
                        map.insert(
                            ::std::string::String::from(#field_name),
                            ::protovalidate_buffa::cel::AsCelValue::as_cel_value(v),
                        );
                    }
                },
                _ => {
                    let insert_val = field_to_cel_value_expr(f, &field_ident);
                    quote! {
                        map.insert(
                            ::std::string::String::from(#field_name),
                            #insert_val,
                        );
                    }
                }
            }
        })
        .collect();

    let allows = crate::emit::gen_allows();
    Ok(quote! {
        #allows
        impl ::protovalidate_buffa::cel::AsCelValue for #rust_path {
            fn as_cel_value(&self) -> ::protovalidate_buffa::cel_interpreter::Value {
                let mut map: ::std::collections::HashMap<
                    ::std::string::String,
                    ::protovalidate_buffa::cel_interpreter::Value,
                > = ::std::collections::HashMap::new();
                #( #inserts )*
                ::protovalidate_buffa::cel_interpreter::Value::Map(map.into())
            }
        }
        #allows
        impl ::protovalidate_buffa::cel::ToCelValue for #rust_path {
            fn to_cel_value(&self) -> ::protovalidate_buffa::cel_interpreter::Value {
                ::protovalidate_buffa::cel::AsCelValue::as_cel_value(self)
            }
        }
    })
}

/// Returns true if a field type references a WKT (google.protobuf.*) message,
/// including when nested inside a Repeated.
fn is_wkt_field(kind: &FieldKind) -> bool {
    match kind {
        FieldKind::Message { full_name } => full_name.starts_with("google.protobuf."),
        FieldKind::Repeated(inner) | FieldKind::Optional(inner) => is_wkt_field(inner),
        _ => false,
    }
}

/// Generate the expression that converts a field to a CEL Value for insertion
/// into the `AsCelValue` map.
///
/// - Scalar / string / bytes: `::protovalidate_buffa::cel::to_cel_value(&self.<field>)`
/// - Message (`MessageField`<T>): `self.<field>.as_option().map_or(Value::Null, |v| v.as_cel_value())`
/// - Repeated<Message>: explicit list comprehension using `as_cel_value()`
/// - Repeated<scalar>: `::protovalidate_buffa::cel::to_cel_value(&self.<field>)`
fn field_to_cel_value_expr(f: &FieldValidator, field_ident: &syn::Ident) -> TokenStream {
    match &f.field_type {
        FieldKind::Message { .. } => {
            // MessageField<T> — call as_cel_value on the inner value if set.
            quote! {
                self.#field_ident.as_option().map_or(
                    ::protovalidate_buffa::cel_interpreter::Value::Null,
                    ::protovalidate_buffa::cel::AsCelValue::as_cel_value,
                )
            }
        }
        FieldKind::Optional(_) => {
            // EXPLICIT-presence scalar: `Option<T>`. Map None→Null, Some(v)→to_cel_value.
            quote! {
                match self.#field_ident {
                    Some(ref v) => ::protovalidate_buffa::cel::to_cel_value(v),
                    None => ::protovalidate_buffa::cel_interpreter::Value::Null,
                }
            }
        }
        FieldKind::Repeated(inner) => {
            match inner.as_ref() {
                FieldKind::Message { .. } => {
                    // Vec<MessageType> — iterate and call as_cel_value on each elem.
                    quote! {
                        ::protovalidate_buffa::cel_interpreter::Value::List(
                            self.#field_ident
                                .iter()
                                .map(::protovalidate_buffa::cel::AsCelValue::as_cel_value)
                                .collect::<::std::vec::Vec<_>>()
                                .into()
                        )
                    }
                }
                _ => {
                    // Vec<scalar> — use the ToCelValue blanket.
                    quote! {
                        ::protovalidate_buffa::cel::to_cel_value(&self.#field_ident)
                    }
                }
            }
        }
        _ => {
            // Scalar / string / bytes / enum.
            quote! {
                ::protovalidate_buffa::cel::to_cel_value(&self.#field_ident)
            }
        }
    }
}

/// Build the identifier for a static CEL constraint.
///
/// e.g. `proto_name` `"test.v1.UpdatePomRequest"`, id `"update_pom.pom.id_required"` →
/// `CEL_UPDATEPOMREQUEST_UPDATE_POM_POM_ID_REQUIRED`
#[must_use]
pub fn const_ident(proto_name: &str, rule_id: &str) -> syn::Ident {
    let sanitized = rule_id
        .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
        .to_uppercase();
    let msg_short = proto_name.rsplit('.').next().unwrap_or(proto_name);
    format_ident!("CEL_{}_{}", msg_short.to_uppercase(), sanitized)
}

/// Collect the set of message `proto_names` that need an `AsCelValue` impl.
///
/// Strategy:
/// - Any message with `message_cel` or any `field_cel` directly gets one.
/// - Any message that is a `FieldKind::Message` or `Repeated(Message)` target
///   of such a message also gets one, transitively until the set stabilises.
///
/// Returns a `HashSet<String>` of fully-qualified proto names.
pub fn cel_value_set<'a>(
    all: impl IntoIterator<Item = &'a MessageValidators>,
) -> std::collections::HashSet<String> {
    let all: Vec<&MessageValidators> = all.into_iter().collect();

    // Build a lookup map from proto_name to validator for fast access.
    let by_name: std::collections::HashMap<&str, &MessageValidators> =
        all.iter().map(|m| (m.proto_name.as_str(), *m)).collect();

    // Phase 1 — direct CEL holders.
    let mut needs: std::collections::HashSet<String> = all
        .iter()
        .filter(|m| has_any_cel(m))
        .map(|m| m.proto_name.clone())
        .collect();

    // Phase 2 — transitive closure: keep expanding until no new names are added.
    loop {
        let newly_referenced: Vec<String> = needs
            .iter()
            .filter_map(|name| by_name.get(name.as_str()))
            .flat_map(|m| m.field_rules.iter())
            .filter_map(message_field_target)
            // Skip WKTs — they don't need AsCelValue.
            .filter(|n| !n.starts_with("google.protobuf."))
            .filter(|n| !needs.contains(n))
            .collect();

        if newly_referenced.is_empty() {
            break;
        }
        needs.extend(newly_referenced);
    }

    needs
}

fn has_any_cel(m: &MessageValidators) -> bool {
    !m.message_cel.is_empty()
        || m.field_rules.iter().any(|f| {
            !f.cel.is_empty()
                || f.standard
                    .repeated
                    .as_ref()
                    .and_then(|r| r.items.as_ref())
                    .is_some_and(|i| !i.cel.is_empty())
                || f.standard
                    .map
                    .as_ref()
                    .and_then(|m| m.keys.as_ref())
                    .is_some_and(|k| !k.cel.is_empty())
                || f.standard
                    .map
                    .as_ref()
                    .and_then(|m| m.values.as_ref())
                    .is_some_and(|v| !v.cel.is_empty())
        })
}

fn message_field_target(f: &FieldValidator) -> Option<String> {
    match &f.field_type {
        FieldKind::Message { full_name } => Some(full_name.clone()),
        FieldKind::Repeated(inner) | FieldKind::Optional(inner) => {
            if let FieldKind::Message { full_name } = inner.as_ref() {
                Some(full_name.clone())
            } else {
                None
            }
        }
        FieldKind::Map { value, .. } => {
            if let FieldKind::Message { full_name } = value.as_ref() {
                Some(full_name.clone())
            } else {
                None
            }
        }
        _ => None,
    }
}
