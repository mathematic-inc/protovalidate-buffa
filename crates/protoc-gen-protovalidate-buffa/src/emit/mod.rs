//! Orchestrate the emit phase: group scanned validators by source `.proto`
//! file and render one Rust file per source.

use anyhow::Result;
use buffa_codegen::generated::compiler::code_generator_response::File;
use proc_macro2::TokenStream;
use quote::quote;

use crate::scan::MessageValidators;

pub mod cel;
pub mod field;
pub mod oneof;
pub mod repeated;

/// Render one output `.rs` file per source `.proto` file.
///
/// Output path: `"example/v1/foo.proto"` → `"example.v1.foo.rs"`.
///
/// # Errors
///
/// Returns an error if any message's Rust path cannot be parsed, if a field
/// emitter fails (e.g. unsupported enum nesting), or if `prettyplease`
/// cannot format the generated `TokenStream`.
pub fn render(messages: &[MessageValidators]) -> Result<Vec<File>> {
    use std::collections::BTreeMap;

    let mut by_file: BTreeMap<String, Vec<&MessageValidators>> = BTreeMap::new();
    for m in messages {
        by_file.entry(m.source_file.clone()).or_default().push(m);
    }

    let mut files = Vec::new();
    for (source_file, msgs) in by_file {
        let body = render_file(&msgs)?;
        let stem = source_file.trim_end_matches(".proto").replace('/', ".");
        let path = format!("{stem}.rs");
        let body_str = body.to_string();
        let parsed = syn::parse2(body.clone()).map_err(|e| {
            anyhow::anyhow!("syn parse failed for {source_file}: {e}\n--- BEGIN TOKENS ---\n{body_str}\n--- END TOKENS ---")
        })?;
        files.push(File {
            name: Some(path),
            content: Some(prettyplease::unparse(&parsed)),
            insertion_point: None,
            generated_code_info: None.into(),
            ..Default::default()
        });
    }
    Ok(files)
}

fn render_file(msgs: &[&MessageValidators]) -> Result<TokenStream> {
    // Build the set of proto names that need AsCelValue impls.
    let cel_set = cel::cel_value_set(msgs.iter().copied());

    let impls: Vec<TokenStream> = msgs
        .iter()
        .map(|m| render_message(m, &cel_set))
        .collect::<Result<_>>()?;
    Ok(quote! {
        use super::*;
        #( #impls )*
    })
}

/// Outer attribute set applied to every emitted `impl` / `static`. The code
/// is machine-generated and gets included via `include!()`, which means
/// inner attributes aren't allowed — instead every top-level item carries
/// an outer allow. Suppresses: unused `mut` on `violations` vectors for
/// messages whose rules produce violations only conditionally, unused
/// `value`/`key` map iteration locals when only one half is referenced,
/// parenthesised literal groups emitted by `prettyplease`, and a handful
/// of codegen-side diagnostics that have no user-facing reader.
pub(crate) fn gen_allows() -> TokenStream {
    quote! {
        #[allow(
            clippy::all,
            unused_mut,
            unused_variables,
            unused_parens,
            dead_code,
            unreachable_patterns,
            reason = "protovalidate-buffa generated validators — codegen emits uniform scaffolding regardless of which rules apply"
        )]
    }
}

fn render_message(
    msg: &MessageValidators,
    cel_set: &std::collections::HashSet<String>,
) -> Result<TokenStream> {
    use std::collections::HashSet;
    // Use only the message name relative to the package — the generated file
    // is included inside the package module, so `use super::*;` brings the
    // type into scope and just the local name is sufficient.
    //
    // For `proto_name = "test.v1.ScalarsMessage"` with `package = "test.v1"`,
    // the local suffix is `ScalarsMessage`. For nested messages like
    // `"test.v1.Outer.Inner"` the local suffix is `Outer.Inner`; buffa
    // renders parent segments in snake_case, giving `outer::Inner` — see
    // the PascalCase → snake_case transform below.
    let local_name = strip_package_prefix(&msg.proto_name, &msg.package);
    // For nested messages `Outer.Inner.Leaf`, buffa emits
    // `outer::inner::Leaf` — parent PascalCase segments lowered to snake_case.
    let segs: Vec<&str> = local_name.split('.').collect();
    let rust_segs: Vec<String> = segs
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let is_last = i + 1 == segs.len();
            let starts_upper = s.chars().next().is_some_and(char::is_uppercase);
            if !is_last && starts_upper {
                snake_from_pascal(s)
            } else {
                (*s).to_string()
            }
        })
        .collect();
    let rust_path_str = rust_segs.join("::");
    let rust_path = syn::parse_str::<syn::Path>(&rust_path_str)?;

    // Fields listed in a `(buf.validate.message).oneof` get implicit
    // IGNORE_IF_ZERO_VALUE semantics: their rule checks only fire when the
    // field is set (non-default). Wrap those blocks in a zero-value guard.
    let implicit_ignore: HashSet<&str> = msg
        .message_oneofs
        .iter()
        .flat_map(|o| o.fields.iter().map(String::as_str))
        .collect();
    let field_blocks: Vec<TokenStream> = msg
        .field_rules
        .iter()
        .map(|f| {
            let inner = field::emit(f)?;
            if implicit_ignore.contains(f.field_name.as_str())
                && !matches!(f.ignore, crate::scan::Ignore::Always)
            {
                let accessor = syn::Ident::new(&f.field_name, proc_macro2::Span::call_site());
                let guard: Option<TokenStream> = match &f.field_type {
                    crate::scan::FieldKind::String | crate::scan::FieldKind::Bytes => {
                        Some(quote! { !self.#accessor.is_empty() })
                    }
                    crate::scan::FieldKind::Repeated(_) | crate::scan::FieldKind::Map { .. } => {
                        Some(quote! { !self.#accessor.is_empty() })
                    }
                    crate::scan::FieldKind::Int32
                    | crate::scan::FieldKind::Sint32
                    | crate::scan::FieldKind::Sfixed32 => Some(quote! { self.#accessor != 0i32 }),
                    crate::scan::FieldKind::Int64
                    | crate::scan::FieldKind::Sint64
                    | crate::scan::FieldKind::Sfixed64 => Some(quote! { self.#accessor != 0i64 }),
                    crate::scan::FieldKind::Uint32 | crate::scan::FieldKind::Fixed32 => {
                        Some(quote! { self.#accessor != 0u32 })
                    }
                    crate::scan::FieldKind::Uint64 | crate::scan::FieldKind::Fixed64 => {
                        Some(quote! { self.#accessor != 0u64 })
                    }
                    crate::scan::FieldKind::Float => Some(quote! { self.#accessor != 0f32 }),
                    crate::scan::FieldKind::Double => Some(quote! { self.#accessor != 0f64 }),
                    crate::scan::FieldKind::Bool => Some(quote! { self.#accessor }),
                    crate::scan::FieldKind::Enum { .. } => {
                        Some(quote! { (self.#accessor as i32) != 0i32 })
                    }
                    crate::scan::FieldKind::Message { .. } | crate::scan::FieldKind::Wrapper(_) => {
                        Some(quote! { self.#accessor.is_set() })
                    }
                    crate::scan::FieldKind::Optional(_) => {
                        Some(quote! { self.#accessor.is_some() })
                    }
                };
                if let Some(g) = guard {
                    Ok(quote! { if #g { #inner } })
                } else {
                    Ok(inner)
                }
            } else {
                Ok(inner)
            }
        })
        .collect::<Result<_>>()?;
    let oneof_blocks: Vec<TokenStream> = msg
        .oneof_rules
        .iter()
        .map(oneof::emit)
        .collect::<Result<_>>()?;

    // `(buf.validate.message).oneof` — fields where at most one may be set.
    let message_oneof_blocks: Vec<TokenStream> = msg
        .message_oneofs
        .iter()
        .map(|spec| emit_message_oneof(msg, spec))
        .collect();

    let (cel_statics, cel_calls) = cel::emit_message_level(msg);

    let as_cel_value = if cel_set.contains(&msg.proto_name) {
        cel::emit_as_cel_value(msg, &rust_path)?
    } else {
        quote! {}
    };

    let allows = gen_allows();
    if let Some(reason) = &msg.compile_error {
        return Ok(quote! {
            #allows
            impl ::protovalidate_buffa::Validate for #rust_path {
                fn validate(
                    &self,
                ) -> ::core::result::Result<(), ::protovalidate_buffa::ValidationError> {
                    Err(::protovalidate_buffa::ValidationError {
                        compile_error: ::core::option::Option::Some(
                            ::std::string::String::from(#reason),
                        ),
                        ..::core::default::Default::default()
                    })
                }
            }
        });
    }
    // Wrap each static + impl in the same outer allow set.
    let statics_with_allows: Vec<TokenStream> = cel_statics
        .into_iter()
        .map(|s| quote! { #allows #s })
        .collect();
    Ok(quote! {
        #( #statics_with_allows )*
        #allows
        impl ::protovalidate_buffa::Validate for #rust_path {
            fn validate(
                &self,
            ) -> ::core::result::Result<(), ::protovalidate_buffa::ValidationError> {
                let mut violations: ::std::vec::Vec<::protovalidate_buffa::Violation> =
                    ::std::vec::Vec::new();
                #( #field_blocks )*
                #( #oneof_blocks )*
                #( #message_oneof_blocks )*
                #( #cel_calls )*
                // Lift any `__cel_runtime_error__` marker violations to the
                // typed `runtime_error` field so callers can pattern-match
                // instead of sniffing `rule_id` strings.
                let (rt_violation, violations): (
                    ::std::option::Option<::protovalidate_buffa::Violation>,
                    ::std::vec::Vec<::protovalidate_buffa::Violation>,
                ) = {
                    let mut rt = None;
                    let mut rest = ::std::vec::Vec::with_capacity(violations.len());
                    for v in violations {
                        if rt.is_none() && v.rule_id == "__cel_runtime_error__" {
                            rt = Some(v);
                        } else {
                            rest.push(v);
                        }
                    }
                    (rt, rest)
                };
                if let Some(v) = rt_violation {
                    return ::core::result::Result::Err(
                        ::protovalidate_buffa::ValidationError {
                            runtime_error: ::core::option::Option::Some(v.message.into_owned()),
                            ..::core::default::Default::default()
                        },
                    );
                }
                if violations.is_empty() {
                    Ok(())
                } else {
                    Err(::protovalidate_buffa::ValidationError {
                        violations,
                        ..::core::default::Default::default()
                    })
                }
            }
        }
        #as_cel_value
    })
}

/// Strip the package prefix from a fully-qualified proto name.
///
/// `"test.v1.ScalarsMessage"` with package `"test.v1"` → `"ScalarsMessage"`.
/// `"example.v1.Outer.Inner"` with package `"example.v1"` → `"Outer.Inner"`.
/// If `package` is empty or the name does not start with `<package>.`, return
/// the original name unchanged.
/// Emit a `(buf.validate.message).oneof` rule. Counts how many listed fields
/// are considered "set"; emits `message.oneof` violation if zero (only when
/// required) or more than one.
fn emit_message_oneof(
    msg: &crate::scan::MessageValidators,
    spec: &crate::scan::MessageOneofSpec,
) -> TokenStream {
    use proc_macro2::Span;

    use crate::scan::FieldKind;
    let checks: Vec<TokenStream> = spec
        .fields
        .iter()
        .filter_map(|name| {
            let fv = msg.field_rules.iter().find(|f| &f.field_name == name)?;
            let ident = syn::Ident::new(&fv.field_name, Span::call_site());
            // "Set" semantics per protovalidate-go for message.oneof:
            // messages: present; repeated/map: non-empty; proto3 optional: is_some;
            // scalar: always counted as set (we can't distinguish default from unset).
            let expr = match &fv.field_type {
                FieldKind::Message { .. } | FieldKind::Wrapper(_) => {
                    quote! { self.#ident.is_set() }
                }
                FieldKind::Repeated(_) | FieldKind::Map { .. } => {
                    quote! { !self.#ident.is_empty() }
                }
                FieldKind::Optional(_) => quote! { self.#ident.is_some() },
                FieldKind::String | FieldKind::Bytes => quote! { !self.#ident.is_empty() },
                FieldKind::Bool => quote! { self.#ident },
                FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32 => {
                    quote! { self.#ident != 0i32 }
                }
                FieldKind::Int64 | FieldKind::Sint64 | FieldKind::Sfixed64 => {
                    quote! { self.#ident != 0i64 }
                }
                FieldKind::Uint32 | FieldKind::Fixed32 => quote! { self.#ident != 0u32 },
                FieldKind::Uint64 | FieldKind::Fixed64 => quote! { self.#ident != 0u64 },
                FieldKind::Float => quote! { self.#ident != 0f32 },
                FieldKind::Double => quote! { self.#ident != 0f64 },
                FieldKind::Enum { .. } => quote! { (self.#ident as i32) != 0i32 },
            };
            Some(quote! { if #expr { __count += 1; } })
        })
        .collect();
    let required = spec.required;
    quote! {
        {
            let mut __count: usize = 0;
            #( #checks )*
            if __count > 1 {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::FieldPath::default(),
                    rule: ::protovalidate_buffa::FieldPath::default(),
                    rule_id: ::std::borrow::Cow::Borrowed("message.oneof"),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            } else if __count == 0 && #required {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::FieldPath::default(),
                    rule: ::protovalidate_buffa::FieldPath::default(),
                    rule_id: ::std::borrow::Cow::Borrowed("message.oneof"),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        }
    }
}

fn snake_from_pascal(s: &str) -> String {
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

fn strip_package_prefix<'a>(proto_name: &'a str, package: &str) -> &'a str {
    if package.is_empty() {
        return proto_name;
    }
    let prefix = format!("{package}.");
    proto_name
        .strip_prefix(prefix.as_str())
        .unwrap_or(proto_name)
}
