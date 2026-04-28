//! Emit validation code for `repeated` and `map` fields, including per-element
//! / per-key / per-value rule application and message-type recursion.

use anyhow::Result;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::scan::{FieldKind, MapStandard, RepeatedStandard};

/// Metadata-rich map key/value check emission. `for_key=true` generates
/// rule paths starting with `map.keys.<family>...`, otherwise `map.values.*`.
#[expect(
    clippy::too_many_arguments,
    reason = "map key/value emission needs element ident, kind, rules, name, field_number, two kind variants, and for_key flag — bundling into a struct would fragment the signature without aiding readers"
)]
fn emit_map_kv_checks(
    elem_ident: &syn::Ident,
    kind: &FieldKind,
    rules: &crate::scan::StandardRules,
    name_lit: &str,
    field_number: i32,
    key_kind_variant: &str,
    value_kind_variant: &str,
    for_key: bool,
) -> Vec<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    let key_ty = format_ident!("{}", key_kind_variant);
    let value_ty = format_ident!("{}", value_kind_variant);
    // Field path for a map entry: contains key_type, value_type, and the
    // key itself as a subscript. We can't easily build the subscript here
    // without knowing the exact type — emit with `KeySubscript(key.clone())`
    // via a helper in protovalidate_buffa rules runtime is overkill. Use
    // the right subscript variant based on key kind.
    let key_subscript: TokenStream = match kind_variant_to_subscript(key_kind_variant) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let field_path = quote! {
        ::protovalidate_buffa::FieldPath {
            elements: ::std::vec![
                ::protovalidate_buffa::FieldPathElement {
                    field_number: Some(#field_number),
                    field_name: Some(::std::borrow::Cow::Borrowed(#name_lit)),
                    field_type: Some(::protovalidate_buffa::FieldType::Message),
                    key_type: Some(::protovalidate_buffa::FieldType::#key_ty),
                    value_type: Some(::protovalidate_buffa::FieldType::#value_ty),
                    subscript: Some(#key_subscript),
                },
            ],
        }
    };
    // Rule path: [map(19), keys(4)/values(5), <family>, <rule>].
    let kv_num = if for_key { 4i32 } else { 5i32 };
    let kv_name = if for_key { "keys" } else { "values" };
    let rule_path_5 = |family: &str,
                       outer_num: i32,
                       inner_name: &str,
                       inner_num: i32,
                       inner_ty: &str|
     -> TokenStream {
        let ity = format_ident!("{}", inner_ty);
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
                        field_number: Some(#kv_num),
                        field_name: Some(::std::borrow::Cow::Borrowed(#kv_name)),
                        field_type: Some(::protovalidate_buffa::FieldType::Message),
                        key_type: None,
                        value_type: None,
                        subscript: None,
                    },
                    ::protovalidate_buffa::FieldPathElement {
                        field_number: Some(#outer_num),
                        field_name: Some(::std::borrow::Cow::Borrowed(#family)),
                        field_type: Some(::protovalidate_buffa::FieldType::Message),
                        key_type: None,
                        value_type: None,
                        subscript: None,
                    },
                    ::protovalidate_buffa::FieldPathElement {
                        field_number: Some(#inner_num),
                        field_name: Some(::std::borrow::Cow::Borrowed(#inner_name)),
                        field_type: Some(::protovalidate_buffa::FieldType::#ity),
                        key_type: None,
                        value_type: None,
                        subscript: None,
                    },
                ],
            }
        }
    };
    let push = |out: &mut Vec<TokenStream>,
                family: &str,
                outer_num: i32,
                inner_name: &str,
                inner_num: i32,
                inner_ty: &str,
                rule_id: String,
                cond: TokenStream| {
        let fp = field_path.clone();
        let rule = rule_path_5(family, outer_num, inner_name, inner_num, inner_ty);
        let fk = for_key;
        out.push(quote! {
            if #cond {
                violations.push(::protovalidate_buffa::Violation {
                    field: #fp, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: #fk,
                });
            }
        });
    };
    match kind {
        FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32 => {
            let (family, outer, scalar_ty) = match kind {
                FieldKind::Int32 => ("int32", 3, "Int32"),
                FieldKind::Sint32 => ("sint32", 7, "Sint32"),
                FieldKind::Sfixed32 => ("sfixed32", 11, "Sfixed32"),
                _ => unreachable!(),
            };
            if let Some(n) = &rules.int32 {
                if let Some(c) = n.r#const {
                    push(
                        &mut out,
                        family,
                        outer,
                        "const",
                        1,
                        scalar_ty,
                        format!("{family}.const"),
                        quote! { *#elem_ident != #c },
                    );
                }
                if let Some(lo) = n.gt {
                    push(
                        &mut out,
                        family,
                        outer,
                        "gt",
                        4,
                        scalar_ty,
                        format!("{family}.gt"),
                        quote! { *#elem_ident <= #lo },
                    );
                }
                if let Some(lo) = n.gte {
                    push(
                        &mut out,
                        family,
                        outer,
                        "gte",
                        5,
                        scalar_ty,
                        format!("{family}.gte"),
                        quote! { *#elem_ident < #lo },
                    );
                }
                if let Some(hi) = n.lt {
                    push(
                        &mut out,
                        family,
                        outer,
                        "lt",
                        2,
                        scalar_ty,
                        format!("{family}.lt"),
                        quote! { *#elem_ident >= #hi },
                    );
                }
                if let Some(hi) = n.lte {
                    push(
                        &mut out,
                        family,
                        outer,
                        "lte",
                        3,
                        scalar_ty,
                        format!("{family}.lte"),
                        quote! { *#elem_ident > #hi },
                    );
                }
            }
        }
        FieldKind::Int64 | FieldKind::Sint64 | FieldKind::Sfixed64 => {
            let (family, outer, scalar_ty) = match kind {
                FieldKind::Int64 => ("int64", 4, "Int64"),
                FieldKind::Sint64 => ("sint64", 8, "Sint64"),
                FieldKind::Sfixed64 => ("sfixed64", 12, "Sfixed64"),
                _ => unreachable!(),
            };
            if let Some(n) = &rules.int64 {
                if let Some(c) = n.r#const {
                    push(
                        &mut out,
                        family,
                        outer,
                        "const",
                        1,
                        scalar_ty,
                        format!("{family}.const"),
                        quote! { *#elem_ident != #c },
                    );
                }
                if let Some(lo) = n.gt {
                    push(
                        &mut out,
                        family,
                        outer,
                        "gt",
                        4,
                        scalar_ty,
                        format!("{family}.gt"),
                        quote! { *#elem_ident <= #lo },
                    );
                }
                if let Some(lo) = n.gte {
                    push(
                        &mut out,
                        family,
                        outer,
                        "gte",
                        5,
                        scalar_ty,
                        format!("{family}.gte"),
                        quote! { *#elem_ident < #lo },
                    );
                }
                if let Some(hi) = n.lt {
                    push(
                        &mut out,
                        family,
                        outer,
                        "lt",
                        2,
                        scalar_ty,
                        format!("{family}.lt"),
                        quote! { *#elem_ident >= #hi },
                    );
                }
                if let Some(hi) = n.lte {
                    push(
                        &mut out,
                        family,
                        outer,
                        "lte",
                        3,
                        scalar_ty,
                        format!("{family}.lte"),
                        quote! { *#elem_ident > #hi },
                    );
                }
            }
        }
        FieldKind::String => {
            if let Some(s) = &rules.string {
                if let Some(n) = s.min_len {
                    let n_usize = usize::try_from(n).expect("len fits in usize");
                    push(
                        &mut out,
                        "string",
                        14,
                        "min_len",
                        2,
                        "Uint64",
                        "string.min_len".to_string(),
                        quote! { #elem_ident.chars().count() < #n_usize },
                    );
                }
                if let Some(n) = s.max_len {
                    let n_usize = usize::try_from(n).expect("len fits in usize");
                    push(
                        &mut out,
                        "string",
                        14,
                        "max_len",
                        3,
                        "Uint64",
                        "string.max_len".to_string(),
                        quote! { #elem_ident.chars().count() > #n_usize },
                    );
                }
                if !s.in_set.is_empty() {
                    let set = &s.in_set;
                    let fp = field_path.clone();
                    let rule = rule_path_5("string", 14, "in", 10, "String");
                    let fk = for_key;
                    out.push(quote! {
                        {
                            const ALLOWED: &[&str] = &[ #( #set ),* ];
                            if !ALLOWED.iter().any(|c| *c == #elem_ident.as_str()) {
                                violations.push(::protovalidate_buffa::Violation {
                                    field: #fp, rule: #rule,
                                    rule_id: ::std::borrow::Cow::Borrowed("string.in"),
                                    message: ::std::borrow::Cow::Borrowed(""),
                                    for_key: #fk,
                                });
                            }
                        }
                    });
                }
                if let Some(pat) = &s.pattern {
                    let pat_str = pat.as_str();
                    let fp = field_path.clone();
                    let rule = rule_path_5("string", 14, "pattern", 6, "String");
                    let fk = for_key;
                    let cache_ident = format_ident!(
                        "RE_MAP_{}_{}",
                        if for_key { "K" } else { "V" },
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
                            if !re.is_match(#elem_ident) {
                                violations.push(::protovalidate_buffa::Violation {
                                    field: #fp, rule: #rule,
                                    rule_id: ::std::borrow::Cow::Borrowed("string.pattern"),
                                    message: ::std::borrow::Cow::Borrowed(""),
                                    for_key: #fk,
                                });
                            }
                        }
                    });
                }
            }
        }
        _ => {}
    }
    out
}

pub(crate) fn kind_variant_to_subscript(kind_variant: &str) -> Option<TokenStream> {
    match kind_variant {
        "Bool" => Some(quote! { ::protovalidate_buffa::Subscript::BoolKey(*key) }),
        "Int32" | "Sint32" | "Sfixed32" => {
            Some(quote! { ::protovalidate_buffa::Subscript::IntKey(i64::from(*key)) })
        }
        "Int64" | "Sint64" | "Sfixed64" => {
            Some(quote! { ::protovalidate_buffa::Subscript::IntKey(*key) })
        }
        "Uint32" | "Fixed32" => {
            Some(quote! { ::protovalidate_buffa::Subscript::UintKey(u64::from(*key)) })
        }
        "Uint64" | "Fixed64" => Some(quote! { ::protovalidate_buffa::Subscript::UintKey(*key) }),
        "String" => Some(
            quote! { ::protovalidate_buffa::Subscript::StringKey(::std::borrow::Cow::Owned(key.clone())) },
        ),
        _ => None,
    }
}

/// Per-element metadata-rich rule emission for `repeated` items. Produces
/// FieldPath/Rule paths that include index subscripts and the full
/// `repeated.items.<family>.<rule>` rule-id prefix.
fn emit_repeated_items_checks(
    elem_ident: &syn::Ident,
    kind: &FieldKind,
    rules: &crate::scan::StandardRules,
    name_lit: &str,
    field_number: i32,
    element_type_variant: &str,
) -> Vec<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    let ety = format_ident!("{}", element_type_variant);
    let fp_idx = quote! {
        ::protovalidate_buffa::FieldPath {
            elements: ::std::vec![
                ::protovalidate_buffa::FieldPathElement {
                    field_number: Some(#field_number),
                    field_name: Some(::std::borrow::Cow::Borrowed(#name_lit)),
                    field_type: Some(::protovalidate_buffa::FieldType::#ety),
                    key_type: None,
                    value_type: None,
                    subscript: Some(::protovalidate_buffa::Subscript::Index(idx as u64)),
                },
            ],
        }
    };
    // Helper: build a 4-element rule path [repeated, items, <family>, <rule>].
    let rule_path_4 = |family: &str,
                       outer_num: i32,
                       inner_name: &str,
                       inner_num: i32,
                       inner_ty: &str|
     -> TokenStream {
        let ity = format_ident!("{}", inner_ty);
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
                        field_number: Some(4i32),
                        field_name: Some(::std::borrow::Cow::Borrowed("items")),
                        field_type: Some(::protovalidate_buffa::FieldType::Message),
                        key_type: None,
                        value_type: None,
                        subscript: None,
                    },
                    ::protovalidate_buffa::FieldPathElement {
                        field_number: Some(#outer_num),
                        field_name: Some(::std::borrow::Cow::Borrowed(#family)),
                        field_type: Some(::protovalidate_buffa::FieldType::Message),
                        key_type: None,
                        value_type: None,
                        subscript: None,
                    },
                    ::protovalidate_buffa::FieldPathElement {
                        field_number: Some(#inner_num),
                        field_name: Some(::std::borrow::Cow::Borrowed(#inner_name)),
                        field_type: Some(::protovalidate_buffa::FieldType::#ity),
                        key_type: None,
                        value_type: None,
                        subscript: None,
                    },
                ],
            }
        }
    };

    let push = |out: &mut Vec<TokenStream>,
                family: &str,
                outer_num: i32,
                inner_name: &str,
                inner_num: i32,
                inner_ty: &str,
                rule_id: String,
                cond: TokenStream| {
        let fp = fp_idx.clone();
        let rule = rule_path_4(family, outer_num, inner_name, inner_num, inner_ty);
        out.push(quote! {
            if #cond {
                violations.push(::protovalidate_buffa::Violation {
                    field: #fp, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#rule_id),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        });
    };

    match kind {
        FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32 => {
            let (family, outer, scalar_ty) = match kind {
                FieldKind::Int32 => ("int32", 3, "Int32"),
                FieldKind::Sint32 => ("sint32", 7, "Sint32"),
                FieldKind::Sfixed32 => ("sfixed32", 11, "Sfixed32"),
                _ => unreachable!(),
            };
            if let Some(n) = &rules.int32 {
                if let Some(c) = n.r#const {
                    push(
                        &mut out,
                        family,
                        outer,
                        "const",
                        1,
                        scalar_ty,
                        format!("{family}.const"),
                        quote! { *#elem_ident != #c },
                    );
                }
                if let Some(lo) = n.gt {
                    push(
                        &mut out,
                        family,
                        outer,
                        "gt",
                        4,
                        scalar_ty,
                        format!("{family}.gt"),
                        quote! { *#elem_ident <= #lo },
                    );
                }
                if let Some(lo) = n.gte {
                    push(
                        &mut out,
                        family,
                        outer,
                        "gte",
                        5,
                        scalar_ty,
                        format!("{family}.gte"),
                        quote! { *#elem_ident < #lo },
                    );
                }
                if let Some(hi) = n.lt {
                    push(
                        &mut out,
                        family,
                        outer,
                        "lt",
                        2,
                        scalar_ty,
                        format!("{family}.lt"),
                        quote! { *#elem_ident >= #hi },
                    );
                }
                if let Some(hi) = n.lte {
                    push(
                        &mut out,
                        family,
                        outer,
                        "lte",
                        3,
                        scalar_ty,
                        format!("{family}.lte"),
                        quote! { *#elem_ident > #hi },
                    );
                }
            }
        }
        FieldKind::Int64 | FieldKind::Sint64 | FieldKind::Sfixed64 => {
            let (family, outer, scalar_ty) = match kind {
                FieldKind::Int64 => ("int64", 4, "Int64"),
                FieldKind::Sint64 => ("sint64", 8, "Sint64"),
                FieldKind::Sfixed64 => ("sfixed64", 12, "Sfixed64"),
                _ => unreachable!(),
            };
            if let Some(n) = &rules.int64 {
                if let Some(c) = n.r#const {
                    push(
                        &mut out,
                        family,
                        outer,
                        "const",
                        1,
                        scalar_ty,
                        format!("{family}.const"),
                        quote! { *#elem_ident != #c },
                    );
                }
                if let Some(lo) = n.gt {
                    push(
                        &mut out,
                        family,
                        outer,
                        "gt",
                        4,
                        scalar_ty,
                        format!("{family}.gt"),
                        quote! { *#elem_ident <= #lo },
                    );
                }
                if let Some(lo) = n.gte {
                    push(
                        &mut out,
                        family,
                        outer,
                        "gte",
                        5,
                        scalar_ty,
                        format!("{family}.gte"),
                        quote! { *#elem_ident < #lo },
                    );
                }
                if let Some(hi) = n.lt {
                    push(
                        &mut out,
                        family,
                        outer,
                        "lt",
                        2,
                        scalar_ty,
                        format!("{family}.lt"),
                        quote! { *#elem_ident >= #hi },
                    );
                }
                if let Some(hi) = n.lte {
                    push(
                        &mut out,
                        family,
                        outer,
                        "lte",
                        3,
                        scalar_ty,
                        format!("{family}.lte"),
                        quote! { *#elem_ident > #hi },
                    );
                }
            }
        }
        FieldKind::Uint32 | FieldKind::Fixed32 => {
            let (family, outer, scalar_ty) = match kind {
                FieldKind::Uint32 => ("uint32", 5, "Uint32"),
                FieldKind::Fixed32 => ("fixed32", 9, "Fixed32"),
                _ => unreachable!(),
            };
            if let Some(n) = &rules.uint32 {
                if let Some(c) = n.r#const {
                    push(
                        &mut out,
                        family,
                        outer,
                        "const",
                        1,
                        scalar_ty,
                        format!("{family}.const"),
                        quote! { *#elem_ident != #c },
                    );
                }
                if let Some(lo) = n.gt {
                    push(
                        &mut out,
                        family,
                        outer,
                        "gt",
                        4,
                        scalar_ty,
                        format!("{family}.gt"),
                        quote! { *#elem_ident <= #lo },
                    );
                }
                if let Some(lo) = n.gte {
                    push(
                        &mut out,
                        family,
                        outer,
                        "gte",
                        5,
                        scalar_ty,
                        format!("{family}.gte"),
                        quote! { *#elem_ident < #lo },
                    );
                }
                if let Some(hi) = n.lt {
                    push(
                        &mut out,
                        family,
                        outer,
                        "lt",
                        2,
                        scalar_ty,
                        format!("{family}.lt"),
                        quote! { *#elem_ident >= #hi },
                    );
                }
                if let Some(hi) = n.lte {
                    push(
                        &mut out,
                        family,
                        outer,
                        "lte",
                        3,
                        scalar_ty,
                        format!("{family}.lte"),
                        quote! { *#elem_ident > #hi },
                    );
                }
            }
        }
        FieldKind::Uint64 | FieldKind::Fixed64 => {
            let (family, outer, scalar_ty) = match kind {
                FieldKind::Uint64 => ("uint64", 6, "Uint64"),
                FieldKind::Fixed64 => ("fixed64", 10, "Fixed64"),
                _ => unreachable!(),
            };
            if let Some(n) = &rules.uint64 {
                if let Some(c) = n.r#const {
                    push(
                        &mut out,
                        family,
                        outer,
                        "const",
                        1,
                        scalar_ty,
                        format!("{family}.const"),
                        quote! { *#elem_ident != #c },
                    );
                }
                if let Some(lo) = n.gt {
                    push(
                        &mut out,
                        family,
                        outer,
                        "gt",
                        4,
                        scalar_ty,
                        format!("{family}.gt"),
                        quote! { *#elem_ident <= #lo },
                    );
                }
                if let Some(lo) = n.gte {
                    push(
                        &mut out,
                        family,
                        outer,
                        "gte",
                        5,
                        scalar_ty,
                        format!("{family}.gte"),
                        quote! { *#elem_ident < #lo },
                    );
                }
                if let Some(hi) = n.lt {
                    push(
                        &mut out,
                        family,
                        outer,
                        "lt",
                        2,
                        scalar_ty,
                        format!("{family}.lt"),
                        quote! { *#elem_ident >= #hi },
                    );
                }
                if let Some(hi) = n.lte {
                    push(
                        &mut out,
                        family,
                        outer,
                        "lte",
                        3,
                        scalar_ty,
                        format!("{family}.lte"),
                        quote! { *#elem_ident > #hi },
                    );
                }
            }
        }
        FieldKind::Enum { .. } => {
            if let Some(e) = &rules.enum_rules {
                if let Some(c) = e.r#const {
                    push(
                        &mut out,
                        "enum",
                        16,
                        "const",
                        1,
                        "Int32",
                        "enum.const".to_string(),
                        quote! { #elem_ident.to_i32() != #c },
                    );
                }
                if !e.in_set.is_empty() {
                    let set = &e.in_set;
                    let fp = fp_idx.clone();
                    let rule = rule_path_4("enum", 16, "in", 3, "Int32");
                    out.push(quote! {
                        {
                            const ALLOWED: &[i32] = &[ #( #set ),* ];
                            if !ALLOWED.contains(&#elem_ident.to_i32()) {
                                violations.push(::protovalidate_buffa::Violation {
                                    field: #fp, rule: #rule,
                                    rule_id: ::std::borrow::Cow::Borrowed("enum.in"),
                                    message: ::std::borrow::Cow::Borrowed(""),
                                    for_key: false,
                                });
                            }
                        }
                    });
                }
                if !e.not_in.is_empty() {
                    let set = &e.not_in;
                    let fp = fp_idx.clone();
                    let rule = rule_path_4("enum", 16, "not_in", 4, "Int32");
                    out.push(quote! {
                        {
                            const DISALLOWED: &[i32] = &[ #( #set ),* ];
                            if DISALLOWED.contains(&#elem_ident.to_i32()) {
                                violations.push(::protovalidate_buffa::Violation {
                                    field: #fp, rule: #rule,
                                    rule_id: ::std::borrow::Cow::Borrowed("enum.not_in"),
                                    message: ::std::borrow::Cow::Borrowed(""),
                                    for_key: false,
                                });
                            }
                        }
                    });
                }
            }
        }
        FieldKind::Float => {
            if let Some(f) = &rules.float {
                if let Some(lo) = f.gt {
                    push(
                        &mut out,
                        "float",
                        1,
                        "gt",
                        4,
                        "Float",
                        "float.gt".to_string(),
                        quote! { !(*#elem_ident > #lo) },
                    );
                }
                if let Some(lo) = f.gte {
                    push(
                        &mut out,
                        "float",
                        1,
                        "gte",
                        5,
                        "Float",
                        "float.gte".to_string(),
                        quote! { !(*#elem_ident >= #lo) },
                    );
                }
                if let Some(hi) = f.lt {
                    push(
                        &mut out,
                        "float",
                        1,
                        "lt",
                        2,
                        "Float",
                        "float.lt".to_string(),
                        quote! { !(*#elem_ident < #hi) },
                    );
                }
                if let Some(hi) = f.lte {
                    push(
                        &mut out,
                        "float",
                        1,
                        "lte",
                        3,
                        "Float",
                        "float.lte".to_string(),
                        quote! { !(*#elem_ident <= #hi) },
                    );
                }
                if let Some(c) = f.r#const {
                    push(
                        &mut out,
                        "float",
                        1,
                        "const",
                        1,
                        "Float",
                        "float.const".to_string(),
                        quote! { *#elem_ident != #c },
                    );
                }
            }
        }
        FieldKind::Double => {
            if let Some(d) = &rules.double {
                if let Some(lo) = d.gt {
                    push(
                        &mut out,
                        "double",
                        2,
                        "gt",
                        4,
                        "Double",
                        "double.gt".to_string(),
                        quote! { !(*#elem_ident > #lo) },
                    );
                }
                if let Some(lo) = d.gte {
                    push(
                        &mut out,
                        "double",
                        2,
                        "gte",
                        5,
                        "Double",
                        "double.gte".to_string(),
                        quote! { !(*#elem_ident >= #lo) },
                    );
                }
                if let Some(hi) = d.lt {
                    push(
                        &mut out,
                        "double",
                        2,
                        "lt",
                        2,
                        "Double",
                        "double.lt".to_string(),
                        quote! { !(*#elem_ident < #hi) },
                    );
                }
                if let Some(hi) = d.lte {
                    push(
                        &mut out,
                        "double",
                        2,
                        "lte",
                        3,
                        "Double",
                        "double.lte".to_string(),
                        quote! { !(*#elem_ident <= #hi) },
                    );
                }
                if let Some(c) = d.r#const {
                    push(
                        &mut out,
                        "double",
                        2,
                        "const",
                        1,
                        "Double",
                        "double.const".to_string(),
                        quote! { *#elem_ident != #c },
                    );
                }
            }
        }
        FieldKind::Bool => {
            if let Some(b) = &rules.bool_rules {
                if let Some(c) = b.r#const {
                    push(
                        &mut out,
                        "bool",
                        13,
                        "const",
                        1,
                        "Bool",
                        "bool.const".to_string(),
                        quote! { *#elem_ident != #c },
                    );
                }
            }
        }
        FieldKind::String => {
            if let Some(s) = &rules.string {
                if !s.in_set.is_empty() {
                    let set = &s.in_set;
                    let fp = fp_idx.clone();
                    let rule = rule_path_4("string", 14, "in", 10, "String");
                    out.push(quote! {
                        {
                            const ALLOWED: &[&str] = &[ #( #set ),* ];
                            if !ALLOWED.iter().any(|c| *c == #elem_ident.as_str()) {
                                violations.push(::protovalidate_buffa::Violation {
                                    field: #fp, rule: #rule,
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
                    let fp = fp_idx.clone();
                    let rule = rule_path_4("string", 14, "not_in", 11, "String");
                    out.push(quote! {
                        {
                            const DISALLOWED: &[&str] = &[ #( #set ),* ];
                            if DISALLOWED.iter().any(|c| *c == #elem_ident.as_str()) {
                                violations.push(::protovalidate_buffa::Violation {
                                    field: #fp, rule: #rule,
                                    rule_id: ::std::borrow::Cow::Borrowed("string.not_in"),
                                    message: ::std::borrow::Cow::Borrowed(""),
                                    for_key: false,
                                });
                            }
                        }
                    });
                }
                if let Some(c) = &s.r#const {
                    let fp = fp_idx.clone();
                    let rule = rule_path_4("string", 14, "const", 1, "String");
                    out.push(quote! {
                        if #elem_ident != #c {
                            violations.push(::protovalidate_buffa::Violation {
                                field: #fp, rule: #rule,
                                rule_id: ::std::borrow::Cow::Borrowed("string.const"),
                                message: ::std::borrow::Cow::Borrowed(""),
                                for_key: false,
                            });
                        }
                    });
                }
                if let Some(n) = s.len {
                    let n_usize = usize::try_from(n).expect("len fits in usize");
                    push(
                        &mut out,
                        "string",
                        14,
                        "len",
                        19,
                        "Uint64",
                        "string.len".to_string(),
                        quote! { #elem_ident.chars().count() != #n_usize },
                    );
                }
                if let Some(n) = s.min_len {
                    let n_usize = usize::try_from(n).expect("len fits in usize");
                    push(
                        &mut out,
                        "string",
                        14,
                        "min_len",
                        2,
                        "Uint64",
                        "string.min_len".to_string(),
                        quote! { #elem_ident.chars().count() < #n_usize },
                    );
                }
                if let Some(n) = s.max_len {
                    let n_usize = usize::try_from(n).expect("len fits in usize");
                    push(
                        &mut out,
                        "string",
                        14,
                        "max_len",
                        3,
                        "Uint64",
                        "string.max_len".to_string(),
                        quote! { #elem_ident.chars().count() > #n_usize },
                    );
                }
                if let Some(pat) = &s.pattern {
                    let pat_str = pat.as_str();
                    let cache_ident = format_ident!(
                        "RE_ITEMS_{}",
                        name_lit
                            .to_uppercase()
                            .replace(|c: char| !c.is_alphanumeric(), "_")
                    );
                    let fp = fp_idx.clone();
                    let rule = rule_path_4("string", 14, "pattern", 6, "String");
                    out.push(quote! {
                        {
                            static #cache_ident: ::std::sync::OnceLock<::protovalidate_buffa::regex::Regex> =
                                ::std::sync::OnceLock::new();
                            let re = #cache_ident.get_or_init(|| {
                                ::protovalidate_buffa::regex::Regex::new(#pat_str)
                                    .expect("pattern regex compiled at code-gen time")
                            });
                            if !re.is_match(#elem_ident) {
                                violations.push(::protovalidate_buffa::Violation {
                                    field: #fp, rule: #rule,
                                    rule_id: ::std::borrow::Cow::Borrowed("string.pattern"),
                                    message: ::std::borrow::Cow::Borrowed(""),
                                    for_key: false,
                                });
                            }
                        }
                    });
                }
            }
        }
        _ => {}
    }
    out
}

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
/// - Per-element scalar rules from `items` (for string/bytes/numeric elements).
/// - Per-element message recursion (for message-typed elements).
///
/// # Errors
///
/// Returns an error if the emitted `TokenStream` cannot be assembled (currently
/// infallible; reserved for future element-level emitters that may fail).
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
        out.push(quote! {
            {
                let mut seen: ::std::collections::HashSet<_> = ::std::collections::HashSet::new();
                let mut dup = false;
                for item in self.#accessor.iter() {
                    if !seen.insert(item) { dup = true; break; }
                }
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

    // Per-element scalar rules — only for non-message elements.
    // Message elements are handled by the recursion block below.
    if let Some(items) = &spec.items {
        if matches!(items.ignore, crate::scan::Ignore::Always) {
            // Entirely skip per-element checks.
            return Ok(quote! { #( #out )* });
        }
        if !matches!(element_kind, FieldKind::Message { .. }) {
            let elem_ident = format_ident!("elem");
            // Emit metadata-rich items checks for supported numeric kinds.
            let items_checks = emit_repeated_items_checks(
                &elem_ident,
                element_kind,
                &items.standard,
                name_lit,
                field_number,
                element_type_variant,
            );
            if !items_checks.is_empty() {
                let ignore_empty = matches!(items.ignore, crate::scan::Ignore::IfZeroValue);
                let guard: Option<TokenStream> = if ignore_empty {
                    match element_kind {
                        FieldKind::String | FieldKind::Bytes => {
                            Some(quote! { !#elem_ident.is_empty() })
                        }
                        FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32 => {
                            Some(quote! { *#elem_ident != 0i32 })
                        }
                        FieldKind::Int64 | FieldKind::Sint64 | FieldKind::Sfixed64 => {
                            Some(quote! { *#elem_ident != 0i64 })
                        }
                        FieldKind::Uint32 | FieldKind::Fixed32 => {
                            Some(quote! { *#elem_ident != 0u32 })
                        }
                        FieldKind::Uint64 | FieldKind::Fixed64 => {
                            Some(quote! { *#elem_ident != 0u64 })
                        }
                        FieldKind::Float => Some(quote! { *#elem_ident != 0f32 }),
                        FieldKind::Double => Some(quote! { *#elem_ident != 0f64 }),
                        FieldKind::Bool => Some(quote! { *#elem_ident }),
                        _ => None,
                    }
                } else {
                    None
                };
                match guard {
                    Some(g) => out.push(quote! {
                        for (idx, elem) in self.#accessor.iter().enumerate() {
                            if #g { #( #items_checks )* }
                        }
                    }),
                    None => out.push(quote! {
                        for (idx, elem) in self.#accessor.iter().enumerate() {
                            #( #items_checks )*
                        }
                    }),
                }
                return Ok(quote! { #( #out )* });
            }
            let checks =
                emit_scalar_checks(&elem_ident, element_kind, &items.standard, name_lit, false);
            if !checks.is_empty() {
                // IGNORE_IF_ZERO_VALUE on items: skip zero-value elements.
                let ignore_empty = matches!(items.ignore, crate::scan::Ignore::IfZeroValue);
                let guard: Option<TokenStream> = if ignore_empty {
                    match element_kind {
                        FieldKind::String | FieldKind::Bytes => {
                            Some(quote! { !#elem_ident.is_empty() })
                        }
                        FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32 => {
                            Some(quote! { *#elem_ident != 0i32 })
                        }
                        FieldKind::Int64 | FieldKind::Sint64 | FieldKind::Sfixed64 => {
                            Some(quote! { *#elem_ident != 0i64 })
                        }
                        FieldKind::Uint32 | FieldKind::Fixed32 => {
                            Some(quote! { *#elem_ident != 0u32 })
                        }
                        FieldKind::Uint64 | FieldKind::Fixed64 => {
                            Some(quote! { *#elem_ident != 0u64 })
                        }
                        FieldKind::Float => Some(quote! { *#elem_ident != 0f32 }),
                        FieldKind::Double => Some(quote! { *#elem_ident != 0f64 }),
                        FieldKind::Bool => Some(quote! { *#elem_ident }),
                        _ => None,
                    }
                } else {
                    None
                };
                match guard {
                    Some(g) => out.push(quote! {
                        for (idx, elem) in self.#accessor.iter().enumerate() {
                            let _ = idx;
                            if #g { #( #checks )* }
                        }
                    }),
                    None => out.push(quote! {
                        for (idx, elem) in self.#accessor.iter().enumerate() {
                            let _ = idx;
                            #( #checks )*
                        }
                    }),
                }
            }
        }
    }

    // Per-element WKT (Any, Duration) rules.
    if let Some(items) = &spec.items {
        if !matches!(items.ignore, crate::scan::Ignore::Always) {
            if let FieldKind::Message { full_name } = element_kind {
                if full_name == "google.protobuf.Duration" {
                    if let Some(d) = &items.standard.duration {
                        let fnum = field_number;
                        let nl = name_lit;
                        let emit_dur = |out: &mut Vec<TokenStream>,
                                        inner_name: &str,
                                        inner_num: i32,
                                        bound: &(i64, i32),
                                        op: &str,
                                        rule_id: &str,
                                        msg: &str| {
                            let (secs, nano) = *bound;
                            let cond: TokenStream = match op {
                                "gte" => {
                                    quote! { elem_ns < #secs as i128 * 1_000_000_000 + #nano as i128 }
                                }
                                "gt" => {
                                    quote! { elem_ns <= #secs as i128 * 1_000_000_000 + #nano as i128 }
                                }
                                "lte" => {
                                    quote! { elem_ns > #secs as i128 * 1_000_000_000 + #nano as i128 }
                                }
                                "lt" => {
                                    quote! { elem_ns >= #secs as i128 * 1_000_000_000 + #nano as i128 }
                                }
                                _ => return,
                            };
                            let inner_name_s = inner_name.to_string();
                            let rid = rule_id.to_string();
                            let ms = msg.to_string();
                            out.push(quote! {
                                for (idx, elem) in self.#accessor.iter().enumerate() {
                                    let elem_ns: i128 = elem.seconds as i128 * 1_000_000_000 + elem.nanos as i128;
                                    if #cond {
                                        violations.push(::protovalidate_buffa::Violation {
                                            field: ::protovalidate_buffa::FieldPath {
                                                elements: ::std::vec![::protovalidate_buffa::FieldPathElement {
                                                    field_number: Some(#fnum),
                                                    field_name: Some(::std::borrow::Cow::Borrowed(#nl)),
                                                    field_type: Some(::protovalidate_buffa::FieldType::Message),
                                                    key_type: None, value_type: None,
                                                    subscript: Some(::protovalidate_buffa::Subscript::Index(idx as u64)),
                                                }],
                                            },
                                            rule: ::protovalidate_buffa::FieldPath {
                                                elements: ::std::vec![
                                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(18i32), field_name: Some(::std::borrow::Cow::Borrowed("repeated")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(4i32), field_name: Some(::std::borrow::Cow::Borrowed("items")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(21i32), field_name: Some(::std::borrow::Cow::Borrowed("duration")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(#inner_num), field_name: Some(::std::borrow::Cow::Borrowed(#inner_name_s)), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                                ],
                                            },
                                            rule_id: ::std::borrow::Cow::Borrowed(#rid),
                                            message: ::std::borrow::Cow::Borrowed(#ms),
                                            for_key: false,
                                        });
                                    }
                                }
                            });
                        };
                        if let Some(b) = &d.gte {
                            emit_dur(
                                &mut out,
                                "gte",
                                6,
                                b,
                                "gte",
                                "duration.gte",
                                "must be greater than or equal to 0.001s",
                            );
                        }
                        if let Some(b) = &d.gt {
                            emit_dur(&mut out, "gt", 5, b, "gt", "duration.gt", "");
                        }
                        if let Some(b) = &d.lte {
                            emit_dur(&mut out, "lte", 4, b, "lte", "duration.lte", "");
                        }
                        if let Some(b) = &d.lt {
                            emit_dur(&mut out, "lt", 3, b, "lt", "duration.lt", "");
                        }
                    }
                }
                if full_name == "google.protobuf.Timestamp" {
                    if let Some(t) = &items.standard.timestamp {
                        let fnum = field_number;
                        let nl = name_lit;
                        let emit_ts = |out: &mut Vec<TokenStream>,
                                       inner_name: &str,
                                       inner_num: i32,
                                       bound: &(i64, i32),
                                       op: &str,
                                       rule_id: &str| {
                            let (secs, nano) = *bound;
                            let cond: TokenStream = match op {
                                "gte" => {
                                    quote! { elem_ns < #secs as i128 * 1_000_000_000 + #nano as i128 }
                                }
                                "gt" => {
                                    quote! { elem_ns <= #secs as i128 * 1_000_000_000 + #nano as i128 }
                                }
                                "lte" => {
                                    quote! { elem_ns > #secs as i128 * 1_000_000_000 + #nano as i128 }
                                }
                                "lt" => {
                                    quote! { elem_ns >= #secs as i128 * 1_000_000_000 + #nano as i128 }
                                }
                                _ => return,
                            };
                            let inner_name_s = inner_name.to_string();
                            let rid = rule_id.to_string();
                            out.push(quote! {
                                for (idx, elem) in self.#accessor.iter().enumerate() {
                                    let elem_ns: i128 = elem.seconds as i128 * 1_000_000_000 + elem.nanos as i128;
                                    if #cond {
                                        violations.push(::protovalidate_buffa::Violation {
                                            field: ::protovalidate_buffa::FieldPath {
                                                elements: ::std::vec![::protovalidate_buffa::FieldPathElement {
                                                    field_number: Some(#fnum),
                                                    field_name: Some(::std::borrow::Cow::Borrowed(#nl)),
                                                    field_type: Some(::protovalidate_buffa::FieldType::Message),
                                                    key_type: None, value_type: None,
                                                    subscript: Some(::protovalidate_buffa::Subscript::Index(idx as u64)),
                                                }],
                                            },
                                            rule: ::protovalidate_buffa::FieldPath {
                                                elements: ::std::vec![
                                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(18i32), field_name: Some(::std::borrow::Cow::Borrowed("repeated")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(4i32), field_name: Some(::std::borrow::Cow::Borrowed("items")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(22i32), field_name: Some(::std::borrow::Cow::Borrowed("timestamp")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(#inner_num), field_name: Some(::std::borrow::Cow::Borrowed(#inner_name_s)), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                                ],
                                            },
                                            rule_id: ::std::borrow::Cow::Borrowed(#rid),
                                            message: ::std::borrow::Cow::Borrowed(""),
                                            for_key: false,
                                        });
                                    }
                                }
                            });
                        };
                        if let Some(b) = &t.gte {
                            emit_ts(&mut out, "gte", 6, b, "gte", "timestamp.gte");
                        }
                        if let Some(b) = &t.gt {
                            emit_ts(&mut out, "gt", 5, b, "gt", "timestamp.gt");
                        }
                        if let Some(b) = &t.lte {
                            emit_ts(&mut out, "lte", 4, b, "lte", "timestamp.lte");
                        }
                        if let Some(b) = &t.lt {
                            emit_ts(&mut out, "lt", 3, b, "lt", "timestamp.lt");
                        }
                    }
                }
                if full_name == "google.protobuf.Any" {
                    if let Some(a) = &items.standard.any_rules {
                        if !a.in_set.is_empty() {
                            let set = &a.in_set;
                            let fnum = field_number;
                            let nl = name_lit;
                            out.push(quote! {
                                for (idx, elem) in self.#accessor.iter().enumerate() {
                                    const ALLOWED: &[&str] = &[ #( #set ),* ];
                                    if !ALLOWED.iter().any(|s| *s == elem.type_url.as_str()) {
                                        violations.push(::protovalidate_buffa::Violation {
                                            field: ::protovalidate_buffa::FieldPath {
                                                elements: ::std::vec![::protovalidate_buffa::FieldPathElement {
                                                    field_number: Some(#fnum),
                                                    field_name: Some(::std::borrow::Cow::Borrowed(#nl)),
                                                    field_type: Some(::protovalidate_buffa::FieldType::Message),
                                                    key_type: None, value_type: None,
                                                    subscript: Some(::protovalidate_buffa::Subscript::Index(idx as u64)),
                                                }],
                                            },
                                            rule: ::protovalidate_buffa::FieldPath {
                                                elements: ::std::vec![
                                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(18i32), field_name: Some(::std::borrow::Cow::Borrowed("repeated")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(4i32), field_name: Some(::std::borrow::Cow::Borrowed("items")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(20i32), field_name: Some(::std::borrow::Cow::Borrowed("any")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(2i32), field_name: Some(::std::borrow::Cow::Borrowed("in")), field_type: Some(::protovalidate_buffa::FieldType::String), key_type: None, value_type: None, subscript: None },
                                                ],
                                            },
                                            rule_id: ::std::borrow::Cow::Borrowed("any.in"),
                                            message: ::std::borrow::Cow::Borrowed("type URL must be in the allow list"),
                                            for_key: false,
                                        });
                                    }
                                }
                            });
                        }
                        if !a.not_in.is_empty() {
                            let set = &a.not_in;
                            let fnum = field_number;
                            let nl = name_lit;
                            out.push(quote! {
                                for (idx, elem) in self.#accessor.iter().enumerate() {
                                    const DENIED: &[&str] = &[ #( #set ),* ];
                                    if DENIED.iter().any(|s| *s == elem.type_url.as_str()) {
                                        violations.push(::protovalidate_buffa::Violation {
                                            field: ::protovalidate_buffa::FieldPath {
                                                elements: ::std::vec![::protovalidate_buffa::FieldPathElement {
                                                    field_number: Some(#fnum),
                                                    field_name: Some(::std::borrow::Cow::Borrowed(#nl)),
                                                    field_type: Some(::protovalidate_buffa::FieldType::Message),
                                                    key_type: None, value_type: None,
                                                    subscript: Some(::protovalidate_buffa::Subscript::Index(idx as u64)),
                                                }],
                                            },
                                            rule: ::protovalidate_buffa::FieldPath {
                                                elements: ::std::vec![
                                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(18i32), field_name: Some(::std::borrow::Cow::Borrowed("repeated")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(4i32), field_name: Some(::std::borrow::Cow::Borrowed("items")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(20i32), field_name: Some(::std::borrow::Cow::Borrowed("any")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(3i32), field_name: Some(::std::borrow::Cow::Borrowed("not_in")), field_type: Some(::protovalidate_buffa::FieldType::String), key_type: None, value_type: None, subscript: None },
                                                ],
                                            },
                                            rule_id: ::std::borrow::Cow::Borrowed("any.not_in"),
                                            message: ::std::borrow::Cow::Borrowed("type URL must not be in the block list"),
                                            for_key: false,
                                        });
                                    }
                                }
                            });
                        }
                    }
                }
            }
        }
    }

    // Per-element predefined (extension-based) rules (`repeated.items.<family>.<ext>`).
    if let Some(items) = &spec.items {
        if !matches!(items.ignore, crate::scan::Ignore::Always)
            && !items.standard.predefined.is_empty()
        {
            let element_ty_ident = format_ident!("{}", element_type_variant);
            let family = crate::emit::cel::predef_family_for(element_kind, &items.standard);
            for (pi, rule) in items.standard.predefined.iter().enumerate() {
                let id = rule.id.as_str();
                let msg = rule.message.as_str();
                let expr = rule.expression.as_str();
                let ext_num = rule.ext_number;
                let ext_name = &rule.ext_name;
                let ext_ty_ident = format_ident!("{}", rule.ext_field_type);
                let rule_value: TokenStream = syn::parse_str(&rule.rule_value_expr)
                    .unwrap_or_else(|_| quote! { ::protovalidate_buffa::cel_core::Value::Null });
                let Some(fam) = family else { continue };
                let fam_name = fam.name;
                let fam_num = fam.number;
                let ext_bracketed = format!("[buf.validate.conformance.cases.{ext_name}]");
                let static_ident = format_ident!(
                    "__ITEMS_PRED_{}_{}",
                    pi,
                    id.replace(|c: char| !c.is_ascii_alphanumeric(), "_")
                        .to_uppercase()
                );
                let as_value: TokenStream = match element_kind {
                    FieldKind::Message { full_name }
                        if full_name.starts_with("google.protobuf.")
                            && full_name.ends_with("Value") =>
                    {
                        // Wrapper (FloatValue, Int32Value, etc.) — use inner .value.
                        quote! { ::protovalidate_buffa::cel::to_cel_value(&elem.value) }
                    }
                    FieldKind::Message { .. } => {
                        quote! { ::protovalidate_buffa::cel::AsCelValue::as_cel_value(elem) }
                    }
                    _ => quote! { ::protovalidate_buffa::cel::to_cel_value(elem) },
                };
                out.push(quote! {
                    {
                        static #static_ident: ::protovalidate_buffa::cel::CelConstraint =
                            ::protovalidate_buffa::cel::CelConstraint::new(#id, #msg, #expr);
                        for (idx, elem) in self.#accessor.iter().enumerate() {
                            let field_path = ::protovalidate_buffa::FieldPath {
                                elements: ::std::vec![::protovalidate_buffa::FieldPathElement {
                                    field_number: Some(#field_number),
                                    field_name: Some(::std::borrow::Cow::Borrowed(#name_lit)),
                                    field_type: Some(::protovalidate_buffa::FieldType::#element_ty_ident),
                                    key_type: None, value_type: None,
                                    subscript: Some(::protovalidate_buffa::Subscript::Index(idx as u64)),
                                }],
                            };
                            let rule_path = ::protovalidate_buffa::FieldPath {
                                elements: ::std::vec![
                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(18i32), field_name: Some(::std::borrow::Cow::Borrowed("repeated")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(4i32), field_name: Some(::std::borrow::Cow::Borrowed("items")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(#fam_num), field_name: Some(::std::borrow::Cow::Borrowed(#fam_name)), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                    ::protovalidate_buffa::FieldPathElement { field_number: Some(#ext_num), field_name: Some(::std::borrow::Cow::Borrowed(#ext_bracketed)), field_type: Some(::protovalidate_buffa::FieldType::#ext_ty_ident), key_type: None, value_type: None, subscript: None },
                                ],
                            };
                            if let Err(v) = #static_ident.eval_predefined(#as_value, #rule_value, field_path, rule_path) {
                                violations.push(v);
                            }
                        }
                    }
                });
            }
        }
    }

    // Per-element CEL rules (`repeated.items.cel`).
    if let Some(items) = &spec.items {
        if !matches!(items.ignore, crate::scan::Ignore::Always) && !items.cel.is_empty() {
            let element_ty_ident = format_ident!("{}", element_type_variant);
            for (idx, rule) in items.cel.iter().enumerate() {
                let id = rule.id.as_str();
                let msg = rule.message.as_str();
                let expr = rule.expression.as_str();
                let idx_lit = idx as u64;
                let as_value: TokenStream = if matches!(element_kind, FieldKind::Message { .. }) {
                    quote! { ::protovalidate_buffa::cel::AsCelValue::as_cel_value(elem) }
                } else {
                    quote! { ::protovalidate_buffa::cel::to_cel_value(elem) }
                };
                out.push(quote! {
                    {
                        static __ITEMS_CEL: ::protovalidate_buffa::cel::CelConstraint =
                            ::protovalidate_buffa::cel::CelConstraint::new(#id, #msg, #expr);
                        for (idx, elem) in self.#accessor.iter().enumerate() {
                            let fp = ::protovalidate_buffa::FieldPath {
                                elements: ::std::vec![::protovalidate_buffa::FieldPathElement {
                                    field_number: Some(#field_number),
                                    field_name: Some(::std::borrow::Cow::Borrowed(#name_lit)),
                                    field_type: Some(::protovalidate_buffa::FieldType::#element_ty_ident),
                                    key_type: None,
                                    value_type: None,
                                    subscript: Some(::protovalidate_buffa::Subscript::Index(idx as u64)),
                                }],
                            };
                            if let Err(v) = __ITEMS_CEL.eval_repeated_items_cel(#as_value, fp, #idx_lit) {
                                violations.push(v);
                            }
                        }
                    }
                });
            }
        }
    }

    // Per-element message recursion. Skip google.protobuf.* (WKTs we don't
    // validate) and any cross-package messages where we can't guarantee an
    // impl Validate exists.
    if let FieldKind::Message { full_name } = element_kind {
        if !full_name.starts_with("google.protobuf.") {
            let fnum = field_number;
            out.push(quote! {
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
/// Returns an error if the emitted `TokenStream` cannot be assembled (currently
/// infallible; reserved for future key/value emitters that may fail).
///
/// # Panics
///
/// Panics if `min_pairs` or `max_pairs` cannot be converted to `usize`. In
/// practice proto size bounds are small non-negative integers, so this
/// invariant always holds.
pub fn emit_map(
    accessor: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    spec: &MapStandard,
    key_kind: &FieldKind,
    value_kind: &FieldKind,
) -> Result<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    let fp = || map_field_path(name_lit, field_number);

    if let Some(min) = spec.min_pairs {
        let min_usize = usize::try_from(min).expect("proto length bound fits in usize");
        let field = fp();
        let rule = map_rule_path("min_pairs", 1);
        out.push(quote! {
            if self.#accessor.len() < #min_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("map.min_pairs"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "map must contain at least {} pairs (got {})",
                        #min_usize, self.#accessor.len()
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
            if self.#accessor.len() > #max_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("map.max_pairs"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "map must contain at most {} pairs (got {})",
                        #max_usize, self.#accessor.len()
                    )),
                    for_key: false,
                });
            }
        });
    }

    let keys_always = spec
        .keys
        .as_deref()
        .is_some_and(|k| matches!(k.ignore, crate::scan::Ignore::Always));
    let values_always = spec
        .values
        .as_deref()
        .is_some_and(|v| matches!(v.ignore, crate::scan::Ignore::Always));
    let key_ty_variant = crate::emit::field::kind_to_field_type(key_kind);
    let val_ty_variant = crate::emit::field::kind_to_field_type(value_kind);

    let key_checks: Vec<TokenStream> = if keys_always {
        Vec::new()
    } else if let Some(k) = spec.keys.as_deref() {
        let rich = emit_map_kv_checks(
            &format_ident!("key"),
            key_kind,
            &k.standard,
            name_lit,
            field_number,
            key_ty_variant,
            val_ty_variant,
            true,
        );
        if rich.is_empty() {
            emit_scalar_checks(&format_ident!("key"), key_kind, &k.standard, name_lit, true)
        } else {
            rich
        }
    } else {
        Vec::new()
    };

    let val_checks: Vec<TokenStream> = if values_always {
        Vec::new()
    } else if let Some(v) = spec.values.as_deref() {
        let rich = emit_map_kv_checks(
            &format_ident!("value"),
            value_kind,
            &v.standard,
            name_lit,
            field_number,
            key_ty_variant,
            val_ty_variant,
            false,
        );
        if rich.is_empty() {
            emit_scalar_checks(
                &format_ident!("value"),
                value_kind,
                &v.standard,
                name_lit,
                false,
            )
        } else {
            rich
        }
    } else {
        Vec::new()
    };

    // Zero-value guards for ignore_empty on map keys/values.
    let zero_guard = |kind: &FieldKind, ident: &syn::Ident| -> Option<TokenStream> {
        match kind {
            FieldKind::String | FieldKind::Bytes => Some(quote! { !#ident.is_empty() }),
            FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32 => {
                Some(quote! { *#ident != 0i32 })
            }
            FieldKind::Int64 | FieldKind::Sint64 | FieldKind::Sfixed64 => {
                Some(quote! { *#ident != 0i64 })
            }
            FieldKind::Uint32 | FieldKind::Fixed32 => Some(quote! { *#ident != 0u32 }),
            FieldKind::Uint64 | FieldKind::Fixed64 => Some(quote! { *#ident != 0u64 }),
            FieldKind::Float => Some(quote! { *#ident != 0f32 }),
            FieldKind::Double => Some(quote! { *#ident != 0f64 }),
            FieldKind::Bool => Some(quote! { *#ident }),
            _ => None,
        }
    };
    let key_empty = spec
        .keys
        .as_deref()
        .is_some_and(|k| matches!(k.ignore, crate::scan::Ignore::IfZeroValue));
    let val_empty = spec
        .values
        .as_deref()
        .is_some_and(|v| matches!(v.ignore, crate::scan::Ignore::IfZeroValue));
    let key_guard = if key_empty {
        zero_guard(key_kind, &format_ident!("key"))
    } else {
        None
    };
    let val_guard = if val_empty {
        zero_guard(value_kind, &format_ident!("value"))
    } else {
        None
    };

    if !key_checks.is_empty() || !val_checks.is_empty() {
        let key_block = key_guard.as_ref().map_or_else(
            || quote! { #( #key_checks )* },
            |g| quote! { if #g { #( #key_checks )* } },
        );
        let val_block = val_guard.as_ref().map_or_else(
            || quote! { #( #val_checks )* },
            |g| quote! { if #g { #( #val_checks )* } },
        );
        out.push(quote! {
            for (key, value) in self.#accessor.iter() {
                #key_block
                #val_block
            }
        });
    }

    // Per-key / per-value CEL rules.
    let key_ty_ident = format_ident!("{}", crate::emit::field::kind_to_field_type(key_kind));
    let val_ty_ident = format_ident!("{}", crate::emit::field::kind_to_field_type(value_kind));
    let emit_map_cel =
        |out: &mut Vec<TokenStream>, rules: &[crate::scan::CelRule], for_key: bool| {
            let Some(key_subscript) =
                kind_variant_to_subscript(crate::emit::field::kind_to_field_type(key_kind))
            else {
                return;
            };
            for (idx, rule) in rules.iter().enumerate() {
                let id = rule.id.as_str();
                let msg = rule.message.as_str();
                let expr = rule.expression.as_str();
                let idx_lit = idx as u64;
                let value_ident = format_ident!("{}", if for_key { "key" } else { "value" });
                let target_kind = if for_key { key_kind } else { value_kind };
                let as_value: TokenStream = if matches!(target_kind, FieldKind::Message { .. }) {
                    quote! { ::protovalidate_buffa::cel::AsCelValue::as_cel_value(#value_ident) }
                } else {
                    quote! { ::protovalidate_buffa::cel::to_cel_value(#value_ident) }
                };
                let method = if for_key {
                    format_ident!("eval_map_keys_cel")
                } else {
                    format_ident!("eval_map_values_cel")
                };
                let kt = key_ty_ident.clone();
                let vt = val_ty_ident.clone();
                let ks = key_subscript.clone();
                out.push(quote! {
                    {
                        static __MAP_CEL: ::protovalidate_buffa::cel::CelConstraint =
                            ::protovalidate_buffa::cel::CelConstraint::new(#id, #msg, #expr);
                        for (key, value) in self.#accessor.iter() {
                            let fp = ::protovalidate_buffa::FieldPath {
                                elements: ::std::vec![::protovalidate_buffa::FieldPathElement {
                                    field_number: Some(#field_number),
                                    field_name: Some(::std::borrow::Cow::Borrowed(#name_lit)),
                                    field_type: Some(::protovalidate_buffa::FieldType::Message),
                                    key_type: Some(::protovalidate_buffa::FieldType::#kt),
                                    value_type: Some(::protovalidate_buffa::FieldType::#vt),
                                    subscript: Some(#ks),
                                }],
                            };
                            if let Err(v) = __MAP_CEL.#method(#as_value, fp, #idx_lit) {
                                violations.push(v);
                            }
                        }
                    }
                });
            }
        };
    if let Some(k) = spec.keys.as_deref() {
        if !matches!(k.ignore, crate::scan::Ignore::Always) && !k.cel.is_empty() {
            emit_map_cel(&mut out, &k.cel, true);
        }
    }
    if let Some(v) = spec.values.as_deref() {
        if !matches!(v.ignore, crate::scan::Ignore::Always) && !v.cel.is_empty() {
            emit_map_cel(&mut out, &v.cel, false);
        }
    }

    // Recurse into message-typed map values so nested validators fire.
    if let FieldKind::Message { full_name } = value_kind {
        if !full_name.starts_with("google.protobuf.") {
            let key_subscript_opt =
                kind_variant_to_subscript(crate::emit::field::kind_to_field_type(key_kind));
            if let Some(key_subscript) = key_subscript_opt {
                let kt = format_ident!("{}", crate::emit::field::kind_to_field_type(key_kind));
                let vt = format_ident!("{}", crate::emit::field::kind_to_field_type(value_kind));
                out.push(quote! {
                    for (key, value) in self.#accessor.iter() {
                        if let Err(sub) = value.validate() {
                            violations.extend(sub.violations.into_iter().map(|mut v| {
                                v.field.elements.insert(0, ::protovalidate_buffa::FieldPathElement {
                                    field_number: Some(#field_number),
                                    field_name: Some(::std::borrow::Cow::Borrowed(#name_lit)),
                                    field_type: Some(::protovalidate_buffa::FieldType::Message),
                                    key_type: Some(::protovalidate_buffa::FieldType::#kt),
                                    value_type: Some(::protovalidate_buffa::FieldType::#vt),
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

    Ok(quote! { #( #out )* })
}

// ─── scalar per-element checks ────────────────────────────────────────────────

/// Emit per-element rule checks bound to `elem_ident` (e.g. `elem`, `key`,
/// `value`). Dispatches on `kind` to produce the appropriate rule comparisons.
/// Only the types actually used in current proto annotations are implemented;
/// others can be added following the same pattern.
///
/// `for_key` controls the `for_key` field on emitted `Violation`s — pass
/// `true` when generating checks for a map's key side, `false` otherwise.
#[expect(
    clippy::too_many_lines,
    reason = "codegen helper — one branch per rule family; splitting hurts readability"
)]
fn emit_scalar_checks(
    elem_ident: &syn::Ident,
    kind: &FieldKind,
    rules: &crate::scan::StandardRules,
    field_name_lit: &str,
    for_key: bool,
) -> Vec<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    let for_key_bool = for_key;

    match kind {
        FieldKind::String => {
            if let Some(s) = &rules.string {
                if !s.in_set.is_empty() {
                    let set = &s.in_set;
                    out.push(quote! {
                        {
                            const ALLOWED: &[&str] = &[ #( #set ),* ];
                            if !ALLOWED.iter().any(|c| *c == #elem_ident.as_str()) {
                                violations.push(::protovalidate_buffa::Violation {
                                    field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                    rule: ::protovalidate_buffa::field_path!("string", "in"),
                                    rule_id: ::std::borrow::Cow::Borrowed("string.in"),
                                    message: ::std::borrow::Cow::Borrowed("value not in allowed set"),
                                    for_key: #for_key_bool,
                                });
                            }
                        }
                    });
                }
                if !s.not_in_set.is_empty() {
                    let set = &s.not_in_set;
                    out.push(quote! {
                        {
                            const DISALLOWED: &[&str] = &[ #( #set ),* ];
                            if DISALLOWED.iter().any(|c| *c == #elem_ident.as_str()) {
                                violations.push(::protovalidate_buffa::Violation {
                                    field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                    rule: ::protovalidate_buffa::field_path!("string", "not_in"),
                                    rule_id: ::std::borrow::Cow::Borrowed("string.not_in"),
                                    message: ::std::borrow::Cow::Borrowed("value in disallowed set"),
                                    for_key: #for_key_bool,
                                });
                            }
                        }
                    });
                }
                if let Some(c) = &s.r#const {
                    out.push(quote! {
                        if #elem_ident != #c {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                rule: ::protovalidate_buffa::field_path!("string", "const"),
                                rule_id: ::std::borrow::Cow::Borrowed("string.const"),
                                message: ::std::borrow::Cow::Borrowed("value must equal const"),
                                for_key: #for_key_bool,
                            });
                        }
                    });
                }
                if let Some(n) = s.min_len {
                    let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
                    out.push(quote! {
                        if #elem_ident.len() < #n_usize {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                rule: ::protovalidate_buffa::field_path!("string", "min_len"),
                                rule_id: ::std::borrow::Cow::Borrowed("string.min_len"),
                                message: ::std::borrow::Cow::Owned(::std::format!(
                                    "value length must be at least {} bytes (got {})",
                                    #n_usize, #elem_ident.len()
                                )),
                                for_key: #for_key_bool,
                            });
                        }
                    });
                }
                if let Some(n) = s.max_len {
                    let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
                    out.push(quote! {
                        if #elem_ident.len() > #n_usize {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                rule: ::protovalidate_buffa::field_path!("string", "max_len"),
                                rule_id: ::std::borrow::Cow::Borrowed("string.max_len"),
                                message: ::std::borrow::Cow::Owned(::std::format!(
                                    "value length must be at most {} bytes (got {})",
                                    #n_usize, #elem_ident.len()
                                )),
                                for_key: #for_key_bool,
                            });
                        }
                    });
                }
                if let Some(pat) = &s.pattern {
                    let pat_str = pat.as_str();
                    let field_upper = field_name_lit
                        .to_uppercase()
                        .replace(|c: char| !c.is_alphanumeric(), "_");
                    let elem_upper = elem_ident.to_string().to_uppercase();
                    let cache_ident = format_ident!("RE_{}_{}", field_upper, elem_upper);
                    out.push(quote! {
                        {
                            static #cache_ident: ::std::sync::OnceLock<::regex::Regex> =
                                ::std::sync::OnceLock::new();
                            let re = #cache_ident.get_or_init(|| {
                                ::regex::Regex::new(#pat_str)
                                    .expect("pattern regex compiled at code-gen time")
                            });
                            if !re.is_match(#elem_ident) {
                                violations.push(::protovalidate_buffa::Violation {
                                    field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                    rule: ::protovalidate_buffa::field_path!("string", "pattern"),
                                    rule_id: ::std::borrow::Cow::Borrowed("string.pattern"),
                                    message: ::std::borrow::Cow::Owned(::std::format!(
                                        "value must match pattern /{}/", #pat_str
                                    )),
                                    for_key: #for_key_bool,
                                });
                            }
                        }
                    });
                }
            }
        }
        FieldKind::Bytes => {
            if let Some(b) = &rules.bytes {
                if let Some(n) = b.min_len {
                    let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
                    out.push(quote! {
                        if #elem_ident.len() < #n_usize {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                rule: ::protovalidate_buffa::field_path!("bytes", "min_len"),
                                rule_id: ::std::borrow::Cow::Borrowed("bytes.min_len"),
                                message: ::std::borrow::Cow::Owned(::std::format!(
                                    "value length must be at least {} bytes (got {})",
                                    #n_usize, #elem_ident.len()
                                )),
                                for_key: #for_key_bool,
                            });
                        }
                    });
                }
                if let Some(n) = b.max_len {
                    let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
                    out.push(quote! {
                        if #elem_ident.len() > #n_usize {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                rule: ::protovalidate_buffa::field_path!("bytes", "max_len"),
                                rule_id: ::std::borrow::Cow::Borrowed("bytes.max_len"),
                                message: ::std::borrow::Cow::Owned(::std::format!(
                                    "value length must be at most {} bytes (got {})",
                                    #n_usize, #elem_ident.len()
                                )),
                                for_key: #for_key_bool,
                            });
                        }
                    });
                }
            }
        }
        FieldKind::Float => {
            if let Some(f) = &rules.float {
                if let Some(lower) = f.gt {
                    out.push(quote! {
                        if !(*#elem_ident > #lower) {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                rule: ::protovalidate_buffa::field_path!("float", "gt"),
                                rule_id: ::std::borrow::Cow::Borrowed("float.gt"),
                                message: ::std::borrow::Cow::Borrowed(""),
                                for_key: #for_key_bool,
                            });
                        }
                    });
                }
                if let Some(lower) = f.gte {
                    out.push(quote! {
                        if !(*#elem_ident >= #lower) {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                rule: ::protovalidate_buffa::field_path!("float", "gte"),
                                rule_id: ::std::borrow::Cow::Borrowed("float.gte"),
                                message: ::std::borrow::Cow::Borrowed(""),
                                for_key: #for_key_bool,
                            });
                        }
                    });
                }
                if let Some(upper) = f.lt {
                    out.push(quote! {
                        if !(*#elem_ident < #upper) {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                rule: ::protovalidate_buffa::field_path!("float", "lt"),
                                rule_id: ::std::borrow::Cow::Borrowed("float.lt"),
                                message: ::std::borrow::Cow::Borrowed(""),
                                for_key: #for_key_bool,
                            });
                        }
                    });
                }
                if let Some(upper) = f.lte {
                    out.push(quote! {
                        if !(*#elem_ident <= #upper) {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                rule: ::protovalidate_buffa::field_path!("float", "lte"),
                                rule_id: ::std::borrow::Cow::Borrowed("float.lte"),
                                message: ::std::borrow::Cow::Borrowed(""),
                                for_key: #for_key_bool,
                            });
                        }
                    });
                }
            }
        }
        FieldKind::Double => {
            if let Some(d) = &rules.double {
                if let Some(lower) = d.gt {
                    out.push(quote! {
                        if !(*#elem_ident > #lower) {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                rule: ::protovalidate_buffa::field_path!("double", "gt"),
                                rule_id: ::std::borrow::Cow::Borrowed("double.gt"),
                                message: ::std::borrow::Cow::Borrowed(""),
                                for_key: #for_key_bool,
                            });
                        }
                    });
                }
                if let Some(lower) = d.gte {
                    out.push(quote! {
                        if !(*#elem_ident >= #lower) {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                rule: ::protovalidate_buffa::field_path!("double", "gte"),
                                rule_id: ::std::borrow::Cow::Borrowed("double.gte"),
                                message: ::std::borrow::Cow::Borrowed(""),
                                for_key: #for_key_bool,
                            });
                        }
                    });
                }
            }
        }
        FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32 => {
            if let Some(n) = &rules.int32 {
                if let Some(lower) = n.gt {
                    out.push(quote! {
                        if *#elem_ident <= #lower {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                rule: ::protovalidate_buffa::field_path!("int32", "gt"),
                                rule_id: ::std::borrow::Cow::Borrowed("int32.gt"),
                                message: ::std::borrow::Cow::Owned(::std::format!(
                                    "value must be > {} (got {})", #lower, #elem_ident
                                )),
                                for_key: #for_key_bool,
                            });
                        }
                    });
                }
                if let Some(lower) = n.gte {
                    out.push(quote! {
                        if *#elem_ident < #lower {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                rule: ::protovalidate_buffa::field_path!("int32", "gte"),
                                rule_id: ::std::borrow::Cow::Borrowed("int32.gte"),
                                message: ::std::borrow::Cow::Owned(::std::format!(
                                    "value must be >= {} (got {})", #lower, #elem_ident
                                )),
                                for_key: #for_key_bool,
                            });
                        }
                    });
                }
                if let Some(upper) = n.lt {
                    out.push(quote! {
                        if *#elem_ident >= #upper {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                rule: ::protovalidate_buffa::field_path!("int32", "lt"),
                                rule_id: ::std::borrow::Cow::Borrowed("int32.lt"),
                                message: ::std::borrow::Cow::Owned(::std::format!(
                                    "value must be < {} (got {})", #upper, #elem_ident
                                )),
                                for_key: #for_key_bool,
                            });
                        }
                    });
                }
                if let Some(upper) = n.lte {
                    out.push(quote! {
                        if *#elem_ident > #upper {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                rule: ::protovalidate_buffa::field_path!("int32", "lte"),
                                rule_id: ::std::borrow::Cow::Borrowed("int32.lte"),
                                message: ::std::borrow::Cow::Owned(::std::format!(
                                    "value must be <= {} (got {})", #upper, #elem_ident
                                )),
                                for_key: #for_key_bool,
                            });
                        }
                    });
                }
            }
        }
        FieldKind::Uint32 | FieldKind::Fixed32 => {
            if let Some(n) = &rules.uint32 {
                if let Some(lower) = n.gt {
                    out.push(quote! {
                        if *#elem_ident <= #lower {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                rule: ::protovalidate_buffa::field_path!("uint32", "gt"),
                                rule_id: ::std::borrow::Cow::Borrowed("uint32.gt"),
                                message: ::std::borrow::Cow::Owned(::std::format!(
                                    "value must be > {} (got {})", #lower, #elem_ident
                                )),
                                for_key: #for_key_bool,
                            });
                        }
                    });
                }
                if let Some(lower) = n.gte {
                    out.push(quote! {
                        if *#elem_ident < #lower {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::field_path!(#field_name_lit),
                                rule: ::protovalidate_buffa::field_path!("uint32", "gte"),
                                rule_id: ::std::borrow::Cow::Borrowed("uint32.gte"),
                                message: ::std::borrow::Cow::Owned(::std::format!(
                                    "value must be >= {} (got {})", #lower, #elem_ident
                                )),
                                for_key: #for_key_bool,
                            });
                        }
                    });
                }
            }
        }
        // Additional kinds follow the same pattern. Only those with annotations
        // in current protos are needed now.
        _ => {}
    }

    out
}
