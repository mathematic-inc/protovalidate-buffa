//! Violation locations are independent of rule evaluation. Collection sites
//! bind `idx` or `key` in their enclosing loop; callers must preserve that scope.
use crate::scan::FieldKind;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum MapSide {
    Key,
    Value,
}

#[derive(Clone, Copy)]
pub(super) enum CelList {
    Rule,
    Expression,
}

/// Where a scalar's standard rules apply: the violation's field path, the
/// rule-path elements above the rule family, and `for_key`. Singular fields,
/// wrapper values, repeated items, and map keys and values differ only here,
/// so they share one emitter per rule family through the shared scalar emitter.
pub(super) struct RuleSite {
    /// Expression constructing the complete violation field path.
    field: TokenStream,
    /// FieldPathElement expressions preceding the rule family.
    rule_prefix: Vec<TokenStream>,
    for_key: bool,
}

// ===== impl RuleSite =====

impl RuleSite {
    pub(super) fn legacy_field(name: &str) -> Self {
        Self {
            field: quote! { ::protovalidate_buffa::field_path!(#name) },
            rule_prefix: Vec::new(),
            for_key: false,
        }
    }

    pub(super) const fn for_key(&self) -> bool {
        self.for_key
    }

    pub(super) fn cel_rule(&self, list: CelList, index: usize) -> TokenStream {
        let prefix = &self.rule_prefix;
        let index = index as u64;
        let leaf = match list {
            CelList::Rule => rule_path_element("cel", 23, "Message"),
            CelList::Expression => rule_path_element("cel_expression", 29, "String"),
        };
        quote! {
            ::protovalidate_buffa::FieldPath {
                elements: ::std::vec![#( #prefix, )* {
                    let mut element = #leaf;
                    element.subscript = Some(::protovalidate_buffa::Subscript::Index(#index));
                    element
                }],
            }
        }
    }

    /// A singular field. Wrapper fields pass `"Message"` as the type.
    pub(super) fn field(name: &str, number: i32, type_variant: &str) -> Self {
        Self {
            field: field_path_scalar(name, number, type_variant),
            rule_prefix: Vec::new(),
            for_key: false,
        }
    }

    /// The element of a repeated field at the enclosing loop's `idx`.
    pub(super) fn repeated_item(name: &str, number: i32, element_type_variant: &str) -> Self {
        let ety = format_ident!("{}", element_type_variant);
        Self {
            field: quote! {
                ::protovalidate_buffa::FieldPath {
                    elements: ::std::vec![
                        ::protovalidate_buffa::FieldPathElement {
                            field_number: Some(#number),
                            field_name: Some(::std::borrow::Cow::Borrowed(#name)),
                            field_type: Some(::protovalidate_buffa::FieldType::#ety),
                            key_type: None,
                            value_type: None,
                            subscript: Some(::protovalidate_buffa::Subscript::Index(idx as u64)),
                        },
                    ],
                }
            },
            rule_prefix: vec![
                rule_path_element("repeated", 18, "Message"),
                rule_path_element("items", 4, "Message"),
            ],
            for_key: false,
        }
    }

    /// The key (`for_key`) or value of the map entry at the enclosing loop's
    /// `key`, addressed by `key_subscript`.
    pub(super) fn map_entry(
        name: &str,
        number: i32,
        key_type_variant: &str,
        value_type_variant: &str,
        key_subscript: &TokenStream,
        map_side: MapSide,
    ) -> Self {
        let for_key = map_side == MapSide::Key;
        let kty = format_ident!("{}", key_type_variant);
        let vty = format_ident!("{}", value_type_variant);
        let side = if for_key {
            rule_path_element("keys", 4, "Message")
        } else {
            rule_path_element("values", 5, "Message")
        };
        Self {
            field: quote! {
                ::protovalidate_buffa::FieldPath {
                    elements: ::std::vec![
                        ::protovalidate_buffa::FieldPathElement {
                            field_number: Some(#number),
                            field_name: Some(::std::borrow::Cow::Borrowed(#name)),
                            field_type: Some(::protovalidate_buffa::FieldType::Message),
                            key_type: Some(::protovalidate_buffa::FieldType::#kty),
                            value_type: Some(::protovalidate_buffa::FieldType::#vty),
                            subscript: Some(#key_subscript),
                        },
                    ],
                }
            },
            rule_prefix: vec![rule_path_element("map", 19, "Message"), side],
            for_key,
        }
    }

    pub(super) fn field_path(&self) -> TokenStream {
        self.field.clone()
    }

    /// Rule path `<prefix>.<family>.<rule>`.
    pub(super) fn rule(
        &self,
        outer_name: &str,
        outer_number: i32,
        inner_name: &str,
        inner_number: i32,
        inner_type_variant: &str,
    ) -> TokenStream {
        let prefix = &self.rule_prefix;
        let outer = rule_path_element(outer_name, outer_number, "Message");
        let inner = rule_path_element(inner_name, inner_number, inner_type_variant);
        quote! {
            ::protovalidate_buffa::FieldPath {
                elements: ::std::vec![ #( #prefix, )* #outer, #inner ],
            }
        }
    }
}

fn rule_path_element(name: &str, number: i32, type_variant: &str) -> TokenStream {
    let ty = format_ident!("{}", type_variant);
    quote! {
        ::protovalidate_buffa::FieldPathElement {
            field_number: Some(#number),
            field_name: Some(::std::borrow::Cow::Borrowed(#name)),
            field_type: Some(::protovalidate_buffa::FieldType::#ty),
            key_type: None,
            value_type: None,
            subscript: None,
        }
    }
}

pub(super) fn field_path_scalar(name: &str, number: i32, type_variant: &str) -> TokenStream {
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

pub(super) fn kind_variant_to_subscript(kind_variant: &str) -> Option<TokenStream> {
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
        "String" => Some(quote! {
            ::protovalidate_buffa::Subscript::StringKey(::std::borrow::Cow::Owned(
                ::core::convert::AsRef::<str>::as_ref(key).to_owned()
            ))
        }),
        _ => None,
    }
}

pub(super) const fn kind_to_field_type(k: &FieldKind) -> &'static str {
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
