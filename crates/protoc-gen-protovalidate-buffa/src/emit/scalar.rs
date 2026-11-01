//! One implementation per scalar rule family. Callers bind the value and
//! supply its violation location; field positions never select a rule subset.

use super::rule_site::RuleSite;
use crate::scan::{
    BoolStandard, BytesStandard, DoubleStandard, EnumStandard, FieldKind, FloatStandard,
    Int32Standard, Int64Standard, StringStandard, Uint32Standard, Uint64Standard,
};
use anyhow::Result;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

const STR_OUTER: i32 = 14;

// https://github.com/mathematic-inc/protovalidate-buffa/discussions/83
// All presence forms share the same checks, borrowing their value as &str.
fn emit_string_value(value: &TokenStream, site: &RuleSite, s: &StringStandard) -> Vec<TokenStream> {
    let for_key = site.for_key();
    let value_str = quote! { ::core::convert::AsRef::<str>::as_ref(&(#value)) };
    let mut out: Vec<TokenStream> = Vec::new();

    if let Some(n) = s.min_len {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        let field = site.field_path();
        let rule = site.rule("string", STR_OUTER, "min_len", 2, "Uint64");
        out.push(quote! {
            if (#value_str).chars().count() < #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.min_len"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value length must be at least {} characters", #n_usize
                    )),
                    for_key: #for_key,
                });
            }
        });
    }

    if let Some(n) = s.max_len {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        let field = site.field_path();
        let rule = site.rule("string", STR_OUTER, "max_len", 3, "Uint64");
        out.push(quote! {
            if (#value_str).chars().count() > #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.max_len"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value length must be at most {} characters", #n_usize
                    )),
                    for_key: #for_key,
                });
            }
        });
    }

    if let Some(pat) = &s.pattern {
        let pat_str = pat.as_str();
        let cache_ident = format_ident!("RE_PATTERN");
        let field = site.field_path();
        let rule = site.rule("string", STR_OUTER, "pattern", 6, "String");
        out.push(quote! {
            {
                static #cache_ident: ::std::sync::OnceLock<::protovalidate_buffa::regex::Regex> =
                    ::std::sync::OnceLock::new();
                let re = #cache_ident.get_or_init(|| {
                    ::protovalidate_buffa::regex::Regex::new(#pat_str)
                        .expect("pattern regex compiled at code-gen time")
                });
                if !re.is_match(#value_str) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("string.pattern"),
                        message: ::std::borrow::Cow::Owned(::std::format!(
                            "value must match pattern /{}/", #pat_str
                        )),
                        for_key: #for_key,
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
            let field = site.field_path();
            let rule = site.rule("string", STR_OUTER, inner_name, inner_num, "Bool");
            let rid = rule_id.to_string();
            let m = msg.to_string();
            out.push(quote! {
                if !#fn_path(#value_str) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed(#rid),
                        message: ::std::borrow::Cow::Borrowed(#m),
                        for_key: #for_key,
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
        let field = site.field_path();
        let field2 = site.field_path();
        let rule = site.rule("string", STR_OUTER, inner_name, inner_num, "Bool");
        let rule2 = site.rule("string", STR_OUTER, inner_name, inner_num, "Bool");
        let id_empty = format!("{base_id}_empty");
        let id_base = base_id.to_string();
        out.push(quote! {
            if (#value_str).is_empty() {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#id_empty),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must satisfy {}", #id_empty)),
                    for_key: #for_key,
                });
            } else if !#fn_path(#value_str) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field2, rule: #rule2,
                    rule_id: ::std::borrow::Cow::Borrowed(#id_base),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must satisfy {}", #id_base)),
                    for_key: #for_key,
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
        let field_a = site.field_path();
        let field_b = site.field_path();
        let rule_a = site.rule("string", STR_OUTER, "well_known_regex", 24, "Enum");
        let rule_b = site.rule("string", STR_OUTER, "well_known_regex", 24, "Enum");
        // Only header_name has a distinct empty-rule_id (empty is invalid).
        // header_value allows empty strings.
        let (fn_path, rule_id, empty_rule_id): (TokenStream, &str, Option<&str>) = match wkr {
            1 => (
                quote! { |v: &str| ::protovalidate_buffa::rules::string::is_header_name(v, #strict) },
                "string.well_known_regex.header_name",
                Some("string.well_known_regex.header_name_empty"),
            ),
            2 => (
                quote! { |v: &str| ::protovalidate_buffa::rules::string::is_header_value(v, #strict) },
                "string.well_known_regex.header_value",
                None,
            ),
            _ => (quote! { |_v: &str| true }, "string.well_known_regex", None),
        };
        let rid = rule_id.to_string();
        if let Some(re) = empty_rule_id {
            let rid_empty = re.to_string();
            out.push(quote! {
                if (#value_str).is_empty() {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field_a, rule: #rule_a,
                        rule_id: ::std::borrow::Cow::Borrowed(#rid_empty),
                        message: ::std::borrow::Cow::Owned(::std::format!("value must satisfy {}", #rid_empty)),
                        for_key: #for_key,
                    });
                } else if !(#fn_path)(#value_str) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field_b, rule: #rule_b,
                        rule_id: ::std::borrow::Cow::Borrowed(#rid),
                        message: ::std::borrow::Cow::Owned(::std::format!("value must satisfy {}", #rid)),
                        for_key: #for_key,
                    });
                }
            });
        } else {
            let _ = field_a;
            let _ = rule_a;
            out.push(quote! {
                if !(#value_str).is_empty()
                    && !(#fn_path)(#value_str)
                {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field_b, rule: #rule_b,
                        rule_id: ::std::borrow::Cow::Borrowed(#rid),
                        message: ::std::borrow::Cow::Owned(::std::format!("value must satisfy {}", #rid)),
                        for_key: #for_key,
                    });
                }
            });
        }
    }

    if !s.in_set.is_empty() {
        let set = &s.in_set;
        let field = site.field_path();
        let rule = site.rule("string", STR_OUTER, "in", 10, "String");
        out.push(quote! {
            {
                const ALLOWED: &[&str] = &[ #( #set ),* ];
                if !ALLOWED.iter().any(|candidate| *candidate == #value_str) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("string.in"),
                        message: ::std::borrow::Cow::Owned(::std::format!(
                            "value must be one of [{}]", ALLOWED.join(", ")
                        )),
                        for_key: #for_key,
                    });
                }
            }
        });
    }

    if !s.not_in_set.is_empty() {
        let set = &s.not_in_set;
        let field = site.field_path();
        let rule = site.rule("string", STR_OUTER, "not_in", 11, "String");
        out.push(quote! {
            {
                const DISALLOWED: &[&str] = &[ #( #set ),* ];
                if DISALLOWED.iter().any(|candidate| *candidate == #value_str) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("string.not_in"),
                        message: ::std::borrow::Cow::Owned(::std::format!(
                            "value must not be one of [{}]", DISALLOWED.join(", ")
                        )),
                        for_key: #for_key,
                    });
                }
            }
        });
    }

    if let Some(prefix) = &s.prefix {
        let field = site.field_path();
        let rule = site.rule("string", STR_OUTER, "prefix", 7, "String");
        out.push(quote! {
            if !(#value_str).starts_with(#prefix) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.prefix"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must have prefix {:?}", #prefix
                    )),
                    for_key: #for_key,
                });
            }
        });
    }

    if let Some(suffix) = &s.suffix {
        let field = site.field_path();
        let rule = site.rule("string", STR_OUTER, "suffix", 8, "String");
        out.push(quote! {
            if !(#value_str).ends_with(#suffix) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.suffix"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must have suffix {:?}", #suffix
                    )),
                    for_key: #for_key,
                });
            }
        });
    }

    if let Some(contains) = &s.contains {
        let field = site.field_path();
        let rule = site.rule("string", STR_OUTER, "contains", 9, "String");
        out.push(quote! {
            if !(#value_str).contains(#contains) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.contains"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must contain {:?}", #contains
                    )),
                    for_key: #for_key,
                });
            }
        });
    }

    if let Some(not_contains) = &s.not_contains {
        let field = site.field_path();
        let rule = site.rule("string", STR_OUTER, "not_contains", 23, "String");
        out.push(quote! {
            if (#value_str).contains(#not_contains) {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.not_contains"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must not contain {:?}", #not_contains
                    )),
                    for_key: #for_key,
                });
            }
        });
    }

    if let Some(n) = s.len {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        let field = site.field_path();
        let rule = site.rule("string", STR_OUTER, "len", 19, "Uint64");
        out.push(quote! {
            if (#value_str).chars().count() != #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.len"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value length must be {} characters", #n_usize
                    )),
                    for_key: #for_key,
                });
            }
        });
    }

    if let Some(n) = s.min_bytes {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        let field = site.field_path();
        let rule = site.rule("string", STR_OUTER, "min_bytes", 4, "Uint64");
        out.push(quote! {
            if (#value_str).len() < #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.min_bytes"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must be at least {} bytes", #n_usize
                    )),
                    for_key: #for_key,
                });
            }
        });
    }

    if let Some(n) = s.max_bytes {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        let field = site.field_path();
        let rule = site.rule("string", STR_OUTER, "max_bytes", 5, "Uint64");
        out.push(quote! {
            if (#value_str).len() > #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.max_bytes"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must be at most {} bytes", #n_usize
                    )),
                    for_key: #for_key,
                });
            }
        });
    }

    if let Some(n) = s.len_bytes {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        let field = site.field_path();
        let rule = site.rule("string", STR_OUTER, "len_bytes", 20, "Uint64");
        out.push(quote! {
            if (#value_str).len() != #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.len_bytes"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must be exactly {} bytes", #n_usize
                    )),
                    for_key: #for_key,
                });
            }
        });
    }

    if let Some(r#const) = &s.r#const {
        let field = site.field_path();
        let rule = site.rule("string", STR_OUTER, "const", 1, "String");
        out.push(quote! {
            if (#value_str) != #r#const {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("string.const"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must equal {:?}", #r#const
                    )),
                    for_key: #for_key,
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

fn emit_bytes_value(value: &TokenStream, site: &RuleSite, b: &BytesStandard) -> Vec<TokenStream> {
    let for_key = site.for_key();
    let mut out: Vec<TokenStream> = Vec::new();
    let value_len = quote! { #value.len() };
    let value_slice = quote! { ::core::convert::AsRef::<[u8]>::as_ref(&(#value)) };

    // bytes.ip = 4 or 16 bytes; bytes.ipv4 = 4 bytes; bytes.ipv6 = 16 bytes.
    if b.ip == Some(true) {
        let field = site.field_path();
        let rule = site.rule("bytes", BYTES_OUTER, "ip", 10, "Bool");
        out.push(quote! {
            if #value_len != 4 && #value_len != 16 {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("bytes.ip"),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must satisfy {}", "bytes.ip")),
                    for_key: #for_key,
                });
            }
        });
    }
    if b.ipv4 == Some(true) {
        let field = site.field_path();
        let rule = site.rule("bytes", BYTES_OUTER, "ipv4", 11, "Bool");
        out.push(quote! {
            if #value_len != 4 {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("bytes.ipv4"),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must satisfy {}", "bytes.ipv4")),
                    for_key: #for_key,
                });
            }
        });
    }
    if b.ipv6 == Some(true) {
        let field = site.field_path();
        let rule = site.rule("bytes", BYTES_OUTER, "ipv6", 12, "Bool");
        out.push(quote! {
            if #value_len != 16 {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("bytes.ipv6"),
                    message: ::std::borrow::Cow::Owned(::std::format!("value must satisfy {}", "bytes.ipv6")),
                    for_key: #for_key,
                });
            }
        });
    }
    // bytes.uuid expects raw 16 bytes, not a hex string.
    if b.uuid == Some(true) {
        let field = site.field_path();
        let rule = site.rule("bytes", BYTES_OUTER, "uuid", 15, "Bool");
        out.push(quote! {
            {
                // Empty is a special-cased _empty rule.
                if #value_slice.is_empty() {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field.clone(), rule: #rule.clone(),
                        rule_id: ::std::borrow::Cow::Borrowed("bytes.uuid_empty"),
                        message: ::std::borrow::Cow::Owned(::std::format!("value must satisfy {}", "bytes.uuid_empty")),
                        for_key: #for_key,
                    });
                } else if #value_len != 16 {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("bytes.uuid"),
                        message: ::std::borrow::Cow::Owned(::std::format!("value must satisfy {}", "bytes.uuid")),
                        for_key: #for_key,
                    });
                }
            }
        });
    }

    if let Some(c) = &b.r#const {
        let set: Vec<u8> = c.clone();
        let field = site.field_path();
        let rule = site.rule("bytes", BYTES_OUTER, "const", 1, "Bytes");
        out.push(quote! {
            {
                const EXPECTED: &[u8] = &[ #( #set ),* ];
                if #value_slice != EXPECTED {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("bytes.const"),
                        message: ::std::borrow::Cow::Borrowed("value does not match expected bytes"),
                        for_key: #for_key,
                    });
                }
            }
        });
    }

    if let Some(n) = b.min_len {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        let field = site.field_path();
        let rule = site.rule("bytes", BYTES_OUTER, "min_len", 2, "Uint64");
        out.push(quote! {
            if #value_len < #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("bytes.min_len"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value length must be at least {} bytes (got {})",
                        #n_usize, #value_len
                    )),
                    for_key: #for_key,
                });
            }
        });
    }

    if let Some(n) = b.len {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        let field = site.field_path();
        let rule = site.rule("bytes", BYTES_OUTER, "len", 13, "Uint64");
        out.push(quote! {
            if #value_len != #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("bytes.len"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must be exactly {} bytes (got {})",
                        #n_usize, #value_len
                    )),
                    for_key: #for_key,
                });
            }
        });
    }

    if let Some(n) = b.max_len {
        let n_usize = usize::try_from(n).expect("proto length bound fits in usize");
        let field = site.field_path();
        let rule = site.rule("bytes", BYTES_OUTER, "max_len", 3, "Uint64");
        out.push(quote! {
            if #value_len > #n_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("bytes.max_len"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value length must be at most {} bytes (got {})",
                        #n_usize, #value_len
                    )),
                    for_key: #for_key,
                });
            }
        });
    }

    if let Some(pat) = &b.pattern {
        let pat_str = pat.as_str();
        let cache_ident = format_ident!("RE_BYTES_PATTERN");
        let field = site.field_path();
        let rule = site.rule("bytes", BYTES_OUTER, "pattern", 4, "String");
        out.push(quote! {
            {
                static #cache_ident: ::std::sync::OnceLock<::protovalidate_buffa::regex::Regex> =
                    ::std::sync::OnceLock::new();
                let re = #cache_ident.get_or_init(|| {
                    ::protovalidate_buffa::regex::Regex::new(#pat_str)
                        .expect("pattern regex compiled at code-gen time")
                });
                match ::std::str::from_utf8(#value_slice) {
                    Ok(s) => {
                        if !re.is_match(s) {
                            violations.push(::protovalidate_buffa::Violation {
                                field: #field, rule: #rule,
                                rule_id: ::std::borrow::Cow::Borrowed("bytes.pattern"),
                                message: ::std::borrow::Cow::Owned(::std::format!(
                                    "value must match pattern /{}/", #pat_str
                                )),
                                for_key: #for_key,
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
        let field = site.field_path();
        let rule = site.rule("bytes", BYTES_OUTER, "prefix", 5, "Bytes");
        out.push(quote! {
            {
                const PREFIX: &[u8] = &[ #( #p ),* ];
                if !#value_slice.starts_with(PREFIX) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("bytes.prefix"),
                        message: ::std::borrow::Cow::Borrowed("value does not have required prefix"),
                        for_key: #for_key,
                    });
                }
            }
        });
    }

    if let Some(suffix) = &b.suffix {
        let p: Vec<u8> = suffix.clone();
        let field = site.field_path();
        let rule = site.rule("bytes", BYTES_OUTER, "suffix", 6, "Bytes");
        out.push(quote! {
            {
                const SUFFIX: &[u8] = &[ #( #p ),* ];
                if !#value_slice.ends_with(SUFFIX) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("bytes.suffix"),
                        message: ::std::borrow::Cow::Borrowed("value does not have required suffix"),
                        for_key: #for_key,
                    });
                }
            }
        });
    }

    if let Some(contains) = &b.contains {
        let p: Vec<u8> = contains.clone();
        let field = site.field_path();
        let rule = site.rule("bytes", BYTES_OUTER, "contains", 7, "Bytes");
        out.push(quote! {
            {
                const NEEDLE: &[u8] = &[ #( #p ),* ];
                if !#value_slice.windows(NEEDLE.len()).any(|w| w == NEEDLE) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("bytes.contains"),
                        message: ::std::borrow::Cow::Borrowed("value does not contain required bytes"),
                        for_key: #for_key,
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
        let field = site.field_path();
        let rule = site.rule("bytes", BYTES_OUTER, "in", 8, "Bytes");
        out.push(quote! {
            {
                let allowed: &[&[u8]] = &[ #( #bytes_lits ),* ];
                if !allowed.iter().any(|a| *a == #value_slice) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("bytes.in"),
                        message: ::std::borrow::Cow::Borrowed("value not in allowed set"),
                        for_key: #for_key,
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
        let field = site.field_path();
        let rule = site.rule("bytes", BYTES_OUTER, "not_in", 9, "Bytes");
        out.push(quote! {
            {
                let disallowed: &[&[u8]] = &[ #( #bytes_lits ),* ];
                if disallowed.iter().any(|a| *a == #value_slice) {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("bytes.not_in"),
                        message: ::std::borrow::Cow::Borrowed("value is in forbidden set"),
                        for_key: #for_key,
                    });
                }
            }
        });
    }

    out
}

// ===== Numeric rules =====

const FLOAT_FAM: NumFamily = NumFamily {
    family: "float",
    outer_number: 1,
    scalar_ty: "Float",
};
const DOUBLE_FAM: NumFamily = NumFamily {
    family: "double",
    outer_number: 2,
    scalar_ty: "Double",
};
const INNER_FINITE: i32 = 8;

struct NumberRules {
    constant: Option<TokenStream>,
    /// Bound names and descriptor numbers distinguish inclusive endpoints.
    lower: Option<(&'static str, i32, TokenStream)>,
    upper: Option<(&'static str, i32, TokenStream)>,
    reversed: bool,
    allowed: Vec<TokenStream>,
    denied: Vec<TokenStream>,
    finite: bool,
}

// The scanner retains typed rule structs; only this adapter differs by width.
macro_rules! numeric_emitter {
    ($name:ident, $rules:ty, $literal:expr $(, $finite:ident)?) => {
        fn $name(
            value: &TokenStream,
            site: &RuleSite,
            family: NumFamily,
            rules: &$rules,
        ) -> Vec<TokenStream> {
            // Normalize before the shared emitter to avoid monomorphizing codegen.
            let literal = $literal;
            emit_number(value, site, family, &NumberRules {
                constant: rules.r#const.map(literal),
                lower: rules.gt.map(|v| ("gt", INNER_GT, literal(v)))
                    .or_else(|| rules.gte.map(|v| ("gte", INNER_GTE, literal(v)))),
                upper: rules.lt.map(|v| ("lt", INNER_LT, literal(v)))
                    .or_else(|| rules.lte.map(|v| ("lte", INNER_LTE, literal(v)))),
                reversed: rules.gt.or(rules.gte).zip(rules.lt.or(rules.lte))
                    .is_some_and(|(lower, upper)| upper < lower),
                allowed: rules.in_set.iter().copied().map(literal).collect(),
                denied: rules.not_in.iter().copied().map(literal).collect(),
                finite: false $(|| rules.$finite)?,
            })
        }
    };
}

numeric_emitter!(emit_num_i32_like, Int32Standard, |v: i32| quote! { #v });
numeric_emitter!(emit_int64, Int64Standard, |v: i64| quote! { #v });
numeric_emitter!(emit_uint32, Uint32Standard, |v: u32| quote! { #v });
numeric_emitter!(emit_uint64, Uint64Standard, |v: u64| quote! { #v });
numeric_emitter!(
    emit_float,
    FloatStandard,
    |v: f32| {
        let bits = v.to_bits();
        quote! { ::core::primitive::f32::from_bits(#bits) }
    },
    finite
);
numeric_emitter!(
    emit_double,
    DoubleStandard,
    |v: f64| {
        let bits = v.to_bits();
        quote! { ::core::primitive::f64::from_bits(#bits) }
    },
    finite
);

fn emit_number(
    value: &TokenStream,
    site: &RuleSite,
    family: NumFamily,
    rules: &NumberRules,
) -> Vec<TokenStream> {
    let field = site.field_path();
    let for_key = site.for_key();
    let mut out = Vec::new();
    let mut push = |leaf: &str, number: i32, ty: &str, suffix: &str, condition: TokenStream| {
        let rule = site.rule(family.family, family.outer_number, leaf, number, ty);
        let id = format!("{}.{suffix}", family.family);
        let message = format!("value must satisfy {id}");
        out.push(quote! {
            #[allow(unused_comparisons, reason = "schema bounds may coincide with type limits")]
            if #condition {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#id),
                    message: ::std::borrow::Cow::Borrowed(#message),
                    for_key: #for_key,
                });
            }
        });
    };
    if let Some(expected) = &rules.constant {
        push(
            "const",
            INNER_CONST,
            family.scalar_ty,
            "const",
            quote! { (#value) != #expected },
        );
    }
    let lower = rules.lower.as_ref().map(|(name, number, v)| {
        let satisfied = if *name == "gt" {
            quote! { (#value) > #v }
        } else {
            quote! { (#value) >= #v }
        };
        (*name, *number, satisfied)
    });
    let upper = rules.upper.as_ref().map(|(name, number, v)| {
        let satisfied = if *name == "lt" {
            quote! { (#value) < #v }
        } else {
            quote! { (#value) <= #v }
        };
        (*name, *number, satisfied)
    });
    match (lower, upper) {
        (Some((lo_name, number, lo)), Some((hi_name, _, hi))) => {
            let (suffix, condition) = if rules.reversed {
                (
                    format!("{lo_name}_{hi_name}_exclusive"),
                    quote! { !(#lo || #hi) },
                )
            } else {
                (format!("{lo_name}_{hi_name}"), quote! { !(#lo && #hi) })
            };
            push(lo_name, number, family.scalar_ty, &suffix, condition);
        }
        (Some((name, number, satisfied)), None) | (None, Some((name, number, satisfied))) => {
            // Negating satisfaction also rejects NaN for every float bound.
            push(
                name,
                number,
                family.scalar_ty,
                name,
                quote! { !(#satisfied) },
            );
        }
        (None, None) => {}
    }
    if !rules.allowed.is_empty() {
        let allowed = &rules.allowed;
        push(
            "in",
            INNER_IN,
            family.scalar_ty,
            "in",
            quote! { ![#(#allowed),*].contains(&(#value)) },
        );
    }
    if !rules.denied.is_empty() {
        let denied = &rules.denied;
        push(
            "not_in",
            INNER_NOT_IN,
            family.scalar_ty,
            "not_in",
            quote! { [#(#denied),*].contains(&(#value)) },
        );
    }
    if rules.finite {
        push(
            "finite",
            INNER_FINITE,
            "Bool",
            "finite",
            quote! { !(#value).is_finite() },
        );
    }
    out
}

// ─── enum ────────────────────────────────────────────────────────────────────

fn emit_enum_value(
    value: &TokenStream,
    site: &RuleSite,
    e: &EnumStandard,
    full_name: &str,
) -> Result<Vec<TokenStream>> {
    emit_enum_checks(
        value,
        e,
        full_name,
        &site.field_path(),
        |inner, inner_num, ty| site.rule("enum", 16, inner, inner_num, ty),
    )
}

/// Apply enum rules to a numeric value with the caller's location metadata.
/// Scalar fields, repeated items, and map values share these rule semantics.
fn emit_enum_checks(
    value: &TokenStream,
    e: &EnumStandard,
    full_name: &str,
    field_path: &TokenStream,
    rule_path: impl Fn(&str, i32, &str) -> TokenStream,
) -> Result<Vec<TokenStream>> {
    // EnumRules outer field number = 16; inner: const=1 (TYPE_INT32),
    // defined_only=2 (TYPE_BOOL), in=3 (TYPE_INT32), not_in=4 (TYPE_INT32).
    let mut out: Vec<TokenStream> = Vec::new();

    if let Some(c) = e.r#const {
        let field = field_path;
        let rule = rule_path("const", 1, "Int32");
        out.push(quote! {
            {
                let raw_val: i32 = #value.to_i32();
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
        let field = field_path;
        let rule = rule_path("defined_only", 2, "Bool");
        out.push(quote! {
            {
                let raw_val: i32 = #value.to_i32();
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
        let field = field_path;
        let rule = rule_path("in", 3, "Int32");
        out.push(quote! {
            {
                const ALLOWED: &[i32] = &[ #( #set ),* ];
                let raw_val: i32 = #value.to_i32();
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
        let field = field_path;
        let rule = rule_path("not_in", 4, "Int32");
        out.push(quote! {
            {
                const DISALLOWED: &[i32] = &[ #( #set ),* ];
                let raw_val: i32 = #value.to_i32();
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

/// Metadata describing a numeric rule family (e.g. int32, sint32, ...).
/// Drives FieldPath/Rule path metadata emission.
#[derive(Clone, Copy)]
struct NumFamily {
    /// Rule family name used in `rule_id` (e.g. "int32").
    family: &'static str,
    /// FieldRules outer field number for this family (validate.proto).
    outer_number: i32,
    /// FieldType variant name for the element (e.g. "Int32", "Sint32").
    scalar_ty: &'static str,
}

const NUM_INT32: NumFamily = NumFamily {
    family: "int32",
    outer_number: 3,
    scalar_ty: "Int32",
};
const NUM_INT64: NumFamily = NumFamily {
    family: "int64",
    outer_number: 4,
    scalar_ty: "Int64",
};
const NUM_UINT32: NumFamily = NumFamily {
    family: "uint32",
    outer_number: 5,
    scalar_ty: "Uint32",
};
const NUM_UINT64: NumFamily = NumFamily {
    family: "uint64",
    outer_number: 6,
    scalar_ty: "Uint64",
};
const NUM_SINT32: NumFamily = NumFamily {
    family: "sint32",
    outer_number: 7,
    scalar_ty: "Sint32",
};
const NUM_SINT64: NumFamily = NumFamily {
    family: "sint64",
    outer_number: 8,
    scalar_ty: "Sint64",
};
const NUM_FIXED32: NumFamily = NumFamily {
    family: "fixed32",
    outer_number: 9,
    scalar_ty: "Fixed32",
};
const NUM_FIXED64: NumFamily = NumFamily {
    family: "fixed64",
    outer_number: 10,
    scalar_ty: "Fixed64",
};
const NUM_SFIXED32: NumFamily = NumFamily {
    family: "sfixed32",
    outer_number: 11,
    scalar_ty: "Sfixed32",
};
const NUM_SFIXED64: NumFamily = NumFamily {
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

fn emit_bool(value: &TokenStream, site: &RuleSite, b: &BoolStandard) -> Vec<TokenStream> {
    let for_key = site.for_key();
    let mut out: Vec<TokenStream> = Vec::new();
    if let Some(c) = b.r#const {
        let field_path = site.field_path();
        let rule_path = site.rule("bool", 13, "const", 1, "Bool");
        out.push(quote! {
            if #value != #c {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field_path,
                    rule: #rule_path,
                    rule_id: ::std::borrow::Cow::Borrowed("bool.const"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "value must equal {} (got {})", #c, #value
                    )),
                    for_key: #for_key,
                });
            }
        });
    }
    out
}

/// Apply the standard rules for a scalar `kind` to `value` at `site`.
///
/// `value` is the scalar itself for numeric and bool kinds, anything that
/// borrows as `str` or `[u8]` for string and bytes, and the enum value for
/// enums. Every position a scalar can take calls this, so a rule implemented
/// here applies to all of them.
pub(super) fn emit_scalar_rules(
    value: &TokenStream,
    kind: &FieldKind,
    std: &crate::scan::StandardRules,
    site: &RuleSite,
) -> Result<Vec<TokenStream>> {
    let checks = match kind {
        FieldKind::String => std
            .string
            .as_ref()
            .map(|s| emit_string_value(value, site, s)),
        FieldKind::Bytes => std.bytes.as_ref().map(|b| emit_bytes_value(value, site, b)),
        FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32 => std
            .int32
            .as_ref()
            .and_then(|n| num_family(kind).map(|fam| emit_num_i32_like(value, site, fam, n))),
        FieldKind::Int64 | FieldKind::Sint64 | FieldKind::Sfixed64 => std
            .int64
            .as_ref()
            .and_then(|n| num_family(kind).map(|fam| emit_int64(value, site, fam, n))),
        FieldKind::Uint32 | FieldKind::Fixed32 => std
            .uint32
            .as_ref()
            .and_then(|n| num_family(kind).map(|fam| emit_uint32(value, site, fam, n))),
        FieldKind::Uint64 | FieldKind::Fixed64 => std
            .uint64
            .as_ref()
            .and_then(|n| num_family(kind).map(|fam| emit_uint64(value, site, fam, n))),
        FieldKind::Float => std
            .float
            .as_ref()
            .map(|f| emit_float(value, site, FLOAT_FAM, f)),
        FieldKind::Double => std
            .double
            .as_ref()
            .map(|d| emit_double(value, site, DOUBLE_FAM, d)),
        FieldKind::Bool => std.bool_rules.as_ref().map(|b| emit_bool(value, site, b)),
        FieldKind::Enum { full_name } => std
            .enum_rules
            .as_ref()
            .map(|e| emit_enum_value(value, site, e, full_name))
            .transpose()?,
        FieldKind::Message { .. }
        | FieldKind::Repeated(_)
        | FieldKind::Map { .. }
        | FieldKind::Optional(_)
        | FieldKind::Wrapper(_) => None,
    };
    Ok(checks.unwrap_or_default())
}

const fn num_family(kind: &FieldKind) -> Option<NumFamily> {
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

/// Emit float rules for an explicitly bound value, retaining the legacy name-only field path.
///
/// # Examples
///
/// ```
/// use protoc_gen_protovalidate_buffa::{emit::field::emit_float_on_pub, scan::FloatStandard};
/// let checks = emit_float_on_pub(&syn::parse_str("value")?, "value", &FloatStandard::default());
/// assert!(checks.is_empty());
/// # Ok::<(), syn::Error>(())
/// ```
#[must_use]
pub fn emit_float_on_pub(
    val: &syn::Ident,
    name_lit: &str,
    rules: &FloatStandard,
) -> Vec<TokenStream> {
    emit_float(
        &quote! { #val },
        &RuleSite::legacy_field(name_lit),
        FLOAT_FAM,
        rules,
    )
}

/// Emit double rules for an explicitly bound value, retaining the legacy name-only field path.
///
/// # Examples
///
/// ```
/// use protoc_gen_protovalidate_buffa::{emit::field::emit_double_on_pub, scan::DoubleStandard};
/// let checks = emit_double_on_pub(&syn::parse_str("value")?, "value", &DoubleStandard::default());
/// assert!(checks.is_empty());
/// # Ok::<(), syn::Error>(())
/// ```
#[must_use]
pub fn emit_double_on_pub(
    val: &syn::Ident,
    name_lit: &str,
    rules: &DoubleStandard,
) -> Vec<TokenStream> {
    emit_double(
        &quote! { #val },
        &RuleSite::legacy_field(name_lit),
        DOUBLE_FAM,
        rules,
    )
}

/// Emit int32 rules for an explicitly bound value, retaining the legacy name-only field path.
///
/// # Examples
///
/// ```
/// use protoc_gen_protovalidate_buffa::{emit::field::emit_int32_on_pub, scan::Int32Standard};
/// let checks = emit_int32_on_pub(&syn::parse_str("value")?, "value", &Int32Standard::default());
/// assert!(checks.is_empty());
/// # Ok::<(), syn::Error>(())
/// ```
#[must_use]
pub fn emit_int32_on_pub(
    val: &syn::Ident,
    name_lit: &str,
    rules: &Int32Standard,
) -> Vec<TokenStream> {
    emit_num_i32_like(
        &quote! { #val },
        &RuleSite::legacy_field(name_lit),
        NUM_INT32,
        rules,
    )
}

/// Emit int64 rules for an explicitly bound value, retaining the legacy name-only field path.
///
/// # Examples
///
/// ```
/// use protoc_gen_protovalidate_buffa::{emit::field::emit_int64_on_pub, scan::Int64Standard};
/// let checks = emit_int64_on_pub(&syn::parse_str("value")?, "value", &Int64Standard::default());
/// assert!(checks.is_empty());
/// # Ok::<(), syn::Error>(())
/// ```
#[must_use]
pub fn emit_int64_on_pub(
    val: &syn::Ident,
    name_lit: &str,
    rules: &Int64Standard,
) -> Vec<TokenStream> {
    emit_int64(
        &quote! { #val },
        &RuleSite::legacy_field(name_lit),
        NUM_INT64,
        rules,
    )
}

/// Emit uint32 rules for an explicitly bound value, retaining the legacy name-only field path.
///
/// # Examples
///
/// ```
/// use protoc_gen_protovalidate_buffa::{emit::field::emit_uint32_on_pub, scan::Uint32Standard};
/// let checks = emit_uint32_on_pub(&syn::parse_str("value")?, "value", &Uint32Standard::default());
/// assert!(checks.is_empty());
/// # Ok::<(), syn::Error>(())
/// ```
#[must_use]
pub fn emit_uint32_on_pub(
    val: &syn::Ident,
    name_lit: &str,
    rules: &Uint32Standard,
) -> Vec<TokenStream> {
    emit_uint32(
        &quote! { #val },
        &RuleSite::legacy_field(name_lit),
        NUM_UINT32,
        rules,
    )
}

/// Emit uint64 rules for an explicitly bound value, retaining the legacy name-only field path.
///
/// # Examples
///
/// ```
/// use protoc_gen_protovalidate_buffa::{emit::field::emit_uint64_on_pub, scan::Uint64Standard};
/// let checks = emit_uint64_on_pub(&syn::parse_str("value")?, "value", &Uint64Standard::default());
/// assert!(checks.is_empty());
/// # Ok::<(), syn::Error>(())
/// ```
#[must_use]
pub fn emit_uint64_on_pub(
    val: &syn::Ident,
    name_lit: &str,
    rules: &Uint64Standard,
) -> Vec<TokenStream> {
    emit_uint64(
        &quote! { #val },
        &RuleSite::legacy_field(name_lit),
        NUM_UINT64,
        rules,
    )
}
