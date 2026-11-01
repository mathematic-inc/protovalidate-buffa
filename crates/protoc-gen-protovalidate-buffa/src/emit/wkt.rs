//! Well-known-type rules operate on present message references. The caller
//! owns presence, ignore policy, and iteration; all positions use these checks.
use super::rule_site::RuleSite;
use crate::scan::StandardRules;
use proc_macro2::TokenStream;
use quote::quote;

pub(super) fn emit(
    standard: &StandardRules,
    full_name: &str,
    value: &TokenStream,
    site: &RuleSite,
) -> Vec<TokenStream> {
    let mut out = Vec::new();
    let field_path = site.field_path();
    let for_key = site.for_key();
    if full_name == "google.protobuf.Any"
        && let Some(any) = &standard.any_rules
    {
        if !any.in_set.is_empty() {
            let set = &any.in_set;
            let field = &field_path;
            let rule = site.rule("any", 20, "in", 2, "String");
            out.push(quote! {
                {
                    const ALLOWED: &[&str] = &[ #( #set ),* ];
                    if !ALLOWED.iter().any(|s| *s == ::core::convert::AsRef::<str>::as_ref(&(#value).type_url)) {
                        violations.push(::protovalidate_buffa::Violation {
                            field: #field,
                            rule: #rule,
                            rule_id: ::std::borrow::Cow::Borrowed("any.in"),
                            message: ::std::borrow::Cow::Borrowed("value violates the configured well-known-type rule"),
                            for_key: #for_key,
                        });
                    }
                }
            });
        }
        if !any.not_in.is_empty() {
            let set = &any.not_in;
            let field = &field_path;
            let rule = site.rule("any", 20, "not_in", 3, "String");
            out.push(quote! {
                {
                    const DISALLOWED: &[&str] = &[ #( #set ),* ];
                    if DISALLOWED.iter().any(|s| *s == ::core::convert::AsRef::<str>::as_ref(&(#value).type_url)) {
                        violations.push(::protovalidate_buffa::Violation {
                            field: #field,
                            rule: #rule,
                            rule_id: ::std::borrow::Cow::Borrowed("any.not_in"),
                            message: ::std::borrow::Cow::Borrowed("value violates the configured well-known-type rule"),
                            for_key: #for_key,
                        });
                    }
                }
            });
        }
    }

    if full_name == "google.protobuf.FieldMask"
        && let Some(field_mask) = &standard.field_mask
    {
        if let Some(expected) = &field_mask.r#const {
            let expected_lits = expected.iter().map(String::as_str);
            let message = format!("must equal paths [{}]", expected.join(", "));
            let field = &field_path;
            let rule = site.rule("field_mask", 28, "const", 1, "Message");
            out.push(quote! {
                {
                    const EXPECTED: &[&str] = &[ #( #expected_lits ),* ];
                    let eq = (#value).paths.len() == EXPECTED.len()
                        && (#value).paths.iter().zip(EXPECTED.iter().copied()).all(
                            |(actual, expected)| {
                                ::core::convert::AsRef::<str>::as_ref(actual) == expected
                            },
                        );
                    if !eq {
                        violations.push(::protovalidate_buffa::Violation {
                            field: #field,
                            rule: #rule,
                            rule_id: ::std::borrow::Cow::Borrowed("field_mask.const"),
                            message: ::std::borrow::Cow::Borrowed(#message),
                            for_key: #for_key,
                        });
                    }
                }
            });
        }
        if !field_mask.in_set.is_empty() {
            let allowed = field_mask.in_set.iter().map(String::as_str);
            let field = &field_path;
            let rule = site.rule("field_mask", 28, "in", 2, "String");
            out.push(quote! {
                {
                    const ALLOWED: &[&str] = &[ #( #allowed ),* ];
                    let ok = (#value).paths.iter().all(|p| {
                        ALLOWED.iter().any(|c| ::protovalidate_buffa::rules::string::fieldmask_covers(c, ::core::convert::AsRef::<str>::as_ref(p)))
                    });
                    if !ok {
                        violations.push(::protovalidate_buffa::Violation {
                            field: #field,
                            rule: #rule,
                            rule_id: ::std::borrow::Cow::Borrowed("field_mask.in"),
                            message: ::std::borrow::Cow::Borrowed("value violates the configured well-known-type rule"),
                            for_key: #for_key,
                        });
                    }
                }
            });
        }
        if !field_mask.not_in.is_empty() {
            let denied = field_mask.not_in.iter().map(String::as_str);
            let field = &field_path;
            let rule = site.rule("field_mask", 28, "not_in", 3, "String");
            out.push(quote! {
                {
                    const DENIED: &[&str] = &[ #( #denied ),* ];
                    let bad = (#value).paths.iter().any(|p| {
                        let p = ::core::convert::AsRef::<str>::as_ref(p);
                        DENIED.iter().any(|c| ::protovalidate_buffa::rules::string::fieldmask_covers(c, p)
                            || ::protovalidate_buffa::rules::string::fieldmask_covers(p, c))
                    });
                    if bad {
                        violations.push(::protovalidate_buffa::Violation {
                            field: #field,
                            rule: #rule,
                            rule_id: ::std::borrow::Cow::Borrowed("field_mask.not_in"),
                            message: ::std::borrow::Cow::Borrowed("value violates the configured well-known-type rule"),
                            for_key: #for_key,
                        });
                    }
                }
            });
        }
    }

    if full_name == "google.protobuf.Duration"
        && let Some(d) = &standard.duration
    {
        out.extend(emit_time(
            &TimeRules {
                family: "duration",
                number: 21,
                constant: d.r#const,
                lower: d
                    .gt
                    .map(|v| (Bound::Exclusive, v))
                    .or_else(|| d.gte.map(|v| (Bound::Inclusive, v))),
                upper: d
                    .lt
                    .map(|v| (Bound::Exclusive, v))
                    .or_else(|| d.lte.map(|v| (Bound::Inclusive, v))),
                allowed: &d.in_set,
                denied: &d.not_in,
                before_now: false,
                after_now: false,
                within: None,
            },
            value,
            site,
        ));
    }
    if full_name == "google.protobuf.Timestamp"
        && let Some(t) = &standard.timestamp
    {
        out.extend(emit_time(
            &TimeRules {
                family: "timestamp",
                number: 22,
                constant: t.r#const,
                lower: t
                    .gt
                    .map(|v| (Bound::Exclusive, v))
                    .or_else(|| t.gte.map(|v| (Bound::Inclusive, v))),
                upper: t
                    .lt
                    .map(|v| (Bound::Exclusive, v))
                    .or_else(|| t.lte.map(|v| (Bound::Inclusive, v))),
                allowed: &[],
                denied: &[],
                before_now: t.lt_now,
                after_now: t.gt_now,
                within: t.within,
            },
            value,
            site,
        ));
    }
    out
}

#[derive(Clone, Copy)]
enum Bound {
    Exclusive,
    Inclusive,
}

struct TimeRules<'a> {
    /// Protobuf rule family name and field number.
    family: &'static str,
    number: i32,
    constant: Option<(i64, i32)>,
    /// Lower and upper bounds retain their endpoint inclusion semantics.
    lower: Option<(Bound, (i64, i32))>,
    upper: Option<(Bound, (i64, i32))>,
    allowed: &'a [(i64, i32)],
    denied: &'a [(i64, i32)],
    before_now: bool,
    after_now: bool,
    within: Option<(i64, i32)>,
}

fn nanos(value: (i64, i32)) -> i128 {
    i128::from(value.0) * 1_000_000_000 + i128::from(value.1)
}

fn emit_time(spec: &TimeRules<'_>, value: &TokenStream, site: &RuleSite) -> Vec<TokenStream> {
    let actual =
        quote! { (i128::from((#value).seconds) * 1_000_000_000 + i128::from((#value).nanos)) };
    let field = site.field_path();
    let for_key = site.for_key();
    let mut checks = Vec::new();
    let mut push = |leaf: &str, number: i32, ty: &str, suffix: &str, condition: TokenStream| {
        let rule = site.rule(spec.family, spec.number, leaf, number, ty);
        let id = format!("{}.{suffix}", spec.family);
        let message = format!("value must satisfy {id}");
        checks.push(quote! {
            if #condition {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed(#id),
                    message: ::std::borrow::Cow::Borrowed(#message), for_key: #for_key,
                });
            }
        });
    };
    if let Some(v) = spec.constant {
        let expected = nanos(v);
        push(
            "const",
            2,
            "Message",
            "const",
            quote! { #actual != #expected },
        );
    }
    let lower = spec.lower.map(|(bound, v)| {
        let v = nanos(v);
        match bound {
            Bound::Exclusive => ("gt", 5, v, quote! { #actual > #v }),
            Bound::Inclusive => ("gte", 6, v, quote! { #actual >= #v }),
        }
    });
    let upper = spec.upper.map(|(bound, v)| {
        let v = nanos(v);
        match bound {
            Bound::Exclusive => ("lt", 3, v, quote! { #actual < #v }),
            Bound::Inclusive => ("lte", 4, v, quote! { #actual <= #v }),
        }
    });
    match (lower, upper) {
        (Some((lo_name, lo_num, lo, lo_ok)), Some((hi_name, _, hi, hi_ok))) => {
            let (suffix, condition) = if hi < lo {
                (
                    format!("{lo_name}_{hi_name}_exclusive"),
                    quote! { !(#lo_ok || #hi_ok) },
                )
            } else {
                (
                    format!("{lo_name}_{hi_name}"),
                    quote! { !(#lo_ok && #hi_ok) },
                )
            };
            push(lo_name, lo_num, "Message", &suffix, condition);
        }
        (Some((name, number, _, ok)), None) | (None, Some((name, number, _, ok))) => {
            push(name, number, "Message", name, quote! { !(#ok) });
        }
        (None, None) => {}
    }
    if !spec.allowed.is_empty() {
        let allowed = spec.allowed.iter().copied().map(nanos);
        push(
            "in",
            7,
            "Message",
            "in",
            quote! { ![ #( #allowed ),* ].contains(&#actual) },
        );
    }
    if !spec.denied.is_empty() {
        let denied = spec.denied.iter().copied().map(nanos);
        push(
            "not_in",
            8,
            "Message",
            "not_in",
            quote! { [ #( #denied ),* ].contains(&#actual) },
        );
    }
    let now = quote! { ::std::time::SystemTime::now().duration_since(::std::time::UNIX_EPOCH).map_or_else(|e| -(e.duration().as_nanos() as i128), |d| d.as_nanos() as i128) };
    if spec.before_now {
        push("lt_now", 7, "Bool", "lt_now", quote! { #actual >= #now });
    }
    if spec.after_now {
        push("gt_now", 8, "Bool", "gt_now", quote! { #actual <= #now });
    }
    if let Some(v) = spec.within {
        let within = nanos(v);
        push(
            "within",
            9,
            "Message",
            "within",
            quote! { (#actual - #now).abs() > #within },
        );
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::nanos;
    #[test]
    fn nanos_preserves_sign_and_integer_boundaries() {
        assert_eq!(nanos((0, 0)), 0);
        assert_eq!(nanos((-1, -1)), -1_000_000_001);
        assert_eq!(
            nanos((i64::MAX, 999_999_999)),
            i128::from(i64::MAX) * 1_000_000_000 + 999_999_999
        );
        assert_eq!(
            nanos((i64::MIN, -999_999_999)),
            i128::from(i64::MIN) * 1_000_000_000 - 999_999_999
        );
    }
}
