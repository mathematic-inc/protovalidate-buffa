#![warn(rust_2018_idioms)]

use buffa::{HasMessageView, Message};
use protovalidate_buffa::{Validate, ValidationError};

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    elided_lifetimes_in_paths,
    non_camel_case_types,
    unused_imports,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_html_tags,
    reason = "buffa-build generated code"
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/_include.rs"));
}

use generated::{
    acme::v1::{
        IgnoredLocale, IgnoredUnsupportedRule, PredefinedPaths, PresenceRules, RequiredValue,
        ZeroValueRules, zero_value_rules::State,
    },
    validation::string_presence::{
        __buffa::oneof::oneof_strings::Choice, OneofStrings, OptionalStrings,
    },
};

fn assert_rules(result: Result<(), ValidationError>, expected: &[&str]) {
    let actual = result.map_err(|error| {
        assert!(error.compile_error.is_none(), "{error:?}");
        assert!(error.runtime_error.is_none(), "{error:?}");
        error
            .violations
            .into_iter()
            .map(|violation| violation.rule_id.into_owned())
            .collect::<Vec<_>>()
    });
    let expected = if expected.is_empty() {
        Ok(())
    } else {
        Err(expected.iter().map(|rule| (*rule).to_string()).collect())
    };
    assert_eq!(actual, expected);
}

fn assert_owned_and_view<M>(owned: &M, expected: &[&str]) -> Result<(), buffa::DecodeError>
where
    M: HasMessageView + Validate,
    for<'a> M::View<'a>: Validate,
{
    assert_rules(owned.validate(), expected);
    let bytes = owned.encode_to_vec();
    let view = M::decode_view(&bytes)?;
    assert_rules(view.validate(), expected);
    Ok(())
}

// https://github.com/mathematic-inc/protovalidate-buffa/discussions/83
#[test]
fn optional_strings_enforce_formats_and_exact_lengths() -> Result<(), buffa::DecodeError> {
    assert_owned_and_view(&OptionalStrings::default(), &[])?;
    let valid = OptionalStrings {
        uuid: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
        email: Some("user@example.com".to_string()),
        characters: Some("éé".to_string()),
        bytes: Some("éé".to_string()),
        hostname: Some("example.com".to_string()),
        header: Some("X-Request-Id".to_string()),
        pattern: Some("abc".to_string()),
        constant: Some("a".to_string()),
        ..Default::default()
    };
    assert_owned_and_view(&valid, &[])?;
    let invalid = OptionalStrings {
        uuid: Some("x".to_string()),
        email: Some("x".to_string()),
        characters: Some("é".to_string()),
        bytes: Some("abcdé".to_string()),
        hostname: Some("bad host".to_string()),
        header: Some("bad header".to_string()),
        pattern: Some("b".to_string()),
        constant: Some("b".to_string()),
        ..Default::default()
    };
    assert_owned_and_view(
        &invalid,
        &[
            "string.uuid",
            "string.email",
            "string.len",
            "string.len_bytes",
            "string.hostname",
            "string.well_known_regex.header_name",
            "string.pattern",
            "string.const",
        ],
    )?;
    assert_owned_and_view(
        &OptionalStrings {
            uuid: Some(String::new()),
            ..Default::default()
        },
        &["string.uuid_empty"],
    )
}

// https://github.com/mathematic-inc/protovalidate-buffa/discussions/83
#[test]
fn selected_oneof_strings_enforce_formats_and_exact_lengths() -> Result<(), buffa::DecodeError> {
    assert_owned_and_view(&OneofStrings::default(), &[])?;
    for choice in [
        Choice::Uuid("550e8400-e29b-41d4-a716-446655440000".to_string()),
        Choice::Email("user@example.com".to_string()),
        Choice::Characters("éé".to_string()),
        Choice::Bytes("éé".to_string()),
        Choice::Hostname("example.com".to_string()),
        Choice::Header("X-Request-Id".to_string()),
        Choice::Pattern("abc".to_string()),
        Choice::Constant("a".to_string()),
    ] {
        assert_owned_and_view(
            &OneofStrings {
                choice: Some(choice),
                ..Default::default()
            },
            &[],
        )?;
    }
    for (choice, rule) in [
        (Choice::Uuid("x".to_string()), "string.uuid"),
        (Choice::Uuid(String::new()), "string.uuid_empty"),
        (Choice::Email("x".to_string()), "string.email"),
        (Choice::Characters("é".to_string()), "string.len"),
        (Choice::Bytes("abcdé".to_string()), "string.len_bytes"),
        (Choice::Hostname("bad host".to_string()), "string.hostname"),
        (
            Choice::Header("bad header".to_string()),
            "string.well_known_regex.header_name",
        ),
        (Choice::Pattern("b".to_string()), "string.pattern"),
        (Choice::Constant("b".to_string()), "string.const"),
    ] {
        assert_owned_and_view(
            &OneofStrings {
                choice: Some(choice),
                ..Default::default()
            },
            &[rule],
        )?;
    }
    Ok(())
}

// https://github.com/mathematic-inc/protovalidate-buffa/discussions/84
#[test]
fn zero_value_ignore_covers_standard_cel_and_predefined_rules() -> Result<(), buffa::DecodeError> {
    for locale in ["", "en"] {
        assert_owned_and_view(
            &IgnoredLocale {
                locale: locale.to_string(),
                ..Default::default()
            },
            &[],
        )?;
    }
    assert_owned_and_view(
        &IgnoredLocale {
            locale: "_".to_string(),
            ..Default::default()
        },
        &["string.min_len", "locale.cel", "string.language_tag"],
    )
}

// https://github.com/mathematic-inc/protovalidate-buffa/discussions/84
#[test]
fn zero_value_ignore_covers_every_implicit_presence_kind() -> Result<(), buffa::DecodeError> {
    assert_owned_and_view(&ZeroValueRules::default(), &[])?;
    let nonzero = ZeroValueRules {
        text: "x".to_string(),
        data: vec![1],
        signed32: 1,
        signed64: 1,
        unsigned32: 1,
        unsigned64: 1,
        float32: 1.0,
        float64: 1.0,
        flag: true,
        state: State::STATE_SET.into(),
        items: vec!["x".to_string()],
        entries: std::iter::once(("key".to_string(), "value".to_string())).collect(),
        ..Default::default()
    };
    assert_owned_and_view(
        &nonzero,
        &[
            "text.cel",
            "data.cel",
            "signed32.cel",
            "signed64.cel",
            "unsigned32.cel",
            "unsigned64.cel",
            "float32.cel",
            "float64.cel",
            "flag.cel",
            "state.cel",
            "items.cel",
            "entries.cel",
        ],
    )
}

// https://github.com/mathematic-inc/protovalidate-buffa/discussions/84
#[test]
fn explicit_presence_still_validates_selected_zero_values() -> Result<(), buffa::DecodeError> {
    assert_owned_and_view(&PresenceRules::default(), &[])?;
    assert_owned_and_view(
        &PresenceRules {
            text: Some(String::new()),
            wrapper: generated::google::protobuf::StringValue::default().into(),
            child: generated::acme::v1::presence_rules::Child::default().into(),
            ..Default::default()
        },
        &[
            "optional.cel",
            "wrapper.cel",
            "message.cel",
            "string.language_tag",
            "string.language_tag",
        ],
    )?;
    assert_owned_and_view(
        &RequiredValue::default(),
        &["required.cel", "string.language_tag"],
    )
}

// https://github.com/mathematic-inc/protovalidate-buffa/discussions/84
#[test]
fn ignored_zero_values_skip_unsupported_cel() -> Result<(), buffa::DecodeError> {
    assert_owned_and_view(&IgnoredUnsupportedRule::default(), &[])?;
    let owned = IgnoredUnsupportedRule {
        text: "set".to_string(),
        ..Default::default()
    };
    let bytes = owned.encode_to_vec();
    let view = IgnoredUnsupportedRule::decode_view(&bytes)?;
    for result in [owned.validate(), view.validate()] {
        assert!(result.is_err_and(|error| error.runtime_error.is_some()));
    }
    Ok(())
}

// https://github.com/mathematic-inc/protovalidate-buffa/discussions/85
#[test]
fn predefined_rule_paths_preserve_package_and_enclosing_messages() -> Result<(), buffa::DecodeError>
{
    let owned = PredefinedPaths {
        direct: "_".to_string(),
        nested: "_".to_string(),
        items: vec!["en".to_string(), "_".to_string()],
        global: "_".to_string(),
        ..Default::default()
    };
    let bytes = owned.encode_to_vec();
    let view = PredefinedPaths::decode_view(&bytes)?;
    for result in [owned.validate(), view.validate()] {
        let paths = result.map_err(|error| {
            assert!(error.compile_error.is_none(), "{error:?}");
            assert!(error.runtime_error.is_none(), "{error:?}");
            error
                .violations
                .into_iter()
                .map(|violation| (violation.field.to_string(), violation.rule.to_string()))
                .collect::<Vec<_>>()
        });
        assert_eq!(
            paths,
            Err([
                ("items[1]", "repeated.items.string.[acme.v1.language_tag]"),
                ("direct", "string.[acme.v1.language_tag]"),
                ("nested", "string.[acme.v1.Outer.Inner.language_tag]"),
                ("global", "string.[global_language_tag]"),
            ]
            .into_iter()
            .map(|(field, rule)| (field.to_string(), rule.to_string()))
            .collect())
        );
    }
    Ok(())
}
