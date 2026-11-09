#![warn(rust_2018_idioms)]

use buffa::{Message as _, MessageView as _};
use protovalidate_buffa::{Validate as _, ValidationError};

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

use generated::buf::validate::conformance::cases::{
    __buffa::{oneof, view},
    CelMessageMap, CelMessageMapIndex, CelMessageTree, CelOneofChild, CelOneofContainer,
    CelOneofPresence, MessageOneofPresence,
    cel_oneof_outer::middle::Inner,
};

fn assert_rules(result: Result<(), ValidationError>, expected: &[&str]) {
    if expected.is_empty() {
        assert!(result.is_ok(), "{result:?}");
    } else {
        let error = result.expect_err("expected validation violations");
        assert!(error.compile_error.is_none(), "{error:?}");
        assert!(error.runtime_error.is_none(), "{error:?}");
        let rules: Vec<_> = error
            .violations
            .iter()
            .map(|v| v.rule_id.as_ref())
            .collect();
        assert_eq!(rules, expected);
    }
}

fn assert_runtime_error(result: Result<(), ValidationError>, rule: &str, reason: &str) {
    assert_eq!(
        result.unwrap_err().runtime_error,
        Some(format!("cel runtime error in rule {rule:?}: {reason}"))
    );
}

#[test]
fn selected_oneof_defaults_have_presence() {
    use oneof::cel_oneof_presence::Choice;

    for (choice, selected) in [
        (None, 0),
        (Some(Choice::Number(0)), 1),
        (Some(Choice::Text(String::new())), 2),
        (Some(Choice::Child(CelOneofChild::default().into())), 3),
        (Some(Choice::Stamp(Box::default())), 4),
    ] {
        for claimed in 0..=4 {
            let owned = CelOneofPresence {
                choice: choice.clone(),
                selected: claimed,
                ..Default::default()
            };
            let bytes = owned.encode_to_vec();
            let borrowed = view::CelOneofPresenceView::decode_view(&bytes).unwrap();
            let rules: &[&str] = if claimed == selected {
                &[]
            } else {
                &["oneof.presence"]
            };
            assert_rules(owned.validate(), rules);
            assert_rules(borrowed.validate(), rules);
        }
    }
}

#[test]
fn message_cel_reads_the_selected_oneof_value_or_its_default() {
    use generated::{
        buf::validate::conformance::cases::{CelOneofColor, CelOneofValue},
        google::protobuf::Timestamp,
    };
    use oneof::cel_oneof_value::Choice;

    /// A selected alternative, its rule ID, and a setter for the `want_*`
    /// field it must equal.
    type Case = (Choice, &'static str, fn(&mut CelOneofValue));

    fn stamp() -> Timestamp {
        Timestamp {
            seconds: 5,
            ..Default::default()
        }
    }
    let red = CelOneofColor::CEL_ONEOF_COLOR_RED;
    let child = CelOneofChild {
        id: "c".to_owned(),
        ..Default::default()
    };
    let cases: [Case; 9] = [
        (Choice::Number(7), "oneof.number", |m| m.want_number = 7),
        (Choice::Count(8), "oneof.count", |m| m.want_count = 8),
        (Choice::Ratio(0.5), "oneof.ratio", |m| m.want_ratio = 0.5),
        (Choice::Flag(true), "oneof.flag", |m| m.want_flag = true),
        (Choice::Color(red.into()), "oneof.color", |m| {
            m.want_color = CelOneofColor::CEL_ONEOF_COLOR_RED.into();
        }),
        (Choice::Text("a".to_owned()), "oneof.text", |m| {
            m.want_text = "a".to_owned();
        }),
        (Choice::Data(b"b".to_vec()), "oneof.data", |m| {
            m.want_data = b"b".to_vec();
        }),
        (Choice::Child(child.into()), "oneof.child", |m| {
            m.want_child_id = "c".to_owned();
        }),
        (Choice::Stamp(stamp().into()), "oneof.stamp", |m| {
            m.want_stamp = stamp().into();
        }),
    ];
    for (choice, rule, set_want) in cases {
        let mut wants_only = CelOneofValue::default();
        set_want(&mut wants_only);
        let with_choice_and_wants = CelOneofValue {
            choice: Some(choice.clone()),
            ..wants_only.clone()
        };
        let with_choice_only = CelOneofValue {
            choice: Some(choice),
            ..Default::default()
        };
        for (message, rules) in [
            (with_choice_and_wants, &[][..]),
            // The selected value isn't the default.
            (with_choice_only, &[rule][..]),
            (wants_only, &[rule][..]),
        ] {
            let bytes = message.encode_to_vec();
            let borrowed = view::CelOneofValueView::decode_view(&bytes).unwrap();
            assert_rules(message.validate(), rules);
            assert_rules(borrowed.validate(), rules);
        }
    }
}

#[test]
fn message_cel_reads_a_oneof_from_another_package() {
    use generated::buf::validate::conformance::cases::{
        CelOneofOtherPackage,
        other_package::{__buffa::oneof::cel_oneof::Choice, CelOneof},
    };

    for (choice, want_text, rules) in [
        (Some(Choice::Text("a".to_owned())), "a", &[][..]),
        (Some(Choice::Number(1)), "a", &["oneof.other_package"][..]),
        (None, "", &[][..]),
    ] {
        let owned = CelOneofOtherPackage {
            other: CelOneof {
                choice,
                ..Default::default()
            }
            .into(),
            want_text: want_text.to_owned(),
            ..Default::default()
        };
        let bytes = owned.encode_to_vec();
        let borrowed = view::CelOneofOtherPackageView::decode_view(&bytes).unwrap();
        assert_rules(owned.validate(), rules);
        assert_rules(borrowed.validate(), rules);
    }
}

#[test]
fn nested_and_repeated_oneofs_use_the_correct_representation() {
    use oneof::cel_oneof_presence::Choice;

    for valid in [false, true] {
        let child = CelOneofPresence {
            choice: Some(if valid {
                Choice::Number(0)
            } else {
                Choice::Text(String::new())
            }),
            selected: if valid { 1 } else { 2 },
            ..Default::default()
        };
        let owned = CelOneofContainer {
            single: child.clone().into(),
            many: vec![child],
            ..Default::default()
        };
        let bytes = owned.encode_to_vec();
        let borrowed = view::CelOneofContainerView::decode_view(&bytes).unwrap();
        let rules: &[&str] = if valid {
            &[]
        } else {
            &["oneof.field", "oneof.field_list", "oneof.message_list"]
        };
        assert_rules(owned.validate(), rules);
        assert_rules(borrowed.validate(), rules);
    }
}

#[test]
fn message_oneof_counts_selected_default_values() {
    use oneof::message_oneof_presence::Choice;

    for choice in [
        None,
        Some(Choice::Number(0)),
        Some(Choice::Text(String::new())),
    ] {
        for outside in ["", "set"] {
            let valid = choice.is_some() == outside.is_empty();
            let owned = MessageOneofPresence {
                choice: choice.clone(),
                outside: outside.to_string(),
                ..Default::default()
            };
            let bytes = owned.encode_to_vec();
            let borrowed = view::MessageOneofPresenceView::decode_view(&bytes).unwrap();
            let rules: &[&str] = if valid { &[] } else { &["message.oneof"] };
            assert_rules(owned.validate(), rules);
            assert_rules(borrowed.validate(), rules);
        }
    }
}

#[test]
fn recursive_message_lists_resolve_element_schemas() {
    for ids in [vec![], vec!["a"], vec!["a", "b"], vec!["a", "a"]] {
        let valid = ids != ["a", "a"];
        let owned = CelMessageTree {
            children: ids
                .into_iter()
                .map(|id| CelMessageTree {
                    id: id.to_string(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        let bytes = owned.encode_to_vec();
        let borrowed = view::CelMessageTreeView::decode_view(&bytes).unwrap();
        let rules: &[&str] = if valid {
            &[]
        } else {
            &["tree.unique_children"]
        };
        assert_rules(owned.validate(), rules);
        assert_rules(borrowed.validate(), rules);
    }
}

#[test]
fn oneofs_in_nested_messages_resolve_their_module_path() {
    use oneof::cel_oneof_outer::middle::inner::{Choice, Mode};

    let valid = Inner {
        selected: 1,
        choice: Some(Choice::Number(1)),
        mode: Some(Mode::Strict(true)),
        ..Default::default()
    };
    let cases: [(Inner, &[&str]); 6] = [
        (valid.clone(), &[]),
        (
            Inner {
                selected: 0,
                choice: None,
                ..valid.clone()
            },
            &["required"],
        ),
        (
            Inner {
                choice: Some(Choice::Number(0)),
                ..valid.clone()
            },
            &["int32.gt"],
        ),
        (
            Inner {
                selected: 0,
                ..valid.clone()
            },
            &["nested_oneof.presence"],
        ),
        (
            Inner {
                selected: 0,
                choice: Some(Choice::Text("set".to_string())),
                outside: "set".to_string(),
                ..valid.clone()
            },
            &["message.oneof"],
        ),
        (
            Inner {
                mode: Some(Mode::Lenient(true)),
                ..valid
            },
            &["required"],
        ),
    ];
    for (owned, rules) in cases {
        let bytes = owned.encode_to_vec();
        let borrowed = view::cel_oneof_outer::middle::InnerView::decode_view(&bytes).unwrap();
        assert_rules(owned.validate(), rules);
        assert_rules(borrowed.validate(), rules);
    }
}

#[test]
fn message_cel_reads_a_maps_size_presence_keys_and_values() {
    /// The map's entries, `want_size`, `want_k`, and the rules that fail.
    type Case = (
        &'static [(&'static str, &'static str)],
        i64,
        &'static str,
        &'static [&'static str],
    );

    let cases: [Case; 7] = [
        (&[], 0, "", &[]),
        (&[("k", "v")], 1, "v", &[]),
        (&[("k", "v"), ("j", "w")], 2, "v", &[]),
        (&[("k", "v")], 0, "v", &["map.size", "map.has"]),
        (&[], 1, "", &["map.size", "map.has"]),
        (&[("k", "v")], 1, "other", &["map.lookup"]),
        (&[("", "")], 1, "", &["map.keys", "map.values"]),
    ];
    for (labels, want_size, want_k, rules) in cases {
        let owned = CelMessageMap {
            labels: labels
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
            want_size,
            want_k: want_k.to_owned(),
            ..Default::default()
        };
        let bytes = owned.encode_to_vec();
        let borrowed = view::CelMessageMapView::decode_view(&bytes).unwrap();
        assert_rules(owned.validate(), rules);
        assert_rules(borrowed.validate(), rules);
    }
}

#[test]
fn message_cel_counts_a_repeated_map_key_once() {
    fn entry(value: u8) -> [u8; 8] {
        [0x0a, 0x06, 0x0a, 0x01, b'k', 0x12, 0x01, value]
    }

    let mut bytes = entry(b'a').to_vec();
    bytes.extend(entry(b'b'));
    // `want_size` is 1, `want_k` is "b".
    bytes.extend([0x10, 0x01, 0x1a, 0x01, b'b']);
    let owned = CelMessageMap::decode_from_slice(&bytes).unwrap();
    let borrowed = view::CelMessageMapView::decode_view(&bytes).unwrap();

    assert_eq!(borrowed.labels.len(), 2);
    assert_rules(owned.validate(), &[]);
    assert_rules(borrowed.validate(), &[]);
}

#[test]
fn message_cel_indexing_a_missing_map_key_is_a_runtime_error() {
    let present = CelMessageMapIndex {
        labels: std::iter::once(("k".to_owned(), "v".to_owned())).collect(),
        ..Default::default()
    };
    let bytes = present.encode_to_vec();
    let borrowed = view::CelMessageMapIndexView::decode_view(&bytes).unwrap();
    assert_rules(present.validate(), &[]);
    assert_rules(borrowed.validate(), &[]);

    let missing = CelMessageMapIndex::default();
    let bytes = missing.encode_to_vec();
    let borrowed = view::CelMessageMapIndexView::decode_view(&bytes).unwrap();
    for result in [missing.validate(), borrowed.validate()] {
        assert_runtime_error(result, "map.index", "no such key");
    }
}

#[test]
fn field_cel_indexing_a_missing_key_of_a_message_map_is_a_runtime_error() {
    use generated::buf::validate::conformance::cases::{
        CelMessageMapFieldIndex, cel_message_map_field_index::Child,
    };

    let present = CelMessageMapFieldIndex {
        children: std::iter::once((
            "k".to_owned(),
            Child {
                id: "y".to_owned(),
                ..Default::default()
            },
        ))
        .collect(),
        ..Default::default()
    };
    let bytes = present.encode_to_vec();
    let borrowed = view::CelMessageMapFieldIndexView::decode_view(&bytes).unwrap();
    assert_rules(present.validate(), &[]);
    assert_rules(borrowed.validate(), &[]);

    let missing = CelMessageMapFieldIndex::default();
    let bytes = missing.encode_to_vec();
    let borrowed = view::CelMessageMapFieldIndexView::decode_view(&bytes).unwrap();
    for result in [missing.validate(), borrowed.validate()] {
        assert_runtime_error(result, "map.message_index", "no such key");
    }
}

#[test]
fn field_cel_indexing_a_list_out_of_range_is_a_runtime_error() {
    use generated::buf::validate::conformance::cases::{
        CelListIndex, CelListNegativeIndex, cel_list_index::Child,
    };

    let valid = CelListIndex {
        items: vec!["x".to_owned()],
        children: vec![Child {
            id: "c".to_owned(),
            ..Default::default()
        }],
        ..Default::default()
    };
    for (message, expected) in [
        (valid.clone(), Ok(&[][..])),
        (
            CelListIndex {
                guarded: vec!["y".to_owned()],
                ..valid.clone()
            },
            Ok(&["list.guarded"][..]),
        ),
        (
            CelListIndex {
                items: Vec::new(),
                ..valid.clone()
            },
            Err("list.index"),
        ),
        (
            CelListIndex {
                children: Vec::new(),
                ..valid
            },
            Err("list.message"),
        ),
    ] {
        let bytes = message.encode_to_vec();
        let borrowed = view::CelListIndexView::decode_view(&bytes).unwrap();
        for result in [message.validate(), borrowed.validate()] {
            match expected {
                Ok(rules) => assert_rules(result, rules),
                Err(rule) => assert_runtime_error(result, rule, "index out of range"),
            }
        }
    }

    for items in [Vec::new(), vec!["x".to_owned()]] {
        let message = CelListNegativeIndex {
            items,
            ..Default::default()
        };
        let bytes = message.encode_to_vec();
        let borrowed = view::CelListNegativeIndexView::decode_view(&bytes).unwrap();
        for result in [message.validate(), borrowed.validate()] {
            assert_runtime_error(result, "list.negative", "index out of range");
        }
    }
}

#[test]
fn cel_optional_value_is_its_value_or_a_runtime_error() {
    use generated::buf::validate::conformance::cases::{
        CelOptionalValue, cel_optional_value::Child,
    };

    let valid = CelOptionalValue {
        labels: std::iter::once(("k".to_owned(), "x".to_owned())).collect(),
        items: vec!["x".to_owned()],
        ..Default::default()
    };
    for (message, expected) in [
        (valid.clone(), Ok(&[][..])),
        (
            CelOptionalValue {
                child: Child {
                    id: "x".to_owned(),
                    ..Default::default()
                }
                .into(),
                ..valid.clone()
            },
            Ok(&["message.value"][..]),
        ),
        (
            CelOptionalValue {
                labels: std::collections::HashMap::default(),
                ..valid.clone()
            },
            Err("map.value"),
        ),
        (
            CelOptionalValue {
                items: Vec::new(),
                ..valid
            },
            Err("list.value"),
        ),
    ] {
        let bytes = message.encode_to_vec();
        let borrowed = view::CelOptionalValueView::decode_view(&bytes).unwrap();
        for result in [message.validate(), borrowed.validate()] {
            match expected {
                Ok(rules) => assert_rules(result, rules),
                Err(rule) => assert_runtime_error(result, rule, "optional.none() dereference"),
            }
        }
    }
}

#[test]
fn field_cel_integer_errors_are_runtime_errors() {
    use generated::buf::validate::conformance::cases::CelIntegerArithmetic;

    let valid = CelIntegerArithmetic {
        divisor: 1,
        modulus: 10,
        dividend: 1,
        difference: 1,
        ..Default::default()
    };
    for (message, error) in [
        (valid.clone(), None),
        (
            CelIntegerArithmetic {
                shift: 64,
                ..valid.clone()
            },
            None,
        ),
        (
            CelIntegerArithmetic {
                sum: i64::MAX,
                ..valid.clone()
            },
            Some(("int.add", "integer overflow")),
        ),
        (
            CelIntegerArithmetic {
                divisor: 0,
                ..valid.clone()
            },
            Some(("int.div", "division by zero")),
        ),
        (
            CelIntegerArithmetic {
                modulus: 0,
                ..valid.clone()
            },
            Some(("int.mod", "modulus by zero")),
        ),
        (
            CelIntegerArithmetic {
                dividend: i64::MIN,
                ..valid.clone()
            },
            Some(("int.div_overflow", "integer overflow")),
        ),
        (
            CelIntegerArithmetic {
                negated: i64::MIN,
                ..valid.clone()
            },
            Some(("int.neg", "integer overflow")),
        ),
        (
            CelIntegerArithmetic {
                difference: 0,
                ..valid.clone()
            },
            Some(("uint.sub", "unsigned integer overflow")),
        ),
        (
            CelIntegerArithmetic { shift: -1, ..valid },
            Some(("int.shift", "math.bitShiftLeft() negative offset")),
        ),
    ] {
        let bytes = message.encode_to_vec();
        let borrowed = view::CelIntegerArithmeticView::decode_view(&bytes).unwrap();
        for result in [message.validate(), borrowed.validate()] {
            match error {
                None => assert_rules(result, &[]),
                Some((rule, reason)) => assert_runtime_error(result, rule, reason),
            }
        }
    }
}

#[test]
fn message_cel_reads_closed_enums() {
    use generated::buf::validate::conformance::cases::{
        CelClosedEnum, CelClosedLevel, CelClosedShade,
    };
    use oneof::cel_closed_enum::Choice;

    let high = Some(Choice::Level(CelClosedLevel::CEL_CLOSED_LEVEL_HIGH));
    let dark = Some(CelClosedShade::CEL_CLOSED_SHADE_DARK);
    let unspecified = Some(CelClosedShade::CEL_CLOSED_SHADE_UNSPECIFIED);
    for (choice, shade, want, rules) in [
        (None, None, 1, &[][..]),
        (high.clone(), None, 2, &[][..]),
        (high, dark, 1, &["closed_enum.oneof"][..]),
        (None, unspecified, 1, &["closed_enum.map"][..]),
    ] {
        let owned = CelClosedEnum {
            want: Some(want),
            shades: shade
                .map(|shade| ("k".to_owned(), shade))
                .into_iter()
                .collect(),
            choice,
            ..Default::default()
        };
        let bytes = owned.encode_to_vec();
        let borrowed = view::CelClosedEnumView::decode_view(&bytes).unwrap();
        assert_rules(owned.validate(), rules);
        assert_rules(borrowed.validate(), rules);
    }
}
