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
    CelMessageTree, CelOneofChild, CelOneofContainer, CelOneofPresence, MessageOneofPresence,
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
            &["oneof.message_list", "oneof.field", "oneof.field_list"]
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
