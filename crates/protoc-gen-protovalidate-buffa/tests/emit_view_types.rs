#![warn(rust_2018_idioms)]

use protoc_gen_protovalidate_buffa::{emit::render, scan::MessageValidators};

#[test]
fn nested_message_emits_owned_and_view_validators() {
    let files = render(&[MessageValidators {
        proto_name: "test.v1.Outer.Nested".to_string(),
        package: "test.v1".to_string(),
        source_file: "test/v1/nested.proto".to_string(),
        message_cel: Vec::new(),
        message_oneofs: Vec::new(),
        field_rules: Vec::new(),
        oneof_rules: Vec::new(),
        compile_error: None,
    }])
    .expect("render must succeed");
    let source = files
        .into_iter()
        .filter_map(|file| file.content)
        .collect::<String>();

    assert!(source.contains("Validate for outer::Nested"));
    assert!(source.contains("Validate for __buffa::view::outer::NestedView<'_>"));
    assert_eq!(source.matches("let mut violations").count(), 2);
    assert!(!source.contains("to_owned_message"));
}
