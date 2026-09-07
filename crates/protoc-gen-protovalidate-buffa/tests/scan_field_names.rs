//! Discussion #53: naming matches buffa across the full request, including
//! descriptors that are not selected for generation.
#![warn(rust_2018_idioms)]

use std::{
    io::Write as _,
    process::{Command, Stdio},
};

use buffa::{ExtensionSet as _, Message as _};
use buffa_codegen::{
    CodeGenConfig, GeneratedFileKind,
    generated::{
        compiler::{CodeGeneratorRequest, CodeGeneratorResponse},
        descriptor::{
            DescriptorProto, FieldDescriptorProto, FieldOptions, FileDescriptorProto,
            OneofDescriptorProto,
            field_descriptor_proto::{Label, Type},
        },
    },
};
use protoc_gen_protovalidate_buffa::scan::gather;

fn field(name: &str, number: i32) -> FieldDescriptorProto {
    FieldDescriptorProto {
        name: Some(name.to_string()),
        number: Some(number),
        label: Some(Label::LABEL_OPTIONAL),
        r#type: Some(Type::TYPE_STRING),
        ..Default::default()
    }
}

fn message(name: &str, fields: Vec<FieldDescriptorProto>) -> DescriptorProto {
    DescriptorProto {
        name: Some(name.into()),
        field: fields,
        ..Default::default()
    }
}

fn request(messages: Vec<DescriptorProto>) -> CodeGeneratorRequest {
    CodeGeneratorRequest {
        file_to_generate: vec!["names.proto".into()],
        proto_file: vec![FileDescriptorProto {
            name: Some("names.proto".into()),
            syntax: Some("proto2".into()),
            message_type: messages,
            ..Default::default()
        }],
        parameter: Some("idiomatic_field_names".into()),
        ..Default::default()
    }
}

fn rust_names(request: &CodeGeneratorRequest) -> Vec<String> {
    gather(request)
        .unwrap()
        .into_iter()
        .flat_map(|m| m.field_rules.into_iter().map(|f| f.rust_name))
        .collect()
}

#[test]
fn conversion_matches_buffa_for_acronyms_digits_underscores_and_keywords() {
    let cases = [
        ("userName", "user_name"),
        ("XMLHttpRequest", "xml_http_request"),
        ("v2Field", "v2_field"),
        ("XML2Request", "xml2_request"),
        ("foo_2Bar", "foo_2bar"),
        ("_fieldName3", "_field_name3"),
        ("fieldName_", "field_name_"),
        ("a__B", "a__b"),
        ("already_snake", "already_snake"),
        ("Type", "type"),
        ("Self", "self"),
    ];
    for (proto, rust) in cases {
        let req = request(vec![message("Names", vec![field(proto, 1)])]);
        assert_eq!(rust_names(&req), [rust], "{proto}");
        let mut config = CodeGenConfig::default();
        config.idiomatic_field_names = true;
        let generated =
            buffa_codegen::generate(&req.proto_file, &req.file_to_generate, &config).unwrap();
        let ident = buffa_codegen::idents::make_field_ident(rust);
        assert!(
            generated
                .iter()
                .filter(|file| file.kind == GeneratedFileKind::Owned)
                .any(|file| file.content.contains(&format!("pub {ident}:"))),
            "buffa differs for {proto}"
        );
    }
}

#[test]
fn collisions_include_imports_nested_messages_and_verbatim_precedence() {
    let mut req = request(vec![message(
        "Names",
        vec![field("userName", 1), field("otherName", 3)],
    )]);
    // Imported nested descriptors are deliberately excluded from file_to_generate.
    req.proto_file.push(FileDescriptorProto {
        name: Some("import.proto".into()),
        syntax: Some("proto2".into()),
        message_type: vec![DescriptorProto {
            name: Some("Outer".into()),
            nested_type: vec![
                message(
                    "Suffix",
                    vec![
                        field("userName", 1),
                        field("user_name", 2),
                        field("otherName", 3),
                        field("other_name", 4),
                    ],
                ),
                message(
                    "Fallback",
                    vec![
                        field("otherName", 3),
                        field("other_name", 4),
                        field("other_name_f3", 5),
                    ],
                ),
            ],
            ..Default::default()
        }],
        ..Default::default()
    });
    assert_eq!(rust_names(&req), ["user_name_f1", "otherName"]);
    req.proto_file.reverse();
    req.proto_file[0].message_type[0].nested_type.reverse();
    assert_eq!(rust_names(&req), ["user_name_f1", "otherName"]);
}

#[test]
fn secondary_collision_reverts_unrelated_conversions_too() {
    let req = request(vec![message(
        "Names",
        vec![
            field("userName", 1),
            field("user_name", 2),
            field("user_name_f1", 3),
            field("unrelatedName", 4),
        ],
    )]);
    assert_eq!(
        rust_names(&req),
        ["userName", "user_name", "user_name_f1", "unrelatedName"]
    );
}

#[test]
fn synthetic_oneofs_and_variant_names_do_not_occupy_struct_namespace() {
    let mut optional = field("optionalName", 1);
    optional.oneof_index = Some(1);
    optional.proto3_optional = Some(true);
    let mut variant = field("choice_value", 2);
    variant.oneof_index = Some(0);
    let mut req = request(vec![DescriptorProto {
        oneof_decl: vec![
            OneofDescriptorProto {
                name: Some("choiceValue".into()),
                ..Default::default()
            },
            OneofDescriptorProto {
                name: Some("_optionalName".into()),
                ..Default::default()
            },
        ],
        ..message("Names", vec![optional, variant])
    }]);
    req.proto_file[0].syntax = Some("proto3".into());
    let scanned = gather(&req).unwrap();
    assert_eq!(scanned[0].field_rules[0].rust_name, "optional_name");
    assert_eq!(scanned[0].oneof_rules.len(), 1);
    assert_eq!(scanned[0].oneof_rules[0].rust_name, "choice_value");
    assert_eq!(
        scanned[0].oneof_rules[0].fields[0].field_name,
        "choice_value"
    );
}

#[test]
fn default_false_bare_and_explicit_true_options() {
    let mut req = request(vec![message("Names", vec![field("userName", 1)])]);
    for (parameter, expected) in [
        ("", "userName"),
        ("idiomatic_field_names=false", "userName"),
        ("idiomatic_field_names", "user_name"),
        ("idiomatic_field_names=true", "user_name"),
        (
            " proto_module = crate::pb , idiomatic_field_names = true , future_option",
            "user_name",
        ),
        (
            "idiomatic_field_names=true,idiomatic_field_names=false",
            "userName",
        ),
    ] {
        req.parameter = Some(parameter.into());
        assert_eq!(rust_names(&req), [expected]);
    }
    req.parameter = None;
    assert_eq!(rust_names(&req), ["userName"]);
}

fn invoke_plugin(request: &CodeGeneratorRequest) -> CodeGeneratorResponse {
    let mut child = Command::new(env!("CARGO_BIN_EXE_protoc-gen-protovalidate-buffa"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&request.encode_to_vec())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    CodeGeneratorResponse::decode_from_slice(&output.stdout).unwrap()
}

#[test]
fn plugin_accepts_naming_flag_and_reports_invalid_values() {
    let mut req = request(vec![message("Names", vec![field("userName", 1)])]);
    let mut options = FieldOptions::default();
    options.set_extension(
        &protovalidate_buffa_protos::buf::validate::__buffa::ext::FIELD,
        protovalidate_buffa_protos::buf::validate::FieldRules {
            required: Some(true),
            ..Default::default()
        },
    );
    req.proto_file[0].message_type[0].field[0].options = options.into();
    let response = invoke_plugin(&req);
    assert!(response.error.is_none(), "{:?}", response.error);
    assert!(response.file.iter().any(|file| {
        file.content
            .as_ref()
            .is_some_and(|source| source.contains("self.user_name"))
    }));
    for parameter in [
        "idiomatic_field_names=yes",
        "idiomatic_field_names=",
        "idiomatic_field_names=1",
    ] {
        req.parameter = Some(parameter.into());
        let error = invoke_plugin(&req)
            .error
            .expect("invalid value must fail generation");
        assert!(error.contains("idiomatic_field_names must be true or false"));
    }
}

#[test]
fn every_changed_member_in_a_collision_gets_its_field_number() {
    let req = request(vec![message(
        "Names",
        vec![field("userName", 1), field("UserName", 2)],
    )]);
    assert_eq!(rust_names(&req), ["user_name_f1", "user_name_f2"]);
}

#[test]
fn oneofs_inherit_verbatim_fallback_from_imported_descriptors() {
    let mut member = field("textValue", 1);
    member.oneof_index = Some(0);
    let mut choices = message("Choices", vec![member]);
    choices.oneof_decl.push(OneofDescriptorProto {
        name: Some("choiceValue".into()),
        ..Default::default()
    });
    let mut req = request(vec![choices.clone()]);
    choices.field.push(field("choice_value", 2));
    choices.name = Some("Collision".into());
    req.proto_file.push(FileDescriptorProto {
        name: Some("import.proto".into()),
        message_type: vec![choices],
        syntax: Some("proto2".into()),
        ..Default::default()
    });
    let scanned = gather(&req).unwrap();
    assert_eq!(scanned[0].oneof_rules[0].rust_name, "choiceValue");
    assert_eq!(scanned[0].oneof_rules[0].fields[0].field_name, "textValue");
}
