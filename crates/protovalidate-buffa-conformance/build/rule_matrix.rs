//! Expand one rule catalogue across field positions and protobuf syntaxes.
//! Rule options are copied from protoc descriptors, never inferred from emitted
//! Rust. Expected values and violations remain independent in the tests.

use buffa::ExtensionSet;
use buffa_codegen::generated::descriptor::{
    DescriptorProto, Edition, FieldDescriptorProto, FieldOptions, FileDescriptorSet,
    MessageOptions, OneofDescriptorProto,
    field_descriptor_proto::{Label, Type},
};
use protovalidate_buffa_protos::buf::validate::{
    __buffa::ext::FIELD, FieldRules, MapRules, RepeatedRules, field_rules,
};

#[derive(Clone, Copy)]
enum Position {
    Singular,
    Presence,
    Oneof,
    Items,
    Keys,
    Values,
    Wrappers,
    WrapperItems,
    WrapperValues,
}

// ===== impl Position =====

impl Position {
    const fn name(self) -> &'static str {
        match self {
            Self::Singular => "Singular",
            Self::Presence => "PresenceAll",
            Self::Oneof => "Oneofs",
            Self::Items => "Items",
            Self::Keys => "Keys",
            Self::Values => "Values",
            Self::Wrappers => "WrappersAll",
            Self::WrapperItems => "WrapperItems",
            Self::WrapperValues => "WrapperValues",
        }
    }
}

#[expect(
    clippy::redundant_pub_crate,
    reason = "build-script helper is visible only to its parent"
)]
pub(super) fn extend(fds: &mut FileDescriptorSet) -> Vec<String> {
    let original = fds
        .file
        .iter()
        .position(|f| f.package.as_deref() == Some("validation.collection_rules.proto3"))
        .expect("rule catalogue");
    let seed = fds.file[original].clone();
    let items = seed
        .message_type
        .iter()
        .find(|m| m.name.as_deref() == Some("Items"))
        .expect("item catalogue");
    let mut sources = Vec::new();
    for syntax in ["proto3", "proto2", "editions2023", "editions2024"] {
        let mut file = seed.clone();
        let package = format!("validation.collection_rules.{syntax}");
        file.package = Some(package.clone());
        file.name = Some(format!(
            "validation/collection_rules/{syntax}/collections.proto"
        ));
        file.syntax = Some(
            if syntax.starts_with("editions") {
                "editions"
            } else {
                syntax
            }
            .to_owned(),
        );
        file.edition = match syntax {
            "editions2023" => Some(Edition::EDITION_2023),
            "editions2024" => Some(Edition::EDITION_2024),
            _ => None,
        };
        if syntax == "proto2" {
            // Proto2 enums may default to a nonzero first declaration.
            file.enum_type
                .iter_mut()
                .find(|e| e.name.as_deref() == Some("MatrixEnum"))
                .expect("matrix enum")
                .value
                .swap(0, 1);
        }
        for message in &mut file.message_type {
            adjust_message(message, &package, syntax);
        }
        file.message_type
            .retain(|m| !matches!(m.name.as_deref(), Some("Items" | "Keys" | "Values")));
        for position in [
            Position::Singular,
            Position::Presence,
            Position::Oneof,
            Position::Items,
            Position::Keys,
            Position::Values,
            Position::Wrappers,
            Position::WrapperItems,
            Position::WrapperValues,
        ] {
            file.message_type
                .push(message(&items.field, &package, syntax, position));
        }
        if syntax == "proto3" {
            fds.file[original] = file;
        } else {
            sources.push(file.name.clone().expect("matrix filename"));
            fds.file.push(file);
        }
    }
    sources
}

#[expect(
    clippy::too_many_lines,
    reason = "one descriptor transformation per field position"
)]
fn message(
    cases: &[FieldDescriptorProto],
    package: &str,
    syntax: &str,
    position: Position,
) -> DescriptorProto {
    let mut message = DescriptorProto {
        name: Some(position.name().to_owned()),
        ..Default::default()
    };
    if matches!(position, Position::Oneof) {
        message.oneof_decl.push(OneofDescriptorProto {
            name: Some("choice".to_owned()),
            ..Default::default()
        });
    }
    for case in cases {
        let mut field = case.clone();
        if let Some(name) = &mut field.type_name {
            *name = name.replace("validation.collection_rules.proto3", package);
        }
        let rules = field
            .options
            .as_option()
            .and_then(|o| o.extension(&FIELD))
            .expect("case rules");
        let Some(field_rules::Type::Repeated(repeated)) = rules.r#type else {
            panic!("repeated case")
        };
        let rules = repeated.items.as_option().expect("item rules").clone();
        field.label = Some(Label::LABEL_OPTIONAL);
        set_rules(&mut field, rules.clone());
        if matches!(
            position,
            Position::Wrappers | Position::WrapperItems | Position::WrapperValues
        ) {
            let Some(wrapper) = wrapper(field.r#type.expect("case type")) else {
                continue;
            };
            field.r#type = Some(Type::TYPE_MESSAGE);
            field.type_name = Some(format!(".google.protobuf.{wrapper}"));
        }
        match position {
            Position::Singular => {
                let name = format!("Case{}", field.number.expect("case number"));
                let mut value = field.clone();
                value.name = Some("value".to_owned());
                value.number = Some(1);
                // Editions default to explicit presence; singular scenarios
                // deliberately exercise implicit scalars where available.
                if syntax.starts_with("editions") && field.r#type != Some(Type::TYPE_MESSAGE) {
                    use buffa_codegen::generated::descriptor::{
                        FeatureSet, feature_set::FieldPresence,
                    };
                    value.options.get_or_insert_default().features = FeatureSet {
                        field_presence: Some(FieldPresence::IMPLICIT),
                        ..Default::default()
                    }
                    .into();
                }
                message.nested_type.push(DescriptorProto {
                    name: Some(name.clone()),
                    field: vec![value],
                    ..Default::default()
                });
                field.r#type = Some(Type::TYPE_MESSAGE);
                field.type_name = Some(format!(".{package}.{}.{}", position.name(), name));
                field.options = buffa::MessageField::default();
            }
            Position::Presence => {
                if syntax == "proto3" && field.r#type != Some(Type::TYPE_MESSAGE) {
                    field.proto3_optional = Some(true);
                    field.oneof_index =
                        Some(i32::try_from(message.oneof_decl.len()).expect("oneof index"));
                    message.oneof_decl.push(OneofDescriptorProto {
                        name: Some(format!("_{}", field.name.as_deref().expect("case name"))),
                        ..Default::default()
                    });
                }
            }
            Position::Oneof => field.oneof_index = Some(0),
            Position::Items | Position::WrapperItems => {
                field.label = Some(Label::LABEL_REPEATED);
                set_rules(
                    &mut field,
                    FieldRules {
                        r#type: Some(field_rules::Type::Repeated(Box::new(RepeatedRules {
                            items: rules.into(),
                            ..Default::default()
                        }))),
                        ..Default::default()
                    },
                );
            }
            Position::Keys | Position::Values | Position::WrapperValues => {
                let key_side = matches!(position, Position::Keys);
                if key_side
                    && matches!(
                        field.r#type,
                        Some(
                            Type::TYPE_BYTES
                                | Type::TYPE_FLOAT
                                | Type::TYPE_DOUBLE
                                | Type::TYPE_ENUM
                                | Type::TYPE_MESSAGE
                        )
                    )
                {
                    continue;
                }
                let mut target = field.clone();
                target.number = Some(if key_side { 1 } else { 2 });
                target.name = Some(if key_side { "key" } else { "value" }.to_owned());
                target.options = buffa::MessageField::default();
                let other = FieldDescriptorProto {
                    name: Some(if key_side { "value" } else { "key" }.to_owned()),
                    number: Some(if key_side { 2 } else { 1 }),
                    label: Some(Label::LABEL_OPTIONAL),
                    r#type: Some(Type::TYPE_STRING),
                    ..Default::default()
                };
                let name = format!("Case{}Entry", field.number.expect("case number"));
                message.nested_type.push(DescriptorProto {
                    name: Some(name.clone()),
                    field: if key_side {
                        vec![target, other]
                    } else {
                        vec![other, target]
                    },
                    options: MessageOptions {
                        map_entry: Some(true),
                        ..Default::default()
                    }
                    .into(),
                    ..Default::default()
                });
                field.label = Some(Label::LABEL_REPEATED);
                field.r#type = Some(Type::TYPE_MESSAGE);
                field.type_name = Some(format!(".{package}.{}.{}", position.name(), name));
                let mut map = MapRules::default();
                if key_side {
                    map.keys = rules.into();
                } else {
                    map.values = rules.into();
                }
                set_rules(
                    &mut field,
                    FieldRules {
                        r#type: Some(field_rules::Type::Map(Box::new(map))),
                        ..Default::default()
                    },
                );
            }
            Position::Wrappers => {}
        }
        message.field.push(field);
    }
    message
}

fn set_rules(field: &mut FieldDescriptorProto, rules: FieldRules) {
    let mut options = FieldOptions::default();
    options.set_extension(&FIELD, rules);
    field.options = options.into();
}

const fn wrapper(kind: Type) -> Option<&'static str> {
    match kind {
        Type::TYPE_STRING => Some("StringValue"),
        Type::TYPE_BYTES => Some("BytesValue"),
        Type::TYPE_INT32 => Some("Int32Value"),
        Type::TYPE_INT64 => Some("Int64Value"),
        Type::TYPE_UINT32 => Some("UInt32Value"),
        Type::TYPE_UINT64 => Some("UInt64Value"),
        Type::TYPE_FLOAT => Some("FloatValue"),
        Type::TYPE_DOUBLE => Some("DoubleValue"),
        Type::TYPE_BOOL => Some("BoolValue"),
        _ => None,
    }
}

fn adjust_message(message: &mut DescriptorProto, package: &str, syntax: &str) {
    let synthetic: std::collections::BTreeSet<_> = message
        .field
        .iter()
        .filter(|f| f.proto3_optional == Some(true))
        .filter_map(|f| f.oneof_index)
        .collect();
    if syntax != "proto3" {
        let mut index = 0;
        message.oneof_decl.retain(|_| {
            let keep = !synthetic.contains(&index);
            index += 1;
            keep
        });
    }
    for field in &mut message.field {
        if let Some(name) = &mut field.type_name {
            *name = name.replace("validation.collection_rules.proto3", package);
        }
        if syntax != "proto3" {
            if field.proto3_optional == Some(true) {
                field.proto3_optional = None;
                field.oneof_index = None;
            } else if let Some(index) = &mut field.oneof_index {
                *index -= i32::try_from(synthetic.range(..*index).count()).expect("oneof count");
            }
        }
    }
    for nested in &mut message.nested_type {
        adjust_message(nested, package, syntax);
    }
}
