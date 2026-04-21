//! Walk a `CodeGeneratorRequest` and extract validation rules from descriptors.
//!
//! Extracts `(buf.validate.field)` / `(buf.validate.message)` / `(buf.validate.oneof)`
//! rules via buffa's `ExtensionSet`, and produces a `Vec<MessageValidators>`.

use anyhow::anyhow;
use buffa::ExtensionSet;
use buffa_codegen::generated::{
    compiler::CodeGeneratorRequest,
    descriptor::{
        feature_set, field_descriptor_proto, DescriptorProto, FieldDescriptorProto,
        FileDescriptorProto, OneofDescriptorProto,
    },
};
use protovalidate_buffa_protos::buf::validate::{
    field_rules, fixed32rules, fixed64rules, int32rules, int64rules, s_fixed32rules,
    s_fixed64rules, s_int32rules, s_int64rules, string_rules, u_int32rules, u_int64rules,
    BytesRules, DoubleRules, EnumRules, FieldRules, Fixed32Rules, Fixed64Rules, FloatRules,
    Int32Rules, Int64Rules, MapRules, MessageRules, OneofRules, RepeatedRules, SFixed32Rules,
    SFixed64Rules, SInt32Rules, SInt64Rules, StringRules, UInt32Rules, UInt64Rules, FIELD, MESSAGE,
    ONEOF,
};

// ─── Public output types ──────────────────────────────────────────────────────

/// All validators collected for a single protobuf message.
#[derive(Debug)]
pub struct MessageValidators {
    /// Fully-qualified proto name, e.g. `"test.v1.ScalarsMessage"`.
    pub proto_name: String,
    /// Package, e.g. `"test.v1"`.
    pub package: String,
    /// Source `.proto` filename, e.g. `"scalars.proto"`.
    pub source_file: String,
    /// CEL rules attached to the message itself.
    pub message_cel: Vec<CelRule>,
    /// `(buf.validate.message).oneof` rules.
    pub message_oneofs: Vec<MessageOneofSpec>,
    /// Per-field validators.
    pub field_rules: Vec<FieldValidator>,
    /// Per-oneof validators.
    pub oneof_rules: Vec<OneofValidator>,
    /// If the message has a rule/field type mismatch, emit a stub Validate
    /// impl that reports a compilation error with this reason.
    pub compile_error: Option<String>,
}

/// Validator for a single field.
#[derive(Debug)]
pub struct FieldValidator {
    pub field_number: i32,
    pub field_name: String,
    pub field_type: FieldKind,
    /// `(buf.validate.field).required`
    pub required: bool,
    /// `(buf.validate.field).ignore`
    pub ignore: Ignore,
    /// Standard type-specific rules.
    pub standard: StandardRules,
    /// CEL rules.
    pub cel: Vec<CelRule>,
    /// Index into the parent message's `oneof_decl` list, or `None` for
    /// regular (non-oneof) fields. Used by the emitter to decide whether to
    /// generate `self.<field>.as_option()` (plain optional) or a oneof-match
    /// arm.
    pub oneof_index: Option<i32>,
    /// When the field is part of a oneof, this is the oneof's name (e.g. `"event"`
    /// or `"source"`). `None` for non-oneof fields.
    pub oneof_name: Option<String>,
    /// True if the field has explicit presence semantics but is stored as
    /// plain T (not Option<T>): proto2 LABEL_REQUIRED or editions
    /// LEGACY_REQUIRED. IGNORE_IF_ZERO_VALUE should NOT skip rules for
    /// such fields since the zero value is considered "set".
    pub is_legacy_required: bool,
    /// True if the field is proto group (TYPE_GROUP) — emits TYPE_GROUP in
    /// field_type metadata instead of TYPE_MESSAGE.
    pub is_group: bool,
}

/// Validator for a single oneof.
///
/// Note: `buf.validate.OneofRules` only has `.required` — the validate.proto
/// schema does not expose `.cel` on `OneofRules` (unlike FieldRules/MessageRules).
#[derive(Debug)]
pub struct OneofValidator {
    pub name: String,
    pub required: bool,
    /// The parent message name (e.g. `"CreateGradingRequest"`), used to derive the
    /// buffa-generated module name for the oneof enum type.
    pub parent_msg_name: String,
    /// Per-variant field validators for fields belonging to this oneof.
    /// These have field rules that must be checked inside a match arm.
    pub fields: Vec<FieldValidator>,
}

#[derive(Debug, Clone)]
pub struct MessageOneofSpec {
    pub fields: Vec<std::string::String>,
    pub required: bool,
}

/// A single CEL constraint.
#[derive(Debug, Clone)]
pub struct CelRule {
    pub id: String,
    pub message: String,
    pub expression: String,
    /// If true, this rule came from the `cel_expression` field (rule_id is
    /// the expression itself, emitted with a different rule-path).
    pub is_cel_expression: bool,
}

/// A predefined-rule CEL expression with `rule` bound to an extension value.
#[derive(Debug, Clone)]
pub struct PredefinedCel {
    pub id: String,
    pub message: String,
    pub expression: String,
    /// Pre-rendered CEL value for the `rule` binding — e.g. `Value::Int(-2)`,
    /// `Value::List(...)`, `Value::Bool(true)`. Stored as a Rust expression
    /// string that the emit stage can splice directly into TokenStreams.
    pub rule_value_expr: String,
    /// Extension number (for rule-path metadata).
    pub ext_number: i32,
    /// Extension name (e.g. "int32_abs_in_proto2").
    pub ext_name: String,
    /// Extension's declared proto type (for rule-path field_type).
    pub ext_field_type: String,
    /// Rule family override used when the extension targets RepeatedRules or
    /// MapRules directly (name=\"repeated\"/\"map\", number=18/19), rather
    /// than the field's scalar/message type.
    pub family_override: Option<(&'static str, i32)>,
}

/// Ignore semantics, mirroring `buf.validate.Ignore`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ignore {
    Unspecified,
    IfZeroValue,
    Always,
}

/// Protobuf field type classification (post map/repeated detection).
#[derive(Debug)]
pub enum FieldKind {
    String,
    Bytes,
    Int32,
    Int64,
    Uint32,
    Uint64,
    Sint32,
    Sint64,
    Fixed32,
    Fixed64,
    Sfixed32,
    Sfixed64,
    Float,
    Double,
    Bool,
    Enum {
        full_name: std::string::String,
    },
    Message {
        full_name: std::string::String,
    },
    Repeated(Box<Self>),
    Map {
        key: Box<Self>,
        value: Box<Self>,
    },
    /// A scalar with EXPLICIT field presence (`features.field_presence = EXPLICIT`
    /// in Edition 2023, or `proto3_optional = true` in the descriptor). The Rust
    /// type is `Option<T>` for the inner scalar kind.
    Optional(Box<Self>),
    /// A `google.protobuf.{Int32,Int64,...,String,Bytes}Value` wrapper field.
    /// Buffa stores it as `MessageField<WrapperType>`; rules are applied to the
    /// wrapped inner scalar via `self.field.as_option().map(|w| w.value)`.
    Wrapper(Box<Self>),
}

/// All supported standard rule families — at most one is `Some` for any field.
#[derive(Debug, Default)]
pub struct StandardRules {
    pub string: Option<StringStandard>,
    pub bytes: Option<BytesStandard>,
    pub int32: Option<Int32Standard>,
    pub int64: Option<Int64Standard>,
    pub uint32: Option<Uint32Standard>,
    pub uint64: Option<Uint64Standard>,
    pub float: Option<FloatStandard>,
    pub double: Option<DoubleStandard>,
    pub enum_rules: Option<EnumStandard>,
    pub repeated: Option<RepeatedStandard>,
    pub map: Option<MapStandard>,
    pub bool_rules: Option<BoolStandard>,
    pub any_rules: Option<AnyStandard>,
    pub duration: Option<DurationStandard>,
    pub timestamp: Option<TimestampStandard>,
    pub field_mask: Option<FieldMaskStandard>,
    /// Predefined (extension-defined) CEL rules discovered on this field's
    /// inner rule message via unknown_fields.
    pub predefined: Vec<PredefinedCel>,
}

#[derive(Debug, Default, Clone)]
pub struct FieldMaskStandard {
    /// `const`: value.paths must exactly equal this set.
    pub r#const: Option<Vec<String>>,
    /// `in`: every path in value.paths must match or be a subpath of any entry.
    pub in_set: Vec<String>,
    /// `not_in`: no path may match or be a subpath of any entry.
    pub not_in: Vec<String>,
}

#[derive(Debug, Default)]
pub struct AnyStandard {
    pub in_set: Vec<std::string::String>,
    pub not_in: Vec<std::string::String>,
}

#[derive(Debug, Default, Clone)]
pub struct DurationStandard {
    pub r#const: Option<(i64, i32)>,
    pub lt: Option<(i64, i32)>,
    pub lte: Option<(i64, i32)>,
    pub gt: Option<(i64, i32)>,
    pub gte: Option<(i64, i32)>,
    pub in_set: Vec<(i64, i32)>,
    pub not_in: Vec<(i64, i32)>,
}

#[derive(Debug, Default, Clone)]
pub struct TimestampStandard {
    pub r#const: Option<(i64, i32)>,
    pub lt: Option<(i64, i32)>,
    pub lte: Option<(i64, i32)>,
    pub gt: Option<(i64, i32)>,
    pub gte: Option<(i64, i32)>,
    pub lt_now: bool,
    pub gt_now: bool,
    pub within: Option<(i64, i32)>,
}

impl StandardRules {
    #[must_use]
    pub const fn as_string(&self) -> Option<&StringStandard> {
        self.string.as_ref()
    }
    #[must_use]
    pub const fn as_bytes(&self) -> Option<&BytesStandard> {
        self.bytes.as_ref()
    }
    #[must_use]
    pub const fn as_int32(&self) -> Option<&Int32Standard> {
        self.int32.as_ref()
    }
    #[must_use]
    pub const fn as_int64(&self) -> Option<&Int64Standard> {
        self.int64.as_ref()
    }
    #[must_use]
    pub const fn as_uint32(&self) -> Option<&Uint32Standard> {
        self.uint32.as_ref()
    }
    #[must_use]
    pub const fn as_uint64(&self) -> Option<&Uint64Standard> {
        self.uint64.as_ref()
    }
    #[must_use]
    pub const fn as_float(&self) -> Option<&FloatStandard> {
        self.float.as_ref()
    }
    #[must_use]
    pub const fn as_double(&self) -> Option<&DoubleStandard> {
        self.double.as_ref()
    }
    #[must_use]
    pub const fn as_enum(&self) -> Option<&EnumStandard> {
        self.enum_rules.as_ref()
    }
    #[must_use]
    pub const fn as_repeated(&self) -> Option<&RepeatedStandard> {
        self.repeated.as_ref()
    }
    #[must_use]
    pub const fn as_map(&self) -> Option<&MapStandard> {
        self.map.as_ref()
    }
    #[must_use]
    pub const fn as_bool(&self) -> Option<&BoolStandard> {
        self.bool_rules.as_ref()
    }
}

#[derive(Debug)]
pub struct StringStandard {
    pub min_len: Option<u64>,
    pub max_len: Option<u64>,
    pub len: Option<u64>,
    pub min_bytes: Option<u64>,
    pub max_bytes: Option<u64>,
    pub len_bytes: Option<u64>,
    pub pattern: Option<std::string::String>,
    pub uuid: Option<bool>,
    pub tuuid: Option<bool>,
    pub ulid: Option<bool>,
    pub ip: Option<bool>,
    pub ipv4: Option<bool>,
    pub ipv6: Option<bool>,
    pub ip_with_prefixlen: Option<bool>,
    pub ipv4_with_prefixlen: Option<bool>,
    pub ipv6_with_prefixlen: Option<bool>,
    pub ip_prefix: Option<bool>,
    pub ipv4_prefix: Option<bool>,
    pub ipv6_prefix: Option<bool>,
    pub hostname: Option<bool>,
    pub host_and_port: Option<bool>,
    pub email: Option<bool>,
    pub uri: Option<bool>,
    pub uri_ref: Option<bool>,
    pub address: Option<bool>,
    pub protobuf_fqn: Option<bool>,
    pub protobuf_dot_fqn: Option<bool>,
    pub well_known_regex: Option<i32>,
    pub strict_regex: Option<bool>,
    pub in_set: Vec<std::string::String>,
    pub not_in_set: Vec<std::string::String>,
    pub prefix: Option<std::string::String>,
    pub suffix: Option<std::string::String>,
    pub contains: Option<std::string::String>,
    pub not_contains: Option<std::string::String>,
    pub r#const: Option<std::string::String>,
}

#[derive(Debug)]
pub struct BytesStandard {
    pub min_len: Option<u64>,
    pub max_len: Option<u64>,
    pub len: Option<u64>,
    pub ip: Option<bool>,
    pub ipv4: Option<bool>,
    pub ipv6: Option<bool>,
    pub uuid: Option<bool>,
    pub pattern: Option<std::string::String>,
    pub in_set: Vec<Vec<u8>>,
    pub not_in_set: Vec<Vec<u8>>,
    pub prefix: Option<Vec<u8>>,
    pub suffix: Option<Vec<u8>>,
    pub contains: Option<Vec<u8>>,
    pub r#const: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct Int32Standard {
    pub r#const: Option<i32>,
    pub lt: Option<i32>,
    pub lte: Option<i32>,
    pub gt: Option<i32>,
    pub gte: Option<i32>,
    pub in_set: Vec<i32>,
    pub not_in: Vec<i32>,
}

#[derive(Debug)]
pub struct Int64Standard {
    pub r#const: Option<i64>,
    pub lt: Option<i64>,
    pub lte: Option<i64>,
    pub gt: Option<i64>,
    pub gte: Option<i64>,
    pub in_set: Vec<i64>,
    pub not_in: Vec<i64>,
}

#[derive(Debug)]
pub struct Uint32Standard {
    pub r#const: Option<u32>,
    pub lt: Option<u32>,
    pub lte: Option<u32>,
    pub gt: Option<u32>,
    pub gte: Option<u32>,
    pub in_set: Vec<u32>,
    pub not_in: Vec<u32>,
}

#[derive(Debug)]
pub struct Uint64Standard {
    pub r#const: Option<u64>,
    pub lt: Option<u64>,
    pub lte: Option<u64>,
    pub gt: Option<u64>,
    pub gte: Option<u64>,
    pub in_set: Vec<u64>,
    pub not_in: Vec<u64>,
}

#[derive(Debug)]
pub struct FloatStandard {
    pub r#const: Option<f32>,
    pub lt: Option<f32>,
    pub lte: Option<f32>,
    pub gt: Option<f32>,
    pub gte: Option<f32>,
    pub in_set: Vec<f32>,
    pub not_in: Vec<f32>,
    pub finite: bool,
}

#[derive(Debug)]
pub struct DoubleStandard {
    pub r#const: Option<f64>,
    pub lt: Option<f64>,
    pub lte: Option<f64>,
    pub gt: Option<f64>,
    pub gte: Option<f64>,
    pub in_set: Vec<f64>,
    pub not_in: Vec<f64>,
    pub finite: bool,
}

#[derive(Debug)]
pub struct BoolStandard {
    pub r#const: Option<bool>,
}

#[derive(Debug)]
pub struct EnumStandard {
    pub r#const: Option<i32>,
    pub defined_only: Option<bool>,
    pub in_set: Vec<i32>,
    pub not_in: Vec<i32>,
}

#[derive(Debug)]
pub struct RepeatedStandard {
    pub min_items: Option<u64>,
    pub max_items: Option<u64>,
    pub unique: Option<bool>,
    pub items: Option<Box<FieldValidator>>,
}

#[derive(Debug)]
pub struct MapStandard {
    pub min_pairs: Option<u64>,
    pub max_pairs: Option<u64>,
    pub keys: Option<Box<FieldValidator>>,
    pub values: Option<Box<FieldValidator>>,
}

// ─── Predefined-rule extensions ──────────────────────────────────────────────

/// Metadata about a predefined-rule extension targeting a buf.validate rule type.
///
/// Targets `Int32Rules`, `FloatRules`, `StringRules`, etc. Captured from extension
/// declarations across all proto files in the `CodeGeneratorRequest`.
#[derive(Debug, Clone)]
pub struct PredefinedExt {
    pub extendee: String,
    pub number: u32,
    pub name: String,
    /// Proto type of the extension value (e.g. TYPE_INT32, TYPE_FLOAT, TYPE_MESSAGE).
    pub proto_type: field_descriptor_proto::Type,
    /// For message-typed extensions the referenced type name.
    pub type_name: String,
    /// repeated / optional label.
    pub label: field_descriptor_proto::Label,
    /// CEL rules declared on this extension via `(buf.validate.predefined).cel`.
    pub cel: Vec<CelRule>,
}

/// Keyed by `(extendee_fqn_without_dot, number)`.
pub type PredefinedExtRegistry = std::collections::HashMap<(String, u32), PredefinedExt>;

fn collect_predefined_extensions(req: &CodeGeneratorRequest) -> PredefinedExtRegistry {
    use protovalidate_buffa_protos::buf::validate::{PredefinedRules, PREDEFINED};
    fn walk_messages<F: FnMut(&FieldDescriptorProto)>(msgs: &[DescriptorProto], f: &mut F) {
        for m in msgs {
            for e in &m.extension {
                f(e);
            }
            walk_messages(&m.nested_type, f);
        }
    }
    let mut out: PredefinedExtRegistry = PredefinedExtRegistry::default();
    let mut walk = |ext: &FieldDescriptorProto| {
        let Some(extendee) = ext.extendee.as_deref() else {
            return;
        };
        let extendee_clean = extendee.trim_start_matches('.').to_string();
        if !extendee_clean.starts_with("buf.validate.") {
            return;
        }
        let Some(num) = ext.number else {
            return;
        };
        let Some(num_u32) = u32::try_from(num).ok() else {
            return;
        };
        let proto_type = ext
            .r#type
            .unwrap_or(field_descriptor_proto::Type::TYPE_INT32);
        let type_name = ext.type_name.clone().unwrap_or_default();
        let label = ext
            .label
            .unwrap_or(field_descriptor_proto::Label::LABEL_OPTIONAL);
        let name = ext.name.clone().unwrap_or_default();
        let pr: Option<PredefinedRules> = ext
            .options
            .as_option()
            .and_then(|o| o.extension(&PREDEFINED));
        let cel = pr
            .as_ref()
            .map(|r| r.cel.iter().filter_map(cel_rule_from).collect())
            .unwrap_or_default();
        out.insert(
            (extendee_clean.clone(), num_u32),
            PredefinedExt {
                extendee: extendee_clean,
                number: num_u32,
                name,
                proto_type,
                type_name,
                label,
                cel,
            },
        );
    };
    for file in &req.proto_file {
        for e in &file.extension {
            walk(e);
        }
        walk_messages(&file.message_type, &mut walk);
    }
    out
}

/// Decode unknown-field extension values on a rule message (e.g., `Int32Rules`)
/// and match them against the `predef` registry to produce `PredefinedCel`
/// entries suitable for emission.
fn scan_predefined_on(
    extendee_fqn: &str,
    unknown: &buffa::UnknownFields,
    predef: &PredefinedExtRegistry,
) -> Vec<PredefinedCel> {
    use buffa::unknown_fields::UnknownFieldData;
    // Group repeated extension values by number so we can emit a single CEL
    // rule with `rule` bound to a list.
    let mut repeated_groups: std::collections::BTreeMap<u32, Vec<String>> =
        std::collections::BTreeMap::default();
    for uf in unknown {
        let Some(meta) = predef.get(&(extendee_fqn.to_string(), uf.number)) else {
            continue;
        };
        if meta.cel.is_empty() {
            continue;
        }
        if meta.label == field_descriptor_proto::Label::LABEL_REPEATED {
            // For packed: LengthDelimited contains a sequence of varints/fixed values.
            // For non-packed: each element shows as its own UnknownField.
            let elems = decode_repeated_element(meta, &uf.data);
            for e in elems {
                repeated_groups.entry(uf.number).or_default().push(e);
            }
        }
    }
    let mut out = Vec::new();
    // Emit repeated rules first (one CEL per extension number, value = list).
    for (num, elems) in &repeated_groups {
        let Some(meta) = predef.get(&(extendee_fqn.to_string(), *num)) else {
            continue;
        };
        if meta.cel.is_empty() {
            continue;
        }
        let items = elems.join(", ");
        let rule_value_expr = format!(
            "::protovalidate_buffa::cel_interpreter::Value::List(::std::sync::Arc::new(::std::vec![{items}]))"
        );
        let ext_ty_name = ext_type_name(meta.proto_type);
        for rule in &meta.cel {
            out.push(PredefinedCel {
                id: rule.id.clone(),
                message: rule.message.clone(),
                expression: rule.expression.clone(),
                rule_value_expr: rule_value_expr.clone(),
                ext_number: meta.number as i32,
                ext_name: meta.name.clone(),
                ext_field_type: ext_ty_name.to_string(),
                family_override: override_for_extendee(&meta.extendee),
            });
        }
    }
    for uf in unknown {
        let Some(meta) = predef.get(&(extendee_fqn.to_string(), uf.number)) else {
            continue;
        };
        if meta.cel.is_empty() {
            continue;
        }
        if meta.label == field_descriptor_proto::Label::LABEL_REPEATED {
            continue;
        }
        // Decode the value based on label + proto type.
        let rule_value_expr = match (meta.label, meta.proto_type, &uf.data) {
            (_, field_descriptor_proto::Type::TYPE_BOOL, UnknownFieldData::Varint(v)) => {
                format!(
                    "::protovalidate_buffa::cel_interpreter::Value::Bool({})",
                    *v != 0
                )
            }
            (
                field_descriptor_proto::Label::LABEL_OPTIONAL,
                field_descriptor_proto::Type::TYPE_INT32,
                UnknownFieldData::Varint(v),
            ) => {
                format!(
                    "::protovalidate_buffa::cel_interpreter::Value::Int({} as i64)",
                    *v as i32
                )
            }
            (
                field_descriptor_proto::Label::LABEL_OPTIONAL,
                field_descriptor_proto::Type::TYPE_INT64
                | field_descriptor_proto::Type::TYPE_SINT64
                | field_descriptor_proto::Type::TYPE_SFIXED64,
                UnknownFieldData::Varint(v),
            ) => {
                format!(
                    "::protovalidate_buffa::cel_interpreter::Value::Int({}i64)",
                    *v as i64
                )
            }
            (
                field_descriptor_proto::Label::LABEL_OPTIONAL,
                field_descriptor_proto::Type::TYPE_UINT32,
                UnknownFieldData::Varint(v),
            ) => {
                format!(
                    "::protovalidate_buffa::cel_interpreter::Value::UInt({}u64)",
                    *v as u32
                )
            }
            (
                field_descriptor_proto::Label::LABEL_OPTIONAL,
                field_descriptor_proto::Type::TYPE_UINT64
                | field_descriptor_proto::Type::TYPE_FIXED64,
                UnknownFieldData::Varint(v),
            ) => {
                format!(
                    "::protovalidate_buffa::cel_interpreter::Value::UInt({}u64)",
                    *v
                )
            }
            (
                field_descriptor_proto::Label::LABEL_OPTIONAL,
                field_descriptor_proto::Type::TYPE_FLOAT,
                UnknownFieldData::Fixed32(v),
            ) => {
                format!("::protovalidate_buffa::cel_interpreter::Value::Float(f32::from_bits({}u32) as f64)", *v)
            }
            (
                field_descriptor_proto::Label::LABEL_OPTIONAL,
                field_descriptor_proto::Type::TYPE_DOUBLE,
                UnknownFieldData::Fixed64(v),
            ) => {
                format!(
                    "::protovalidate_buffa::cel_interpreter::Value::Float(f64::from_bits({}u64))",
                    *v
                )
            }
            (
                field_descriptor_proto::Label::LABEL_OPTIONAL,
                field_descriptor_proto::Type::TYPE_STRING,
                UnknownFieldData::LengthDelimited(data),
            ) => {
                let s = String::from_utf8_lossy(data).to_string();
                format!("::protovalidate_buffa::cel_interpreter::Value::String(::std::sync::Arc::new({s:?}.to_string()))")
            }
            _ => continue,
        };
        // Map proto type → FieldType variant name for rule-path metadata.
        let ext_ty_name = ext_type_name(meta.proto_type);
        let _ = ext_ty_name;
        let ext_ty_name = match meta.proto_type {
            field_descriptor_proto::Type::TYPE_INT32 => "Int32",
            field_descriptor_proto::Type::TYPE_INT64 => "Int64",
            field_descriptor_proto::Type::TYPE_UINT32 => "Uint32",
            field_descriptor_proto::Type::TYPE_UINT64 => "Uint64",
            field_descriptor_proto::Type::TYPE_SINT32 => "Sint32",
            field_descriptor_proto::Type::TYPE_SINT64 => "Sint64",
            field_descriptor_proto::Type::TYPE_FIXED32 => "Fixed32",
            field_descriptor_proto::Type::TYPE_FIXED64 => "Fixed64",
            field_descriptor_proto::Type::TYPE_SFIXED32 => "Sfixed32",
            field_descriptor_proto::Type::TYPE_SFIXED64 => "Sfixed64",
            field_descriptor_proto::Type::TYPE_FLOAT => "Float",
            field_descriptor_proto::Type::TYPE_DOUBLE => "Double",
            field_descriptor_proto::Type::TYPE_BOOL => "Bool",
            field_descriptor_proto::Type::TYPE_STRING => "String",
            field_descriptor_proto::Type::TYPE_BYTES => "Bytes",
            field_descriptor_proto::Type::TYPE_MESSAGE
            | field_descriptor_proto::Type::TYPE_GROUP => "Message",
            field_descriptor_proto::Type::TYPE_ENUM => "Enum",
        };
        for rule in &meta.cel {
            out.push(PredefinedCel {
                id: rule.id.clone(),
                message: rule.message.clone(),
                expression: rule.expression.clone(),
                rule_value_expr: rule_value_expr.clone(),
                ext_number: meta.number as i32,
                ext_name: meta.name.clone(),
                ext_field_type: ext_ty_name.to_string(),
                family_override: override_for_extendee(&meta.extendee),
            });
        }
    }
    out
}

fn populate_predefined(out: &mut StandardRules, fr: &FieldRules, predef: &PredefinedExtRegistry) {
    use protovalidate_buffa_protos::buf::validate::field_rules;
    let Some(ty) = fr.r#type.as_ref() else { return };
    let (extendee, unknown): (&str, &buffa::UnknownFields) = match ty {
        field_rules::Type::Float(r) => ("buf.validate.FloatRules", &r.__buffa_unknown_fields),
        field_rules::Type::Double(r) => ("buf.validate.DoubleRules", &r.__buffa_unknown_fields),
        field_rules::Type::Int32(r) => ("buf.validate.Int32Rules", &r.__buffa_unknown_fields),
        field_rules::Type::Int64(r) => ("buf.validate.Int64Rules", &r.__buffa_unknown_fields),
        field_rules::Type::Uint32(r) => ("buf.validate.UInt32Rules", &r.__buffa_unknown_fields),
        field_rules::Type::Uint64(r) => ("buf.validate.UInt64Rules", &r.__buffa_unknown_fields),
        field_rules::Type::Sint32(r) => ("buf.validate.SInt32Rules", &r.__buffa_unknown_fields),
        field_rules::Type::Sint64(r) => ("buf.validate.SInt64Rules", &r.__buffa_unknown_fields),
        field_rules::Type::Fixed32(r) => ("buf.validate.Fixed32Rules", &r.__buffa_unknown_fields),
        field_rules::Type::Fixed64(r) => ("buf.validate.Fixed64Rules", &r.__buffa_unknown_fields),
        field_rules::Type::Sfixed32(r) => ("buf.validate.SFixed32Rules", &r.__buffa_unknown_fields),
        field_rules::Type::Sfixed64(r) => ("buf.validate.SFixed64Rules", &r.__buffa_unknown_fields),
        field_rules::Type::Bool(r) => ("buf.validate.BoolRules", &r.__buffa_unknown_fields),
        field_rules::Type::String(r) => ("buf.validate.StringRules", &r.__buffa_unknown_fields),
        field_rules::Type::Bytes(r) => ("buf.validate.BytesRules", &r.__buffa_unknown_fields),
        field_rules::Type::Enum(r) => ("buf.validate.EnumRules", &r.__buffa_unknown_fields),
        field_rules::Type::Duration(r) => ("buf.validate.DurationRules", &r.__buffa_unknown_fields),
        field_rules::Type::Timestamp(r) => {
            ("buf.validate.TimestampRules", &r.__buffa_unknown_fields)
        }
        field_rules::Type::Any(r) => ("buf.validate.AnyRules", &r.__buffa_unknown_fields),
        field_rules::Type::FieldMask(r) => {
            ("buf.validate.FieldMaskRules", &r.__buffa_unknown_fields)
        }
        field_rules::Type::Repeated(r) => ("buf.validate.RepeatedRules", &r.__buffa_unknown_fields),
        field_rules::Type::Map(r) => ("buf.validate.MapRules", &r.__buffa_unknown_fields),
    };
    let rules = scan_predefined_on(extendee, unknown, predef);
    if rules.is_empty() {
        return;
    }
    out.predefined.extend(rules);
}

fn override_for_extendee(extendee: &str) -> Option<(&'static str, i32)> {
    match extendee {
        "buf.validate.RepeatedRules" => Some(("repeated", 18)),
        "buf.validate.MapRules" => Some(("map", 19)),
        _ => None,
    }
}

const fn ext_type_name(t: field_descriptor_proto::Type) -> &'static str {
    match t {
        field_descriptor_proto::Type::TYPE_INT32 => "Int32",
        field_descriptor_proto::Type::TYPE_INT64 => "Int64",
        field_descriptor_proto::Type::TYPE_UINT32 => "Uint32",
        field_descriptor_proto::Type::TYPE_UINT64 => "Uint64",
        field_descriptor_proto::Type::TYPE_SINT32 => "Sint32",
        field_descriptor_proto::Type::TYPE_SINT64 => "Sint64",
        field_descriptor_proto::Type::TYPE_FIXED32 => "Fixed32",
        field_descriptor_proto::Type::TYPE_FIXED64 => "Fixed64",
        field_descriptor_proto::Type::TYPE_SFIXED32 => "Sfixed32",
        field_descriptor_proto::Type::TYPE_SFIXED64 => "Sfixed64",
        field_descriptor_proto::Type::TYPE_FLOAT => "Float",
        field_descriptor_proto::Type::TYPE_DOUBLE => "Double",
        field_descriptor_proto::Type::TYPE_BOOL => "Bool",
        field_descriptor_proto::Type::TYPE_STRING => "String",
        field_descriptor_proto::Type::TYPE_BYTES => "Bytes",
        field_descriptor_proto::Type::TYPE_MESSAGE | field_descriptor_proto::Type::TYPE_GROUP => {
            "Message"
        }
        field_descriptor_proto::Type::TYPE_ENUM => "Enum",
    }
}

/// Decode a single element of a repeated extension field from its UnknownFieldData.
/// For packed (LengthDelimited) repeated, multiple elements may be in one entry;
/// this function returns each as a CEL Value expression.
fn decode_repeated_element(
    meta: &PredefinedExt,
    data: &buffa::unknown_fields::UnknownFieldData,
) -> Vec<String> {
    use buffa::unknown_fields::UnknownFieldData;
    use field_descriptor_proto::Type;
    let mut out = Vec::new();
    match (meta.proto_type, data) {
        (
            Type::TYPE_INT32
            | Type::TYPE_INT64
            | Type::TYPE_UINT32
            | Type::TYPE_UINT64
            | Type::TYPE_BOOL
            | Type::TYPE_ENUM,
            UnknownFieldData::Varint(v),
        ) => {
            let expr = scalar_to_cel_value_expr(meta.proto_type, Some(*v), None, None, None);
            out.push(expr);
        }
        (Type::TYPE_SINT32 | Type::TYPE_SINT64, UnknownFieldData::Varint(v)) => {
            // zigzag decode
            let s = ((*v >> 1) as i64) ^ -((*v & 1) as i64);
            out.push(format!(
                "::protovalidate_buffa::cel_interpreter::Value::Int({s}i64)"
            ));
        }
        (Type::TYPE_FIXED32 | Type::TYPE_SFIXED32, UnknownFieldData::Fixed32(v)) => {
            out.push(scalar_to_cel_value_expr(
                meta.proto_type,
                None,
                Some(*v as u64),
                None,
                None,
            ));
        }
        (Type::TYPE_FIXED64 | Type::TYPE_SFIXED64, UnknownFieldData::Fixed64(v)) => {
            out.push(scalar_to_cel_value_expr(
                meta.proto_type,
                None,
                Some(*v),
                None,
                None,
            ));
        }
        (Type::TYPE_FLOAT, UnknownFieldData::Fixed32(v)) => {
            let v = *v;
            out.push(format!("::protovalidate_buffa::cel_interpreter::Value::Float(f32::from_bits({v}u32) as f64)"));
        }
        (Type::TYPE_DOUBLE, UnknownFieldData::Fixed64(v)) => {
            let v = *v;
            out.push(format!(
                "::protovalidate_buffa::cel_interpreter::Value::Float(f64::from_bits({v}u64))"
            ));
        }
        (Type::TYPE_STRING, UnknownFieldData::LengthDelimited(data)) => {
            let s = String::from_utf8_lossy(data).to_string();
            out.push(format!("::protovalidate_buffa::cel_interpreter::Value::String(::std::sync::Arc::new({s:?}.to_string()))"));
        }
        (Type::TYPE_BYTES, UnknownFieldData::LengthDelimited(data)) => {
            let b: Vec<u8> = data.clone();
            out.push(format!("::protovalidate_buffa::cel_interpreter::Value::Bytes(::std::sync::Arc::new(vec!{b:?}))"));
        }
        // Wrapper types (e.g. google.protobuf.Int64Value) — decode the inner
        // .value field (field 1). The wire format for an Int64Value{value:3}
        // is tag(1, Varint) + 0x03.
        (Type::TYPE_MESSAGE, UnknownFieldData::LengthDelimited(data)) => {
            let inner_ty = wrapper_inner_type(&meta.type_name);
            if let Some(t) = inner_ty {
                // Find first field of tag 1 in the inner bytes.
                if let Some(val) = decode_wrapper_value(t, data.as_slice()) {
                    out.push(val);
                }
            }
        }
        // Packed repeated numeric.
        (_, UnknownFieldData::LengthDelimited(data)) => {
            let mut buf: &[u8] = data.as_slice();
            while !buf.is_empty() {
                match meta.proto_type {
                    Type::TYPE_INT32
                    | Type::TYPE_INT64
                    | Type::TYPE_UINT32
                    | Type::TYPE_UINT64
                    | Type::TYPE_BOOL
                    | Type::TYPE_ENUM => {
                        let Some((v, rest)) = varint_decode(buf) else {
                            break;
                        };
                        out.push(scalar_to_cel_value_expr(
                            meta.proto_type,
                            Some(v),
                            None,
                            None,
                            None,
                        ));
                        buf = rest;
                    }
                    Type::TYPE_SINT32 | Type::TYPE_SINT64 => {
                        let Some((v, rest)) = varint_decode(buf) else {
                            break;
                        };
                        let s = ((v >> 1) as i64) ^ -((v & 1) as i64);
                        out.push(format!(
                            "::protovalidate_buffa::cel_interpreter::Value::Int({s}i64)"
                        ));
                        buf = rest;
                    }
                    Type::TYPE_FIXED32 | Type::TYPE_SFIXED32 => {
                        if buf.len() < 4 {
                            break;
                        }
                        let v = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                        out.push(scalar_to_cel_value_expr(
                            meta.proto_type,
                            None,
                            Some(v as u64),
                            None,
                            None,
                        ));
                        buf = &buf[4..];
                    }
                    Type::TYPE_FIXED64 | Type::TYPE_SFIXED64 => {
                        if buf.len() < 8 {
                            break;
                        }
                        let v = u64::from_le_bytes([
                            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                        ]);
                        out.push(scalar_to_cel_value_expr(
                            meta.proto_type,
                            None,
                            Some(v),
                            None,
                            None,
                        ));
                        buf = &buf[8..];
                    }
                    Type::TYPE_FLOAT => {
                        if buf.len() < 4 {
                            break;
                        }
                        let v = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                        out.push(format!("::protovalidate_buffa::cel_interpreter::Value::Float(f32::from_bits({v}u32) as f64)"));
                        buf = &buf[4..];
                    }
                    Type::TYPE_DOUBLE => {
                        if buf.len() < 8 {
                            break;
                        }
                        let v = u64::from_le_bytes([
                            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                        ]);
                        out.push(format!("::protovalidate_buffa::cel_interpreter::Value::Float(f64::from_bits({v}u64))"));
                        buf = &buf[8..];
                    }
                    _ => break,
                }
            }
        }
        _ => {}
    }
    out
}

fn scalar_to_cel_value_expr(
    ty: field_descriptor_proto::Type,
    varint: Option<u64>,
    fixed: Option<u64>,
    _len: Option<&[u8]>,
    _str_: Option<&str>,
) -> String {
    use field_descriptor_proto::Type;
    match ty {
        Type::TYPE_INT32 => format!(
            "::protovalidate_buffa::cel_interpreter::Value::Int({} as i64)",
            varint.unwrap_or(0) as i32
        ),
        Type::TYPE_INT64 | Type::TYPE_SFIXED64 => format!(
            "::protovalidate_buffa::cel_interpreter::Value::Int({}i64)",
            fixed.or(varint).unwrap_or(0) as i64
        ),
        Type::TYPE_UINT32 => format!(
            "::protovalidate_buffa::cel_interpreter::Value::UInt({}u64)",
            varint.unwrap_or(0) as u32
        ),
        Type::TYPE_UINT64 | Type::TYPE_FIXED64 => format!(
            "::protovalidate_buffa::cel_interpreter::Value::UInt({}u64)",
            fixed.or(varint).unwrap_or(0)
        ),
        Type::TYPE_FIXED32 => format!(
            "::protovalidate_buffa::cel_interpreter::Value::UInt({}u64)",
            fixed.unwrap_or(0) as u32
        ),
        Type::TYPE_SFIXED32 => format!(
            "::protovalidate_buffa::cel_interpreter::Value::Int({}i64)",
            fixed.unwrap_or(0) as i32
        ),
        Type::TYPE_BOOL => format!(
            "::protovalidate_buffa::cel_interpreter::Value::Bool({})",
            varint.unwrap_or(0) != 0
        ),
        Type::TYPE_ENUM => format!(
            "::protovalidate_buffa::cel_interpreter::Value::Int({}i64)",
            varint.unwrap_or(0) as i32
        ),
        _ => "::protovalidate_buffa::cel_interpreter::Value::Null".to_string(),
    }
}

fn wrapper_inner_type(type_name: &str) -> Option<field_descriptor_proto::Type> {
    use field_descriptor_proto::Type;
    let name = type_name.trim_start_matches('.');
    match name {
        "google.protobuf.FloatValue" => Some(Type::TYPE_FLOAT),
        "google.protobuf.DoubleValue" => Some(Type::TYPE_DOUBLE),
        "google.protobuf.Int32Value" => Some(Type::TYPE_INT32),
        "google.protobuf.Int64Value" => Some(Type::TYPE_INT64),
        "google.protobuf.UInt32Value" => Some(Type::TYPE_UINT32),
        "google.protobuf.UInt64Value" => Some(Type::TYPE_UINT64),
        "google.protobuf.BoolValue" => Some(Type::TYPE_BOOL),
        "google.protobuf.StringValue" => Some(Type::TYPE_STRING),
        "google.protobuf.BytesValue" => Some(Type::TYPE_BYTES),
        _ => None,
    }
}

fn decode_wrapper_value(ty: field_descriptor_proto::Type, bytes: &[u8]) -> Option<String> {
    use field_descriptor_proto::Type;
    // Look for tag (field 1, wire type depends on ty).
    let mut buf = bytes;
    while !buf.is_empty() {
        let (tag, rest) = varint_decode(buf)?;
        let field_num = tag >> 3;
        let wire_type = tag & 0x7;
        buf = rest;
        if field_num != 1 {
            // Skip unknown field of this wire type.
            match wire_type {
                0 => {
                    let (_, r) = varint_decode(buf)?;
                    buf = r;
                }
                1 => {
                    if buf.len() < 8 {
                        return None;
                    }
                    buf = &buf[8..];
                }
                2 => {
                    let (len, r) = varint_decode(buf)?;
                    let len = len as usize;
                    if r.len() < len {
                        return None;
                    }
                    buf = &r[len..];
                }
                5 => {
                    if buf.len() < 4 {
                        return None;
                    }
                    buf = &buf[4..];
                }
                _ => return None,
            }
            continue;
        }
        // Field 1 — decode based on ty.
        return match ty {
            Type::TYPE_INT32
            | Type::TYPE_INT64
            | Type::TYPE_UINT32
            | Type::TYPE_UINT64
            | Type::TYPE_BOOL => {
                let (v, _) = varint_decode(buf)?;
                Some(scalar_to_cel_value_expr(ty, Some(v), None, None, None))
            }
            Type::TYPE_FLOAT => {
                if buf.len() < 4 {
                    return None;
                }
                let v = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                Some(format!("::protovalidate_buffa::cel_interpreter::Value::Float(f32::from_bits({v}u32) as f64)"))
            }
            Type::TYPE_DOUBLE => {
                if buf.len() < 8 {
                    return None;
                }
                let v = u64::from_le_bytes([
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                ]);
                Some(format!(
                    "::protovalidate_buffa::cel_interpreter::Value::Float(f64::from_bits({v}u64))"
                ))
            }
            Type::TYPE_STRING => {
                let (len, r) = varint_decode(buf)?;
                let len = len as usize;
                if r.len() < len {
                    return None;
                }
                let s = String::from_utf8_lossy(&r[..len]).to_string();
                Some(format!("::protovalidate_buffa::cel_interpreter::Value::String(::std::sync::Arc::new({s:?}.to_string()))"))
            }
            Type::TYPE_BYTES => {
                let (len, r) = varint_decode(buf)?;
                let len = len as usize;
                if r.len() < len {
                    return None;
                }
                let bytes: Vec<u8> = r[..len].to_vec();
                Some(format!("::protovalidate_buffa::cel_interpreter::Value::Bytes(::std::sync::Arc::new(vec!{bytes:?}))"))
            }
            _ => None,
        };
    }
    None
}

/// Decode a single protobuf varint from the front of `buf`, returning the
/// value plus the remaining tail. Thin wrapper around
/// [`buffa::encoding::decode_varint`] so we don't re-implement wire-format
/// parsing.
fn varint_decode(buf: &[u8]) -> Option<(u64, &[u8])> {
    let mut cursor: &[u8] = buf;
    let v = ::buffa::encoding::decode_varint(&mut cursor).ok()?;
    Some((v, cursor))
}

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Walk a `CodeGeneratorRequest` and return one `MessageValidators` per
/// message (including nested) in every file listed in `file_to_generate`.
///
/// # Errors
///
/// Returns an error if a field's type cannot be classified, if an unsupported
/// rule family (e.g. `Any`, `Duration`) is encountered, or if a proto type
/// cannot be parsed into the expected format.
pub fn gather(request: &CodeGeneratorRequest) -> anyhow::Result<Vec<MessageValidators>> {
    let generate_set: std::collections::HashSet<&str> = request
        .file_to_generate
        .iter()
        .map(std::string::String::as_str)
        .collect();

    // First pass — collect predefined-rule extensions from ALL proto files
    // (not just those in file_to_generate) so rules defined in imports apply.
    let predefined_exts = collect_predefined_extensions(request);

    let mut out = Vec::new();
    for file in &request.proto_file {
        let file_name = file.name.as_deref().unwrap_or("");
        if !generate_set.contains(file_name) {
            continue;
        }
        let package = file.package.as_deref().unwrap_or("").to_string();
        for msg in &file.message_type {
            gather_message(
                file,
                file_name,
                &package,
                "",
                msg,
                &mut out,
                &predefined_exts,
            )?;
        }
    }
    Ok(out)
}

// ─── Message recursion ───────────────────────────────────────────────────────

fn gather_message(
    file: &FileDescriptorProto,
    source_file: &str,
    package: &str,
    parent: &str,
    msg: &DescriptorProto,
    out: &mut Vec<MessageValidators>,
    predef: &PredefinedExtRegistry,
) -> anyhow::Result<()> {
    let msg_name = msg.name.as_deref().unwrap_or("");

    // Skip synthetic map-entry messages — they have no user-visible validators.
    if msg
        .options
        .as_option()
        .and_then(|o| o.map_entry)
        .unwrap_or(false)
    {
        return Ok(());
    }

    let qualified_name = if parent.is_empty() {
        if package.is_empty() {
            msg_name.to_string()
        } else {
            format!("{package}.{msg_name}")
        }
    } else {
        format!("{parent}.{msg_name}")
    };

    // Message-level rules.
    let message_extension = msg
        .options
        .as_option()
        .and_then(|o: &buffa_codegen::generated::descriptor::MessageOptions| o.extension(&MESSAGE));
    let message_cel = message_extension
        .as_ref()
        .map(extract_message_cel)
        .unwrap_or_default();
    let message_oneofs: Vec<MessageOneofSpec> = message_extension
        .as_ref()
        .map(|mr| {
            mr.oneof
                .iter()
                .map(|o| MessageOneofSpec {
                    fields: o.fields.clone(),
                    required: o.required.unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default();

    // Field rules.
    let mut field_rules_out = Vec::new();
    for field in &msg.field {
        let fv = gather_field(file, msg, field, &qualified_name, predef)
            .map_err(|e| anyhow!("{qualified_name}, field {:?}: {e}", field.name))?;
        field_rules_out.push(fv);
    }

    // Oneof rules — only "real" oneofs (not synthetic proto3-optional oneofs).
    let mut oneof_rules_out = Vec::new();
    for (idx, oneof) in msg.oneof_decl.iter().enumerate() {
        // A synthetic oneof has exactly one field whose oneof_index == idx
        // and that field has proto3_optional == true.
        let is_synthetic = msg.field.iter().any(|f| {
            f.oneof_index == Some(i32::try_from(idx).expect("oneof index fits in i32"))
                && f.proto3_optional.unwrap_or(false)
        });
        if is_synthetic {
            continue;
        }
        // Collect per-variant field validators for this oneof.
        let variant_fields: Vec<FieldValidator> = msg
            .field
            .iter()
            .filter(|f| f.oneof_index == Some(i32::try_from(idx).expect("oneof index fits in i32")))
            .map(|f| gather_field(file, msg, f, &qualified_name, predef))
            .collect::<anyhow::Result<_>>()?;
        let ov = gather_oneof(msg_name, oneof, variant_fields);
        oneof_rules_out.push(ov);
    }

    // Detect rule-type / field-type mismatches → stub the entire message
    // Validate impl with a compilation error marker.
    let compile_error = field_rules_out
        .iter()
        .find_map(|f| check_rule_field_mismatch(&f.field_type, &f.standard))
        .or_else(|| check_message_oneof_specs(&qualified_name, &message_oneofs, &field_rules_out))
        .or_else(|| check_message_cel_missing_fields(&message_cel, &field_rules_out));

    out.push(MessageValidators {
        proto_name: qualified_name.clone(),
        package: package.to_string(),
        source_file: source_file.to_string(),
        message_cel,
        message_oneofs,
        field_rules: field_rules_out,
        oneof_rules: oneof_rules_out,
        compile_error,
    });

    // Recurse into nested messages.
    for nested in &msg.nested_type {
        gather_message(
            file,
            source_file,
            package,
            &qualified_name,
            nested,
            out,
            predef,
        )?;
    }

    Ok(())
}

/// Check whether the field's rule family matches its declared type.
/// Returns `Some(reason)` when a mismatch is detected, else `None`.
fn check_rule_field_mismatch(kind: &FieldKind, s: &StandardRules) -> Option<String> {
    // Unwrap through Optional/Wrapper for the underlying scalar.
    let underlying: &FieldKind = match kind {
        FieldKind::Optional(inner) | FieldKind::Wrapper(inner) => inner,
        other => other,
    };
    // For each rule family that is Some, verify the underlying kind matches.
    let mismatch = |family: &str| -> String {
        format!("{family} rules on {} field", kind_family_name(underlying))
    };
    if s.float.is_some() && !matches!(underlying, FieldKind::Float) {
        return Some(mismatch("float"));
    }
    if s.double.is_some() && !matches!(underlying, FieldKind::Double) {
        return Some(mismatch("double"));
    }
    if s.int32.is_some()
        && !matches!(
            underlying,
            FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32
        )
    {
        return Some(mismatch("int32"));
    }
    if s.int64.is_some()
        && !matches!(
            underlying,
            FieldKind::Int64 | FieldKind::Sint64 | FieldKind::Sfixed64
        )
    {
        return Some(mismatch("int64"));
    }
    if s.uint32.is_some() && !matches!(underlying, FieldKind::Uint32 | FieldKind::Fixed32) {
        return Some(mismatch("uint32"));
    }
    if s.uint64.is_some() && !matches!(underlying, FieldKind::Uint64 | FieldKind::Fixed64) {
        return Some(mismatch("uint64"));
    }
    if s.bool_rules.is_some() && !matches!(underlying, FieldKind::Bool) {
        return Some(mismatch("bool"));
    }
    if s.string.is_some() && !matches!(underlying, FieldKind::String) {
        return Some(mismatch("string"));
    }
    if s.bytes.is_some() && !matches!(underlying, FieldKind::Bytes) {
        return Some(mismatch("bytes"));
    }
    if s.enum_rules.is_some() && !matches!(underlying, FieldKind::Enum { .. }) {
        return Some(mismatch("enum"));
    }
    if s.repeated.is_some() && !matches!(kind, FieldKind::Repeated(_)) {
        return Some(mismatch("repeated"));
    }
    if s.map.is_some() && !matches!(kind, FieldKind::Map { .. }) {
        return Some(mismatch("map"));
    }
    if s.any_rules.is_some()
        && !matches!(underlying, FieldKind::Message { full_name } if full_name == "google.protobuf.Any")
    {
        return Some(mismatch("any"));
    }
    if s.duration.is_some()
        && !matches!(underlying, FieldKind::Message { full_name } if full_name == "google.protobuf.Duration")
    {
        return Some(mismatch("duration"));
    }
    if s.timestamp.is_some()
        && !matches!(underlying, FieldKind::Message { full_name } if full_name == "google.protobuf.Timestamp")
    {
        return Some(mismatch("timestamp"));
    }
    None
}

/// Scan message-level CEL expressions for top-level `this.<ident>` field
/// references that don't match a known field name on the message. A `this.foo`
/// access where `foo` isn't a field on the message is a compile-time error
/// per protovalidate's schema-aware validator.
fn check_message_cel_missing_fields(cels: &[CelRule], fields: &[FieldValidator]) -> Option<String> {
    let names: std::collections::HashSet<&str> =
        fields.iter().map(|f| f.field_name.as_str()).collect();
    for rule in cels {
        let bytes = rule.expression.as_bytes();
        let mut i = 0;
        while i + 5 <= bytes.len() {
            if &bytes[i..i + 5] == b"this." {
                // Verify this isn't part of a longer identifier.
                if i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_') {
                    i += 1;
                    continue;
                }
                let mut j = i + 5;
                let start = j;
                while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                if j > start {
                    let ident = std::str::from_utf8(&bytes[start..j]).unwrap_or("");
                    if !names.contains(ident) {
                        return Some(format!(
                            "expression references a non-existent field {ident}"
                        ));
                    }
                }
                i = j;
            } else {
                i += 1;
            }
        }
    }
    None
}

fn check_message_oneof_specs(
    msg_fqn: &str,
    specs: &[MessageOneofSpec],
    fields: &[FieldValidator],
) -> Option<String> {
    let field_names: std::collections::HashSet<&str> =
        fields.iter().map(|f| f.field_name.as_str()).collect();
    for spec in specs {
        if spec.fields.is_empty() {
            return Some(format!(
                "at least one field must be specified in oneof rule for the message {msg_fqn}"
            ));
        }
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for name in &spec.fields {
            if !field_names.contains(name.as_str()) {
                return Some(format!("field {name} not found in message {msg_fqn}"));
            }
            if !seen.insert(name.as_str()) {
                return Some(format!(
                    "duplicate {name} in oneof rule for the message {msg_fqn}"
                ));
            }
        }
    }
    None
}

const fn kind_family_name(k: &FieldKind) -> &'static str {
    match k {
        FieldKind::Float => "float",
        FieldKind::Double => "double",
        FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32 => "int32",
        FieldKind::Int64 | FieldKind::Sint64 | FieldKind::Sfixed64 => "int64",
        FieldKind::Uint32 | FieldKind::Fixed32 => "uint32",
        FieldKind::Uint64 | FieldKind::Fixed64 => "uint64",
        FieldKind::Bool => "bool",
        FieldKind::String => "string",
        FieldKind::Bytes => "bytes",
        FieldKind::Enum { .. } => "enum",
        FieldKind::Message { .. } => "message",
        FieldKind::Repeated(_) => "repeated",
        FieldKind::Map { .. } => "map",
        FieldKind::Optional(_) => "optional",
        FieldKind::Wrapper(_) => "wrapper",
    }
}

// ─── Field ───────────────────────────────────────────────────────────────────

fn gather_field(
    file: &FileDescriptorProto,
    msg: &DescriptorProto,
    field: &FieldDescriptorProto,
    _qualified_name: &str,
    predef: &PredefinedExtRegistry,
) -> anyhow::Result<FieldValidator> {
    let rules: Option<FieldRules> = field
        .options
        .as_option()
        .and_then(|o: &buffa_codegen::generated::descriptor::FieldOptions| o.extension(&FIELD));

    let required = rules.as_ref().and_then(|r| r.required).unwrap_or(false);
    let ignore = rules
        .as_ref()
        .and_then(|r| r.ignore)
        .map_or(Ignore::Unspecified, map_ignore);

    let cel = rules.as_ref().map(extract_field_cel).unwrap_or_default();

    let mut standard = rules
        .as_ref()
        .map(|r| parse_standard(r, predef))
        .transpose()?
        .unwrap_or_default();
    // Collect predefined rules from unknown_fields of each rule family.
    if let Some(fr) = rules.as_ref() {
        populate_predefined(&mut standard, fr, predef);
    }

    let field_type = classify_field(file, msg, field)?;

    // Determine oneof membership. A field is in a real oneof if it has an
    // `oneof_index` AND that oneof is not a synthetic proto3-optional one.
    let oneof_index = field.oneof_index;
    let oneof_name = oneof_index.and_then(|idx| {
        let oneof = msg.oneof_decl.get(usize::try_from(idx).ok()?)?;
        // A synthetic proto3-optional oneof has exactly one field with
        // `proto3_optional == true`. We skip those — they're not real oneofs.
        let is_synthetic = msg
            .field
            .iter()
            .any(|f| f.oneof_index == Some(idx) && f.proto3_optional.unwrap_or(false));
        if is_synthetic {
            return None;
        }
        Some(oneof.name.as_deref().unwrap_or("").to_string())
    });

    // Detect "legacy required" semantics — fields stored as plain T but with
    // explicit presence: proto2 LABEL_REQUIRED, editions LEGACY_REQUIRED.
    let is_proto2_file =
        !matches!(file.syntax.as_deref(), Some("proto3" | "editions")) && file.edition.is_none();
    let field_presence_for_check = field
        .options
        .as_option()
        .and_then(|o| o.features.as_option())
        .and_then(|f| f.field_presence)
        .or_else(|| {
            file.options
                .as_option()
                .and_then(|o| o.features.as_option())
                .and_then(|f| f.field_presence)
        });
    let is_editions_file = file.edition.is_some();
    let is_legacy_required = (is_proto2_file
        && field.label == Some(field_descriptor_proto::Label::LABEL_REQUIRED))
        || (is_editions_file
            && field_presence_for_check == Some(feature_set::FieldPresence::LEGACY_REQUIRED));

    // TYPE_GROUP in proto2, or editions messages with features.message_encoding = DELIMITED.
    let msg_encoding = field
        .options
        .as_option()
        .and_then(|o| o.features.as_option())
        .and_then(|f| f.message_encoding);
    let is_group = field.r#type == Some(field_descriptor_proto::Type::TYPE_GROUP)
        || msg_encoding == Some(feature_set::MessageEncoding::DELIMITED);

    Ok(FieldValidator {
        field_number: field.number.unwrap_or(0),
        field_name: field.name.as_deref().unwrap_or("").to_string(),
        field_type,
        required,
        ignore,
        standard,
        cel,
        oneof_index,
        oneof_name,
        is_legacy_required,
        is_group,
    })
}

// ─── Oneof ───────────────────────────────────────────────────────────────────

fn gather_oneof(
    parent_msg_name: &str,
    oneof: &OneofDescriptorProto,
    fields: Vec<FieldValidator>,
) -> OneofValidator {
    let rules: Option<OneofRules> = oneof
        .options
        .as_option()
        .and_then(|o: &buffa_codegen::generated::descriptor::OneofOptions| o.extension(&ONEOF));

    let required = rules.as_ref().and_then(|r| r.required).unwrap_or(false);

    OneofValidator {
        name: oneof.name.as_deref().unwrap_or("").to_string(),
        required,
        parent_msg_name: parent_msg_name.to_string(),
        fields,
    }
}

// ─── Field classification ────────────────────────────────────────────────────

fn classify_field(
    file: &FileDescriptorProto,
    msg: &DescriptorProto,
    field: &FieldDescriptorProto,
) -> anyhow::Result<FieldKind> {
    use field_descriptor_proto::{Label, Type};

    let label = field.label.unwrap_or(Label::LABEL_OPTIONAL);
    let proto_type = field.r#type.unwrap_or(Type::TYPE_STRING);
    let type_name = field.type_name.as_deref().unwrap_or("");

    // Check for repeated first, then test for map-entry.
    if label == Label::LABEL_REPEATED {
        // Map detection: a `map<K,V>` compiles to a `repeated MessageType` where
        // the referenced MessageType has `option map_entry = true`.
        if proto_type == Type::TYPE_MESSAGE {
            if let Some(inner) = find_map_entry(file, msg, type_name) {
                // inner is the synthetic MapEntry DescriptorProto.
                // field[0] = key, field[1] = value.
                let key_field = inner
                    .field
                    .first()
                    .ok_or_else(|| anyhow!("map entry has no key field"))?;
                let val_field = inner
                    .field
                    .get(1)
                    .ok_or_else(|| anyhow!("map entry has no value field"))?;
                let key_kind = scalar_kind(
                    key_field.r#type.unwrap_or(Type::TYPE_STRING),
                    key_field.type_name.as_deref().unwrap_or(""),
                );
                let val_kind = scalar_kind(
                    val_field.r#type.unwrap_or(Type::TYPE_STRING),
                    val_field.type_name.as_deref().unwrap_or(""),
                );
                return Ok(FieldKind::Map {
                    key: Box::new(key_kind),
                    value: Box::new(val_kind),
                });
            }
        }
        // Regular repeated.
        let item_kind = scalar_kind(proto_type, type_name);
        return Ok(FieldKind::Repeated(Box::new(item_kind)));
    }

    let inner_kind = scalar_kind(proto_type, type_name);

    // Detect EXPLICIT field presence. There are two encodings:
    //
    // 1. Proto3 optional (`proto3_optional = true` in FieldDescriptorProto):
    //    synthetic oneof wrapping the field (proto3 `optional` keyword).
    //
    // 2. Edition 2023 `features.field_presence = EXPLICIT`:
    //    stored in `FieldOptions.features.field_presence = EXPLICIT`.
    //
    // In both cases buffa generates `Option<T>` for the scalar field, so we
    // wrap the inner kind in `FieldKind::Optional` so the emitter can
    // generate `if let Some(v) = self.field { ... }` guards instead of
    // direct `self.field` comparisons.
    let is_proto3_optional = field.proto3_optional.unwrap_or(false);
    // Features cascade in editions: check field, then file-level default.
    // Edition 2023 default for field_presence is EXPLICIT.
    let field_presence = field
        .options
        .as_option()
        .and_then(|o| o.features.as_option())
        .and_then(|f| f.field_presence)
        .or_else(|| {
            file.options
                .as_option()
                .and_then(|o| o.features.as_option())
                .and_then(|f| f.field_presence)
        });
    let is_editions = file.edition.is_some();
    let is_edition_explicit =
        is_editions && field_presence.is_none_or(|fp| fp == feature_set::FieldPresence::EXPLICIT);
    // proto2: all non-repeated scalar fields (outside oneofs) are Option<T>
    // in buffa. Labels are OPTIONAL or REQUIRED; both produce Option<T>.
    let is_proto2 = !matches!(file.syntax.as_deref(), Some("proto3" | "editions"));
    // But only for proto2-style files, not edition files with unset syntax.
    let is_proto2 = is_proto2 && file.edition.is_none();
    // In proto2, a field is inside a real oneof (not Option<T>) when it has
    // an oneof_index and that oneof is not a synthetic proto3-optional one.
    let in_real_oneof = field.oneof_index.is_some_and(|idx| {
        !msg.field
            .iter()
            .any(|f| f.oneof_index == Some(idx) && f.proto3_optional.unwrap_or(false))
    });
    // proto2 LABEL_REQUIRED generates plain T (not Option<T>) in buffa.
    let is_proto2_required = label == field_descriptor_proto::Label::LABEL_REQUIRED;
    let is_proto2_scalar = is_proto2 && !in_real_oneof && !is_proto2_required;

    // Fields inside real oneofs are stored as enum variants, not Option<T>.
    let in_real_oneof_edition = field.oneof_index.is_some_and(|idx| {
        !msg.field
            .iter()
            .any(|f| f.oneof_index == Some(idx) && f.proto3_optional.unwrap_or(false))
    });
    let is_explicit_presence =
        (is_proto3_optional || is_edition_explicit || is_proto2_scalar) && !in_real_oneof_edition;
    if is_explicit_presence && !matches!(inner_kind, FieldKind::Message { .. }) {
        return Ok(FieldKind::Optional(Box::new(inner_kind)));
    }

    // Wrapper types (google.protobuf.Int32Value etc.) become a Wrapper kind
    // so the emitter unwraps `.as_option().map(|w| w.value)` before applying
    // the inner scalar rules.
    if let FieldKind::Message { ref full_name } = inner_kind {
        let wrapper = match full_name.as_str() {
            "google.protobuf.Int32Value" => Some(FieldKind::Int32),
            "google.protobuf.Int64Value" => Some(FieldKind::Int64),
            "google.protobuf.UInt32Value" => Some(FieldKind::Uint32),
            "google.protobuf.UInt64Value" => Some(FieldKind::Uint64),
            "google.protobuf.FloatValue" => Some(FieldKind::Float),
            "google.protobuf.DoubleValue" => Some(FieldKind::Double),
            "google.protobuf.BoolValue" => Some(FieldKind::Bool),
            "google.protobuf.StringValue" => Some(FieldKind::String),
            "google.protobuf.BytesValue" => Some(FieldKind::Bytes),
            _ => None,
        };
        if let Some(w) = wrapper {
            return Ok(FieldKind::Wrapper(Box::new(w)));
        }
    }

    Ok(inner_kind)
}

/// Look up the referenced type name as a map-entry nested type within the
/// current message or anywhere in the file. Returns `Some` only if the
/// resolved message has `map_entry = true`.
fn find_map_entry<'a>(
    file: &'a FileDescriptorProto,
    msg: &'a DescriptorProto,
    type_name: &str,
) -> Option<&'a DescriptorProto> {
    // type_name is a fully-qualified name like ".test.v1.ScalarsMessage.SomeEntry"
    // or a simple relative name. Strip leading dot.
    let stripped = type_name.strip_prefix('.').unwrap_or(type_name);

    // Check nested types of the current message first.
    let pkg = file.package.as_deref().unwrap_or("");
    let msg_name = msg.name.as_deref().unwrap_or("");
    let msg_prefix = if pkg.is_empty() {
        msg_name.to_string()
    } else {
        format!("{pkg}.{msg_name}")
    };
    for nested in &msg.nested_type {
        let nested_name = nested.name.as_deref().unwrap_or("");
        let fqn = format!("{msg_prefix}.{nested_name}");
        if fqn == stripped
            && nested
                .options
                .as_option()
                .and_then(|o| o.map_entry)
                .unwrap_or(false)
        {
            return Some(nested);
        }
    }

    // Fall back to searching top-level message_type.
    search_map_entry_in(&file.message_type, stripped, pkg)
}

fn search_map_entry_in<'a>(
    messages: &'a [DescriptorProto],
    target: &str,
    prefix: &str,
) -> Option<&'a DescriptorProto> {
    for msg in messages {
        let name = msg.name.as_deref().unwrap_or("");
        let fqn = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}.{name}")
        };
        if fqn == target
            && msg
                .options
                .as_option()
                .and_then(|o| o.map_entry)
                .unwrap_or(false)
        {
            return Some(msg);
        }
        // Recurse.
        if let Some(found) = search_map_entry_in(&msg.nested_type, target, &fqn) {
            return Some(found);
        }
    }
    None
}

/// Map a proto scalar/message/enum type into `FieldKind` (ignoring label).
fn scalar_kind(proto_type: field_descriptor_proto::Type, type_name: &str) -> FieldKind {
    use field_descriptor_proto::Type;
    match proto_type {
        Type::TYPE_STRING => FieldKind::String,
        Type::TYPE_BYTES => FieldKind::Bytes,
        Type::TYPE_INT32 => FieldKind::Int32,
        Type::TYPE_INT64 => FieldKind::Int64,
        Type::TYPE_UINT32 => FieldKind::Uint32,
        Type::TYPE_UINT64 => FieldKind::Uint64,
        Type::TYPE_SINT32 => FieldKind::Sint32,
        Type::TYPE_SINT64 => FieldKind::Sint64,
        Type::TYPE_FIXED32 => FieldKind::Fixed32,
        Type::TYPE_FIXED64 => FieldKind::Fixed64,
        Type::TYPE_SFIXED32 => FieldKind::Sfixed32,
        Type::TYPE_SFIXED64 => FieldKind::Sfixed64,
        Type::TYPE_FLOAT => FieldKind::Float,
        Type::TYPE_DOUBLE => FieldKind::Double,
        Type::TYPE_BOOL => FieldKind::Bool,
        Type::TYPE_ENUM => FieldKind::Enum {
            full_name: type_name.strip_prefix('.').unwrap_or(type_name).to_string(),
        },
        Type::TYPE_MESSAGE | Type::TYPE_GROUP => FieldKind::Message {
            full_name: type_name.strip_prefix('.').unwrap_or(type_name).to_string(),
        },
    }
}

// ─── Standard rules parsing ──────────────────────────────────────────────────

fn parse_standard(
    rules: &FieldRules,
    predef: &PredefinedExtRegistry,
) -> anyhow::Result<StandardRules> {
    let mut out = StandardRules::default();

    let Some(ref type_rules) = rules.r#type else {
        return Ok(out);
    };

    match type_rules {
        field_rules::Type::String(r) => {
            out.string = Some(parse_string_rules(r));
        }
        field_rules::Type::Bytes(r) => {
            out.bytes = Some(parse_bytes_rules(r));
        }
        field_rules::Type::Int32(r) => {
            out.int32 = Some(parse_int32_rules(r));
        }
        field_rules::Type::Int64(r) => {
            out.int64 = Some(parse_int64_rules(r));
        }
        field_rules::Type::Uint32(r) => {
            out.uint32 = Some(parse_uint32_rules(r));
        }
        field_rules::Type::Uint64(r) => {
            out.uint64 = Some(parse_uint64_rules(r));
        }
        field_rules::Type::Sint32(r) => {
            out.int32 = Some(parse_sint32_as_int32(r));
        }
        field_rules::Type::Sint64(r) => {
            out.int64 = Some(parse_sint64_as_int64(r));
        }
        field_rules::Type::Fixed32(r) => {
            out.uint32 = Some(parse_fixed32_as_uint32(r));
        }
        field_rules::Type::Fixed64(r) => {
            out.uint64 = Some(parse_fixed64_as_uint64(r));
        }
        field_rules::Type::Sfixed32(r) => {
            out.int32 = Some(parse_sfixed32_as_int32(r));
        }
        field_rules::Type::Sfixed64(r) => {
            out.int64 = Some(parse_sfixed64_as_int64(r));
        }
        field_rules::Type::Bool(r) => {
            out.bool_rules = Some(parse_bool_rules(r));
        }
        field_rules::Type::Float(r) => {
            out.float = Some(parse_float_rules(r));
        }
        field_rules::Type::Double(r) => {
            out.double = Some(parse_double_rules(r));
        }
        field_rules::Type::Enum(r) => {
            out.enum_rules = Some(parse_enum_rules(r));
        }
        field_rules::Type::Repeated(r) => {
            out.repeated = Some(parse_repeated_rules(r, predef)?);
        }
        field_rules::Type::Map(r) => {
            out.map = Some(parse_map_rules(r, predef)?);
        }
        field_rules::Type::Any(r) => {
            out.any_rules = Some(AnyStandard {
                in_set: r.r#in.clone(),
                not_in: r.not_in.clone(),
            });
        }
        field_rules::Type::Duration(r) => {
            use protovalidate_buffa_protos::{
                buf::validate::duration_rules, google::protobuf::Duration,
            };
            let dur_pair = |d: &Duration| -> (i64, i32) { (d.seconds, d.nanos) };
            let mut ds = DurationStandard::default();
            if let Some(c) = r.r#const.as_option() {
                ds.r#const = Some(dur_pair(c));
            }
            if let Some(lt) = r.less_than.as_ref() {
                match lt {
                    duration_rules::LessThan::Lt(d) => ds.lt = Some(dur_pair(d)),
                    duration_rules::LessThan::Lte(d) => ds.lte = Some(dur_pair(d)),
                }
            }
            if let Some(gt) = r.greater_than.as_ref() {
                match gt {
                    duration_rules::GreaterThan::Gt(d) => ds.gt = Some(dur_pair(d)),
                    duration_rules::GreaterThan::Gte(d) => ds.gte = Some(dur_pair(d)),
                }
            }
            ds.in_set = r.r#in.iter().map(dur_pair).collect();
            ds.not_in = r.not_in.iter().map(dur_pair).collect();
            out.duration = Some(ds);
        }
        field_rules::Type::Timestamp(r) => {
            use protovalidate_buffa_protos::{
                buf::validate::timestamp_rules,
                google::protobuf::{Duration, Timestamp},
            };
            let ts_pair = |t: &Timestamp| -> (i64, i32) { (t.seconds, t.nanos) };
            let dur_pair = |d: &Duration| -> (i64, i32) { (d.seconds, d.nanos) };
            let mut ts = TimestampStandard::default();
            if let Some(c) = r.r#const.as_option() {
                ts.r#const = Some(ts_pair(c));
            }
            if let Some(lt) = r.less_than.as_ref() {
                match lt {
                    timestamp_rules::LessThan::Lt(t) => ts.lt = Some(ts_pair(t)),
                    timestamp_rules::LessThan::Lte(t) => ts.lte = Some(ts_pair(t)),
                    timestamp_rules::LessThan::LtNow(b) => ts.lt_now = *b,
                }
            }
            if let Some(gt) = r.greater_than.as_ref() {
                match gt {
                    timestamp_rules::GreaterThan::Gt(t) => ts.gt = Some(ts_pair(t)),
                    timestamp_rules::GreaterThan::Gte(t) => ts.gte = Some(ts_pair(t)),
                    timestamp_rules::GreaterThan::GtNow(b) => ts.gt_now = *b,
                }
            }
            if let Some(w) = r.within.as_option() {
                ts.within = Some(dur_pair(w));
            }
            out.timestamp = Some(ts);
        }
        field_rules::Type::FieldMask(r) => {
            let mut fm = FieldMaskStandard::default();
            if let Some(c) = r.r#const.as_option() {
                fm.r#const = Some(c.paths.clone());
            }
            fm.in_set.clone_from(&r.r#in);
            fm.not_in.clone_from(&r.not_in);
            if fm.r#const.is_some() || !fm.in_set.is_empty() || !fm.not_in.is_empty() {
                out.field_mask = Some(fm);
            }
        }
    }

    Ok(out)
}

// ─── Rule family parsers ─────────────────────────────────────────────────────

type WellKnownFlags = (
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
);

fn parse_string_rules(r: &StringRules) -> StringStandard {
    // Extract the one-of well-known flag (at most one is set in any FieldRules).
    let wk = r.well_known.as_ref();
    let mut out_well_known: WellKnownFlags = (
        None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
        None, None,
    );
    if let Some(w) = wk {
        match w {
            string_rules::WellKnown::Uuid(b) => out_well_known.0 = Some(*b),
            string_rules::WellKnown::Tuuid(b) => out_well_known.1 = Some(*b),
            string_rules::WellKnown::Ulid(b) => out_well_known.2 = Some(*b),
            string_rules::WellKnown::Ip(b) => out_well_known.3 = Some(*b),
            string_rules::WellKnown::Ipv4(b) => out_well_known.4 = Some(*b),
            string_rules::WellKnown::Ipv6(b) => out_well_known.5 = Some(*b),
            string_rules::WellKnown::IpWithPrefixlen(b) => out_well_known.6 = Some(*b),
            string_rules::WellKnown::Ipv4WithPrefixlen(b) => out_well_known.7 = Some(*b),
            string_rules::WellKnown::Ipv6WithPrefixlen(b) => out_well_known.8 = Some(*b),
            string_rules::WellKnown::IpPrefix(b) => out_well_known.9 = Some(*b),
            string_rules::WellKnown::Ipv4Prefix(b) => out_well_known.10 = Some(*b),
            string_rules::WellKnown::Ipv6Prefix(b) => out_well_known.11 = Some(*b),
            string_rules::WellKnown::Hostname(b) => out_well_known.12 = Some(*b),
            string_rules::WellKnown::HostAndPort(b) => out_well_known.13 = Some(*b),
            string_rules::WellKnown::Email(b) => out_well_known.14 = Some(*b),
            string_rules::WellKnown::Uri(b) => out_well_known.15 = Some(*b),
            string_rules::WellKnown::UriRef(b) => out_well_known.16 = Some(*b),
            _ => {}
        }
    }
    let (mut address, mut protobuf_fqn, mut protobuf_dot_fqn, mut well_known_regex): (
        Option<bool>,
        Option<bool>,
        Option<bool>,
        Option<i32>,
    ) = (None, None, None, None);
    if let Some(w) = r.well_known.as_ref() {
        match w {
            string_rules::WellKnown::Address(b) => address = Some(*b),
            string_rules::WellKnown::ProtobufFqn(b) => protobuf_fqn = Some(*b),
            string_rules::WellKnown::ProtobufDotFqn(b) => protobuf_dot_fqn = Some(*b),
            string_rules::WellKnown::WellKnownRegex(i) => well_known_regex = Some(*i as i32),
            _ => {}
        }
    }

    StringStandard {
        min_len: r.min_len,
        max_len: r.max_len,
        len: r.len,
        min_bytes: r.min_bytes,
        max_bytes: r.max_bytes,
        len_bytes: r.len_bytes,
        not_contains: r.not_contains.clone(),
        pattern: r.pattern.clone(),
        uuid: out_well_known.0,
        tuuid: out_well_known.1,
        ulid: out_well_known.2,
        ip: out_well_known.3,
        ipv4: out_well_known.4,
        ipv6: out_well_known.5,
        ip_with_prefixlen: out_well_known.6,
        ipv4_with_prefixlen: out_well_known.7,
        ipv6_with_prefixlen: out_well_known.8,
        ip_prefix: out_well_known.9,
        ipv4_prefix: out_well_known.10,
        ipv6_prefix: out_well_known.11,
        hostname: out_well_known.12,
        host_and_port: out_well_known.13,
        email: out_well_known.14,
        uri: out_well_known.15,
        uri_ref: out_well_known.16,
        address,
        protobuf_fqn,
        protobuf_dot_fqn,
        well_known_regex,
        strict_regex: r.strict,
        in_set: r.r#in.clone(),
        not_in_set: r.not_in.clone(),
        prefix: r.prefix.clone(),
        suffix: r.suffix.clone(),
        contains: r.contains.clone(),
        r#const: r.r#const.clone(),
    }
}

fn parse_bytes_rules(r: &BytesRules) -> BytesStandard {
    use protovalidate_buffa_protos::buf::validate::bytes_rules;
    let (mut ip, mut ipv4, mut ipv6, mut uuid): (
        Option<bool>,
        Option<bool>,
        Option<bool>,
        Option<bool>,
    ) = (None, None, None, None);
    if let Some(w) = r.well_known.as_ref() {
        match w {
            bytes_rules::WellKnown::Ip(b) => ip = Some(*b),
            bytes_rules::WellKnown::Ipv4(b) => ipv4 = Some(*b),
            bytes_rules::WellKnown::Ipv6(b) => ipv6 = Some(*b),
            bytes_rules::WellKnown::Uuid(b) => uuid = Some(*b),
        }
    }
    BytesStandard {
        min_len: r.min_len,
        max_len: r.max_len,
        len: r.len,
        ip,
        ipv4,
        ipv6,
        uuid,
        pattern: r.pattern.clone(),
        in_set: r.r#in.clone(),
        not_in_set: r.not_in.clone(),
        prefix: r.prefix.clone(),
        suffix: r.suffix.clone(),
        contains: r.contains.clone(),
        r#const: r.r#const.clone(),
    }
}

fn parse_int32_rules(r: &Int32Rules) -> Int32Standard {
    Int32Standard {
        r#const: r.r#const,
        lt: r.less_than.as_ref().and_then(|v| {
            if let int32rules::LessThan::Lt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        lte: r.less_than.as_ref().and_then(|v| {
            if let int32rules::LessThan::Lte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gt: r.greater_than.as_ref().and_then(|v| {
            if let int32rules::GreaterThan::Gt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gte: r.greater_than.as_ref().and_then(|v| {
            if let int32rules::GreaterThan::Gte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        in_set: r.r#in.clone(),
        not_in: r.not_in.clone(),
    }
}

fn parse_int64_rules(r: &Int64Rules) -> Int64Standard {
    Int64Standard {
        r#const: r.r#const,
        lt: r.less_than.as_ref().and_then(|v| {
            if let int64rules::LessThan::Lt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        lte: r.less_than.as_ref().and_then(|v| {
            if let int64rules::LessThan::Lte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gt: r.greater_than.as_ref().and_then(|v| {
            if let int64rules::GreaterThan::Gt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gte: r.greater_than.as_ref().and_then(|v| {
            if let int64rules::GreaterThan::Gte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        in_set: r.r#in.clone(),
        not_in: r.not_in.clone(),
    }
}

fn parse_uint32_rules(r: &UInt32Rules) -> Uint32Standard {
    Uint32Standard {
        r#const: r.r#const,
        lt: r.less_than.as_ref().and_then(|v| {
            if let u_int32rules::LessThan::Lt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        lte: r.less_than.as_ref().and_then(|v| {
            if let u_int32rules::LessThan::Lte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gt: r.greater_than.as_ref().and_then(|v| {
            if let u_int32rules::GreaterThan::Gt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gte: r.greater_than.as_ref().and_then(|v| {
            if let u_int32rules::GreaterThan::Gte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        in_set: r.r#in.clone(),
        not_in: r.not_in.clone(),
    }
}

fn parse_uint64_rules(r: &UInt64Rules) -> Uint64Standard {
    Uint64Standard {
        r#const: r.r#const,
        lt: r.less_than.as_ref().and_then(|v| {
            if let u_int64rules::LessThan::Lt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        lte: r.less_than.as_ref().and_then(|v| {
            if let u_int64rules::LessThan::Lte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gt: r.greater_than.as_ref().and_then(|v| {
            if let u_int64rules::GreaterThan::Gt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gte: r.greater_than.as_ref().and_then(|v| {
            if let u_int64rules::GreaterThan::Gte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        in_set: r.r#in.clone(),
        not_in: r.not_in.clone(),
    }
}

const fn parse_bool_rules(
    r: &protovalidate_buffa_protos::buf::validate::BoolRules,
) -> BoolStandard {
    BoolStandard { r#const: r.r#const }
}

fn parse_float_rules(r: &FloatRules) -> FloatStandard {
    use protovalidate_buffa_protos::buf::validate::float_rules;
    FloatStandard {
        r#const: r.r#const,
        lt: r.less_than.as_ref().and_then(|v| {
            if let float_rules::LessThan::Lt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        lte: r.less_than.as_ref().and_then(|v| {
            if let float_rules::LessThan::Lte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gt: r.greater_than.as_ref().and_then(|v| {
            if let float_rules::GreaterThan::Gt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gte: r.greater_than.as_ref().and_then(|v| {
            if let float_rules::GreaterThan::Gte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        in_set: r.r#in.clone(),
        not_in: r.not_in.clone(),
        finite: r.finite.unwrap_or(false),
    }
}

fn parse_double_rules(r: &DoubleRules) -> DoubleStandard {
    use protovalidate_buffa_protos::buf::validate::double_rules;
    DoubleStandard {
        r#const: r.r#const,
        lt: r.less_than.as_ref().and_then(|v| {
            if let double_rules::LessThan::Lt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        lte: r.less_than.as_ref().and_then(|v| {
            if let double_rules::LessThan::Lte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gt: r.greater_than.as_ref().and_then(|v| {
            if let double_rules::GreaterThan::Gt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gte: r.greater_than.as_ref().and_then(|v| {
            if let double_rules::GreaterThan::Gte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        in_set: r.r#in.clone(),
        not_in: r.not_in.clone(),
        finite: r.finite.unwrap_or(false),
    }
}

fn parse_enum_rules(r: &EnumRules) -> EnumStandard {
    EnumStandard {
        r#const: r.r#const,
        defined_only: r.defined_only,
        in_set: r.r#in.clone(),
        not_in: r.not_in.clone(),
    }
}

fn parse_repeated_rules(
    r: &RepeatedRules,
    predef: &PredefinedExtRegistry,
) -> anyhow::Result<RepeatedStandard> {
    let items = if r.items.is_set() {
        let inner = parse_inner_field(&r.items, predef)?;
        Some(Box::new(inner))
    } else {
        None
    };
    Ok(RepeatedStandard {
        min_items: r.min_items,
        max_items: r.max_items,
        unique: r.unique,
        items,
    })
}

fn parse_map_rules(r: &MapRules, predef: &PredefinedExtRegistry) -> anyhow::Result<MapStandard> {
    let keys = if r.keys.is_set() {
        let inner = parse_inner_field(&r.keys, predef)?;
        Some(Box::new(inner))
    } else {
        None
    };
    let values = if r.values.is_set() {
        let inner = parse_inner_field(&r.values, predef)?;
        Some(Box::new(inner))
    } else {
        None
    };
    Ok(MapStandard {
        min_pairs: r.min_pairs,
        max_pairs: r.max_pairs,
        keys,
        values,
    })
}

/// Parse a nested `FieldRules` (from `repeated.items` / `map.keys` / `map.values`)
/// into a rule-only `FieldValidator` without full descriptor information.
/// `field_number` is set to `-1` as a sentinel meaning "no real descriptor".
fn parse_inner_field(
    rules: &FieldRules,
    predef: &PredefinedExtRegistry,
) -> anyhow::Result<FieldValidator> {
    let mut standard = parse_standard(rules, predef)?;
    populate_predefined(&mut standard, rules, predef);
    let required = rules.required.unwrap_or(false);
    let ignore = rules.ignore.map_or(Ignore::Unspecified, map_ignore);
    let cel = extract_field_cel(rules);
    Ok(FieldValidator {
        field_number: -1,
        field_name: std::string::String::new(),
        field_type: FieldKind::String, // placeholder — no descriptor for inner rules
        required,
        ignore,
        standard,
        cel,
        oneof_index: None,
        oneof_name: None,
        is_legacy_required: false,
        is_group: false,
    })
}

// ─── Sint / Fixed helpers ────────────────────────────────────────────────────

fn parse_sint32_as_int32(r: &SInt32Rules) -> Int32Standard {
    Int32Standard {
        r#const: r.r#const,
        lt: r.less_than.as_ref().and_then(|v| {
            if let s_int32rules::LessThan::Lt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        lte: r.less_than.as_ref().and_then(|v| {
            if let s_int32rules::LessThan::Lte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gt: r.greater_than.as_ref().and_then(|v| {
            if let s_int32rules::GreaterThan::Gt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gte: r.greater_than.as_ref().and_then(|v| {
            if let s_int32rules::GreaterThan::Gte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        in_set: r.r#in.clone(),
        not_in: r.not_in.clone(),
    }
}

fn parse_sint64_as_int64(r: &SInt64Rules) -> Int64Standard {
    Int64Standard {
        r#const: r.r#const,
        lt: r.less_than.as_ref().and_then(|v| {
            if let s_int64rules::LessThan::Lt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        lte: r.less_than.as_ref().and_then(|v| {
            if let s_int64rules::LessThan::Lte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gt: r.greater_than.as_ref().and_then(|v| {
            if let s_int64rules::GreaterThan::Gt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gte: r.greater_than.as_ref().and_then(|v| {
            if let s_int64rules::GreaterThan::Gte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        in_set: r.r#in.clone(),
        not_in: r.not_in.clone(),
    }
}

fn parse_fixed32_as_uint32(r: &Fixed32Rules) -> Uint32Standard {
    Uint32Standard {
        r#const: r.r#const,
        lt: r.less_than.as_ref().and_then(|v| {
            if let fixed32rules::LessThan::Lt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        lte: r.less_than.as_ref().and_then(|v| {
            if let fixed32rules::LessThan::Lte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gt: r.greater_than.as_ref().and_then(|v| {
            if let fixed32rules::GreaterThan::Gt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gte: r.greater_than.as_ref().and_then(|v| {
            if let fixed32rules::GreaterThan::Gte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        in_set: r.r#in.clone(),
        not_in: r.not_in.clone(),
    }
}

fn parse_fixed64_as_uint64(r: &Fixed64Rules) -> Uint64Standard {
    Uint64Standard {
        r#const: r.r#const,
        lt: r.less_than.as_ref().and_then(|v| {
            if let fixed64rules::LessThan::Lt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        lte: r.less_than.as_ref().and_then(|v| {
            if let fixed64rules::LessThan::Lte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gt: r.greater_than.as_ref().and_then(|v| {
            if let fixed64rules::GreaterThan::Gt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gte: r.greater_than.as_ref().and_then(|v| {
            if let fixed64rules::GreaterThan::Gte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        in_set: r.r#in.clone(),
        not_in: r.not_in.clone(),
    }
}

fn parse_sfixed32_as_int32(r: &SFixed32Rules) -> Int32Standard {
    Int32Standard {
        r#const: r.r#const,
        lt: r.less_than.as_ref().and_then(|v| {
            if let s_fixed32rules::LessThan::Lt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        lte: r.less_than.as_ref().and_then(|v| {
            if let s_fixed32rules::LessThan::Lte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gt: r.greater_than.as_ref().and_then(|v| {
            if let s_fixed32rules::GreaterThan::Gt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gte: r.greater_than.as_ref().and_then(|v| {
            if let s_fixed32rules::GreaterThan::Gte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        in_set: r.r#in.clone(),
        not_in: r.not_in.clone(),
    }
}

fn parse_sfixed64_as_int64(r: &SFixed64Rules) -> Int64Standard {
    Int64Standard {
        r#const: r.r#const,
        lt: r.less_than.as_ref().and_then(|v| {
            if let s_fixed64rules::LessThan::Lt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        lte: r.less_than.as_ref().and_then(|v| {
            if let s_fixed64rules::LessThan::Lte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gt: r.greater_than.as_ref().and_then(|v| {
            if let s_fixed64rules::GreaterThan::Gt(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        gte: r.greater_than.as_ref().and_then(|v| {
            if let s_fixed64rules::GreaterThan::Gte(x) = v {
                Some(*x)
            } else {
                None
            }
        }),
        in_set: r.r#in.clone(),
        not_in: r.not_in.clone(),
    }
}

// ─── CEL helpers ─────────────────────────────────────────────────────────────

fn extract_message_cel(mr: &MessageRules) -> Vec<CelRule> {
    let mut out: Vec<CelRule> = mr.cel.iter().filter_map(cel_rule_from).collect();
    for expr in &mr.cel_expression {
        out.push(CelRule {
            id: expr.clone(),
            message: format!("\"{expr}\" returned false"),
            expression: expr.clone(),
            is_cel_expression: true,
        });
    }
    out
}

fn extract_field_cel(rules: &FieldRules) -> Vec<CelRule> {
    let mut out: Vec<CelRule> = rules.cel.iter().filter_map(cel_rule_from).collect();
    // Also handle the `cel_expression` field (repeated plain strings).
    for expr in &rules.cel_expression {
        out.push(CelRule {
            id: expr.clone(),
            message: format!("\"{expr}\" returned false"),
            expression: expr.clone(),
            is_cel_expression: true,
        });
    }
    out
}

fn cel_rule_from(r: &protovalidate_buffa_protos::buf::validate::Rule) -> Option<CelRule> {
    let expression = r.expression.clone()?;
    Some(CelRule {
        id: r.id.clone().unwrap_or_default(),
        message: r.message.clone().unwrap_or_default(),
        expression,
        is_cel_expression: false,
    })
}

// ─── Ignore mapping ──────────────────────────────────────────────────────────

const fn map_ignore(ig: protovalidate_buffa_protos::buf::validate::Ignore) -> Ignore {
    use protovalidate_buffa_protos::buf::validate::Ignore as I;
    match ig {
        I::IGNORE_UNSPECIFIED => Ignore::Unspecified,
        I::IGNORE_IF_ZERO_VALUE => Ignore::IfZeroValue,
        I::IGNORE_ALWAYS => Ignore::Always,
    }
}
