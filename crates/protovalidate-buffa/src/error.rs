use std::{borrow::Cow, fmt};

/// Error that `validate()` returns when a rule fails or cannot run.
#[derive(Debug, Clone, Default)]
pub struct ValidationError {
    /// Rule violations, in the order that the validator found them.
    pub violations: Vec<Violation>,
    /// Non-empty when the generated validator detected at code-gen time that
    /// a rule was malformed (mismatched rule/field type, malformed oneof
    /// spec, CEL referencing a non-existent field). Maps to protovalidate's
    /// compilation error.
    pub compile_error: Option<String>,
    /// Non-empty when a rule's runtime precondition failed. Examples:
    /// `bytes.pattern` applied to non-UTF-8 input; a CEL expression
    /// that the plugin transpiler classified as always-runtime-error
    /// (e.g. `dyn(this).<unknown_field>`); a CEL expression the
    /// transpiler couldn't compile (the unsupported construct is
    /// inlined into the error message). Maps to protovalidate's
    /// runtime error.
    pub runtime_error: Option<String>,
}

/// One failed rule.
#[derive(Debug, Clone)]
pub struct Violation {
    /// Path of the field that failed the rule.
    pub field: FieldPath,
    /// Path of the rule, relative to the rules of the field.
    pub rule: FieldPath,
    /// Stable ID of the rule.
    pub rule_id: Cow<'static, str>,
    /// Description of the failure.
    pub message: Cow<'static, str>,
    /// True if the violation is for a map key, not a map value.
    pub for_key: bool,
}

/// A path of fields and subscripts.
#[derive(Debug, Clone, Default)]
pub struct FieldPath {
    /// Elements of the path, from the outermost field.
    pub elements: Vec<FieldPathElement>,
}

/// One step of a [`FieldPath`].
#[derive(Debug, Clone, Default)]
pub struct FieldPathElement {
    /// Number of the field.
    pub field_number: Option<i32>,
    /// Name of the field.
    pub field_name: Option<Cow<'static, str>>,
    /// Type of the field.
    pub field_type: Option<FieldType>,
    /// Type of the keys, for a map field.
    pub key_type: Option<FieldType>,
    /// Type of the values, for a map field.
    pub value_type: Option<FieldType>,
    /// Index or key that selects an element of a repeated or map field.
    pub subscript: Option<Subscript>,
}

/// Type of a protobuf field, as in `google.protobuf.FieldDescriptorProto.Type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    /// `double`.
    Double,
    /// `float`.
    Float,
    /// `int64`.
    Int64,
    /// `uint64`.
    Uint64,
    /// `int32`.
    Int32,
    /// `fixed64`.
    Fixed64,
    /// `fixed32`.
    Fixed32,
    /// `bool`.
    Bool,
    /// `string`.
    String,
    /// A group.
    Group,
    /// A message.
    Message,
    /// `bytes`.
    Bytes,
    /// `uint32`.
    Uint32,
    /// An enum.
    Enum,
    /// `sfixed32`.
    Sfixed32,
    /// `sfixed64`.
    Sfixed64,
    /// `sint32`.
    Sint32,
    /// `sint64`.
    Sint64,
}

/// Selects an element of a repeated or map field.
#[derive(Debug, Clone)]
pub enum Subscript {
    /// Index into a repeated field.
    Index(u64),
    /// Key of a map with `bool` keys.
    BoolKey(bool),
    /// Key of a map with signed integer keys.
    IntKey(i64),
    /// Key of a map with unsigned integer keys.
    UintKey(u64),
    /// Key of a map with `string` keys.
    StringKey(Cow<'static, str>),
}

impl fmt::Display for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for el in &self.elements {
            if let Some(name) = &el.field_name {
                if !first {
                    f.write_str(".")?;
                }
                f.write_str(name)?;
                first = false;
            }
            if let Some(sub) = &el.subscript {
                match sub {
                    Subscript::Index(i) => write!(f, "[{i}]")?,
                    Subscript::BoolKey(b) => write!(f, "[{b}]")?,
                    Subscript::IntKey(i) => write!(f, "[{i}]")?,
                    Subscript::UintKey(u) => write!(f, "[{u}]")?,
                    Subscript::StringKey(s) => write!(f, "[\"{}\"]", s.escape_default())?,
                }
            }
        }
        Ok(())
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for v in &self.violations {
            if !first {
                f.write_str("; ")?;
            }
            write!(f, "{}: {} [{}]", v.field, v.message, v.rule_id)?;
            first = false;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationError {}
