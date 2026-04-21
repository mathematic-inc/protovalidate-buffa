use std::{borrow::Cow, fmt};

#[derive(Debug, Clone, Default)]
pub struct ValidationError {
    pub violations: Vec<Violation>,
    /// Non-empty when the generated validator detected at code-gen time that
    /// a rule was malformed (mismatched rule/field type, malformed oneof
    /// spec, CEL referencing a non-existent field). Maps to protovalidate's
    /// compilation error.
    pub compile_error: Option<String>,
    /// Non-empty when a rule's runtime precondition failed (bytes.pattern on
    /// non-UTF-8 input, CEL type mismatch). Maps to protovalidate's runtime
    /// error.
    pub runtime_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Violation {
    pub field: FieldPath,
    pub rule: FieldPath,
    pub rule_id: Cow<'static, str>,
    pub message: Cow<'static, str>,
    pub for_key: bool,
}

#[derive(Debug, Clone, Default)]
pub struct FieldPath {
    pub elements: Vec<FieldPathElement>,
}

#[derive(Debug, Clone, Default)]
pub struct FieldPathElement {
    pub field_number: Option<i32>,
    pub field_name: Option<Cow<'static, str>>,
    pub field_type: Option<FieldType>,
    pub key_type: Option<FieldType>,
    pub value_type: Option<FieldType>,
    pub subscript: Option<Subscript>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    Double,
    Float,
    Int64,
    Uint64,
    Int32,
    Fixed64,
    Fixed32,
    Bool,
    String,
    Group,
    Message,
    Bytes,
    Uint32,
    Enum,
    Sfixed32,
    Sfixed64,
    Sint32,
    Sint64,
}

#[derive(Debug, Clone)]
pub enum Subscript {
    Index(u64),
    BoolKey(bool),
    IntKey(i64),
    UintKey(u64),
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
