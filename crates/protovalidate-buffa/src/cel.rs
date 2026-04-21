use std::{
    borrow::Cow,
    sync::{Arc, OnceLock},
};

use cel_interpreter::{
    extractors::{Arguments, This},
    Context, Program, Value,
};

use crate::{FieldPath, Violation};

pub struct CelConstraint {
    pub id: &'static str,
    pub message: &'static str,
    pub expression: &'static str,
    program: OnceLock<Program>,
}

pub trait AsCelValue {
    fn as_cel_value(&self) -> Value;
}

/// Proto scalar / list → CEL value conversion, used by plugin-emitted `AsCelValue` impls.
pub trait ToCelValue {
    fn to_cel_value(&self) -> Value;
}

impl ToCelValue for String {
    fn to_cel_value(&self) -> Value {
        Value::String(self.clone().into())
    }
}

impl ToCelValue for str {
    fn to_cel_value(&self) -> Value {
        Value::String(self.to_string().into())
    }
}

impl ToCelValue for i32 {
    fn to_cel_value(&self) -> Value {
        Value::Int(i64::from(*self))
    }
}

impl ToCelValue for i64 {
    fn to_cel_value(&self) -> Value {
        Value::Int(*self)
    }
}

impl ToCelValue for u32 {
    fn to_cel_value(&self) -> Value {
        Value::UInt(u64::from(*self))
    }
}

impl ToCelValue for u64 {
    fn to_cel_value(&self) -> Value {
        Value::UInt(*self)
    }
}

impl ToCelValue for f32 {
    fn to_cel_value(&self) -> Value {
        Value::Float(f64::from(*self))
    }
}

impl ToCelValue for f64 {
    fn to_cel_value(&self) -> Value {
        Value::Float(*self)
    }
}

impl ToCelValue for bool {
    fn to_cel_value(&self) -> Value {
        Value::Bool(*self)
    }
}

impl ToCelValue for Vec<u8> {
    fn to_cel_value(&self) -> Value {
        Value::Bytes(self.clone().into())
    }
}

impl<T: AsCelValue> ToCelValue for Option<T> {
    fn to_cel_value(&self) -> Value {
        self.as_ref().map_or(Value::Null, AsCelValue::as_cel_value)
    }
}

impl<T: ToCelValue> ToCelValue for Vec<T> {
    fn to_cel_value(&self) -> Value {
        Value::List(
            self.iter()
                .map(ToCelValue::to_cel_value)
                .collect::<Vec<_>>()
                .into(),
        )
    }
}

impl<T: AsCelValue + Default> ToCelValue for buffa::MessageField<T> {
    fn to_cel_value(&self) -> Value {
        self.as_option()
            .map_or(Value::Null, AsCelValue::as_cel_value)
    }
}

impl<E: buffa::Enumeration> ToCelValue for buffa::EnumValue<E> {
    fn to_cel_value(&self) -> Value {
        Value::Int(i64::from(self.to_i32()))
    }
}

macro_rules! impl_to_cel_for_hashmap_key {
    ($kty:ty => $ktarget:ty) => {
        impl<V, S> ToCelValue for std::collections::HashMap<$kty, V, S>
        where
            V: ToCelValue,
            S: std::hash::BuildHasher,
        {
            fn to_cel_value(&self) -> Value {
                let map: cel_interpreter::objects::Map = self
                    .iter()
                    .map(|(k, v)| {
                        (
                            cel_interpreter::objects::Key::from(k.clone() as $ktarget),
                            v.to_cel_value(),
                        )
                    })
                    .collect::<std::collections::HashMap<_, _>>()
                    .into();
                Value::Map(map)
            }
        }
    };
    (string: $kty:ty) => {
        impl<V, S> ToCelValue for std::collections::HashMap<$kty, V, S>
        where
            V: ToCelValue,
            S: std::hash::BuildHasher,
        {
            fn to_cel_value(&self) -> Value {
                let map: cel_interpreter::objects::Map = self
                    .iter()
                    .map(|(k, v)| {
                        (
                            cel_interpreter::objects::Key::from(k.clone()),
                            v.to_cel_value(),
                        )
                    })
                    .collect::<std::collections::HashMap<_, _>>()
                    .into();
                Value::Map(map)
            }
        }
    };
}
impl_to_cel_for_hashmap_key!(i32 => i64);
impl_to_cel_for_hashmap_key!(u32 => u64);
impl_to_cel_for_hashmap_key!(i64 => i64);
impl_to_cel_for_hashmap_key!(u64 => u64);
impl_to_cel_for_hashmap_key!(string: String);

impl<V, S> ToCelValue for std::collections::HashMap<bool, V, S>
where
    V: ToCelValue,
    S: std::hash::BuildHasher,
{
    fn to_cel_value(&self) -> Value {
        let map: cel_interpreter::objects::Map = self
            .iter()
            .map(|(k, v)| (cel_interpreter::objects::Key::from(*k), v.to_cel_value()))
            .collect::<std::collections::HashMap<_, _>>()
            .into();
        Value::Map(map)
    }
}

/// Generic adapter used by emitted impls: accepts anything that implements `ToCelValue`.
///
/// Convert any enum-like value to i32. Works for buffa `EnumValue<E>` and raw
/// enum types (which can be cast via `Enumeration::to_i32`).
pub fn enum_to_i32<E: buffa::Enumeration + Copy>(v: &E) -> i32 {
    v.to_i32()
}

#[must_use]
pub fn duration_from_secs_nanos(seconds: i64, nanos: i32) -> chrono::Duration {
    chrono::Duration::seconds(seconds) + chrono::Duration::nanoseconds(i64::from(nanos))
}

/// # Panics
///
/// Panics only if the fallback `from_timestamp(0, 0)` fails, which is
/// impossible (Unix epoch is always representable).
#[must_use]
pub fn timestamp_from_secs_nanos(
    seconds: i64,
    nanos: i32,
) -> chrono::DateTime<chrono::FixedOffset> {
    let nanos_u32 = u32::try_from(nanos.max(0)).unwrap_or(0);
    let s = chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, nanos_u32)
        .unwrap_or_else(|| chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap());
    s.fixed_offset()
}

pub fn to_cel_value<T: ToCelValue + ?Sized>(v: &T) -> Value {
    v.to_cel_value()
}

impl CelConstraint {
    #[must_use]
    pub const fn new(id: &'static str, message: &'static str, expression: &'static str) -> Self {
        Self {
            id,
            message,
            expression,
            program: OnceLock::new(),
        }
    }

    /// Evaluates this CEL expression against `this` (bound as the `this` variable
    /// inside the expression) plus a per-call-frozen `now` timestamp.
    ///
    /// # Errors
    ///
    /// Returns a [`Violation`] when the compiled CEL expression returns
    /// `false`, returns a non-empty string, or produces a runtime error.
    ///
    /// # Panics
    ///
    /// Panics at first call if the CEL expression fails to compile (it is
    /// baked in at codegen time, so a parse failure indicates a plugin bug).
    /// Evaluate this CEL expression with `this` bound to the supplied raw
    /// `cel_interpreter::Value` (used for scalar-field-level CEL rules where
    /// the "this" target is a primitive, not a message). The violation's
    /// `field` path is set from `field_path` and `rule` path is set to
    /// `[cel[index]]` reflecting position in the repeated `FieldRules.cel`.
    pub fn eval_value_at(
        &self,
        this: Value,
        field_path: FieldPath,
        cel_index: u64,
    ) -> Result<(), Violation> {
        let r = self.eval_value(this);
        match r {
            Ok(()) => Ok(()),
            Err(mut v) => {
                v.field = field_path;
                v.rule = FieldPath {
                    elements: vec![crate::FieldPathElement {
                        field_number: Some(23),
                        field_name: Some(Cow::Borrowed("cel")),
                        field_type: Some(crate::FieldType::Message),
                        key_type: None,
                        value_type: None,
                        subscript: Some(crate::Subscript::Index(cel_index)),
                    }],
                };
                Err(v)
            }
        }
    }

    /// Like `eval_value_at` but for `(field).cel_expression` (string)
    /// constraints — the rule path uses `field_number=29`, `field_name="cel_expression"`,
    /// `field_type=String` instead of cel's `field_number=23`/`field_type=Message`.
    ///
    /// # Errors
    ///
    /// Returns a [`Violation`] when the CEL expression rejects `this`.
    pub fn eval_expr_value_at(
        &self,
        this: Value,
        field_path: FieldPath,
        index: u64,
    ) -> Result<(), Violation> {
        let r = self.eval_value(this);
        match r {
            Ok(()) => Ok(()),
            Err(mut v) => {
                v.field = field_path;
                v.rule = FieldPath {
                    elements: vec![crate::FieldPathElement {
                        field_number: Some(29),
                        field_name: Some(Cow::Borrowed("cel_expression")),
                        field_type: Some(crate::FieldType::String),
                        key_type: None,
                        value_type: None,
                        subscript: Some(crate::Subscript::Index(index)),
                    }],
                };
                Err(v)
            }
        }
    }

    /// Evaluate for a `repeated.items.cel[idx]` rule. Rule path is
    /// `[repeated(18), items(4), cel(23, index:cel_idx)]`.
    ///
    /// # Errors
    ///
    /// Returns a [`Violation`] when the CEL expression rejects `this`.
    pub fn eval_repeated_items_cel(
        &self,
        this: Value,
        field_path: FieldPath,
        cel_idx: u64,
    ) -> Result<(), Violation> {
        let r = self.eval_value(this);
        match r {
            Ok(()) => Ok(()),
            Err(mut v) => {
                v.field = field_path;
                v.rule = FieldPath {
                    elements: vec![
                        crate::FieldPathElement {
                            field_number: Some(18),
                            field_name: Some(Cow::Borrowed("repeated")),
                            field_type: Some(crate::FieldType::Message),
                            key_type: None,
                            value_type: None,
                            subscript: None,
                        },
                        crate::FieldPathElement {
                            field_number: Some(4),
                            field_name: Some(Cow::Borrowed("items")),
                            field_type: Some(crate::FieldType::Message),
                            key_type: None,
                            value_type: None,
                            subscript: None,
                        },
                        crate::FieldPathElement {
                            field_number: Some(23),
                            field_name: Some(Cow::Borrowed("cel")),
                            field_type: Some(crate::FieldType::Message),
                            key_type: None,
                            value_type: None,
                            subscript: Some(crate::Subscript::Index(cel_idx)),
                        },
                    ],
                };
                Err(v)
            }
        }
    }

    /// `map.keys.cel[idx]` — `for_key=true`.
    ///
    /// # Errors
    ///
    /// Returns a [`Violation`] when the CEL expression rejects `this`.
    pub fn eval_map_keys_cel(
        &self,
        this: Value,
        field_path: FieldPath,
        cel_idx: u64,
    ) -> Result<(), Violation> {
        let r = self.eval_value(this);
        match r {
            Ok(()) => Ok(()),
            Err(mut v) => {
                v.field = field_path;
                v.for_key = true;
                v.rule = FieldPath {
                    elements: vec![
                        crate::FieldPathElement {
                            field_number: Some(19),
                            field_name: Some(Cow::Borrowed("map")),
                            field_type: Some(crate::FieldType::Message),
                            key_type: None,
                            value_type: None,
                            subscript: None,
                        },
                        crate::FieldPathElement {
                            field_number: Some(4),
                            field_name: Some(Cow::Borrowed("keys")),
                            field_type: Some(crate::FieldType::Message),
                            key_type: None,
                            value_type: None,
                            subscript: None,
                        },
                        crate::FieldPathElement {
                            field_number: Some(23),
                            field_name: Some(Cow::Borrowed("cel")),
                            field_type: Some(crate::FieldType::Message),
                            key_type: None,
                            value_type: None,
                            subscript: Some(crate::Subscript::Index(cel_idx)),
                        },
                    ],
                };
                Err(v)
            }
        }
    }

    /// `map.values.cel[idx]`.
    ///
    /// # Errors
    ///
    /// Returns a [`Violation`] when the CEL expression rejects `this`.
    pub fn eval_map_values_cel(
        &self,
        this: Value,
        field_path: FieldPath,
        cel_idx: u64,
    ) -> Result<(), Violation> {
        let r = self.eval_value(this);
        match r {
            Ok(()) => Ok(()),
            Err(mut v) => {
                v.field = field_path;
                v.rule = FieldPath {
                    elements: vec![
                        crate::FieldPathElement {
                            field_number: Some(19),
                            field_name: Some(Cow::Borrowed("map")),
                            field_type: Some(crate::FieldType::Message),
                            key_type: None,
                            value_type: None,
                            subscript: None,
                        },
                        crate::FieldPathElement {
                            field_number: Some(5),
                            field_name: Some(Cow::Borrowed("values")),
                            field_type: Some(crate::FieldType::Message),
                            key_type: None,
                            value_type: None,
                            subscript: None,
                        },
                        crate::FieldPathElement {
                            field_number: Some(23),
                            field_name: Some(Cow::Borrowed("cel")),
                            field_type: Some(crate::FieldType::Message),
                            key_type: None,
                            value_type: None,
                            subscript: Some(crate::Subscript::Index(cel_idx)),
                        },
                    ],
                };
                Err(v)
            }
        }
    }

    /// Evaluate a predefined-rule CEL expression with `this` and `rule`
    /// bindings. Caller supplies the complete `field_path` and `rule_path`.
    ///
    /// # Errors
    ///
    /// Returns a [`Violation`] when the CEL expression rejects `this`.
    ///
    /// # Panics
    ///
    /// Panics if the CEL expression fails to compile (baked in at codegen time).
    pub fn eval_predefined(
        &self,
        this: Value,
        rule: Value,
        field_path: FieldPath,
        rule_path: FieldPath,
    ) -> Result<(), Violation> {
        let program = self.program.get_or_init(|| {
            Program::compile(self.expression)
                .unwrap_or_else(|e| panic!("CEL compile failed for {}: {e}", self.id))
        });
        let mut ctx = Context::default();
        ctx.add_variable("this", this).expect("cel: 'this'");
        ctx.add_variable("rule", rule).expect("cel: 'rule'");
        ctx.add_variable("now", Value::Timestamp(chrono::Utc::now().fixed_offset()))
            .expect("cel: 'now'");
        register_custom_functions(&mut ctx);
        let result = program.execute(&ctx).map_err(|e| Violation {
            field: field_path.clone(),
            rule: rule_path.clone(),
            rule_id: Cow::Borrowed(self.id),
            message: Cow::Owned(format!("cel runtime error: {e}")),
            for_key: false,
        })?;
        let ok = match result {
            Value::Bool(true) => true,
            Value::String(s) if s.is_empty() => true,
            _ => false,
        };
        if ok {
            return Ok(());
        }
        Err(Violation {
            field: field_path,
            rule: rule_path,
            rule_id: Cow::Borrowed(self.id),
            message: Cow::Borrowed(self.message),
            for_key: false,
        })
    }

    /// Evaluate with `this` already bound as a raw CEL [`Value`].
    ///
    /// # Errors
    ///
    /// Returns a [`Violation`] when the CEL expression rejects `this`.
    ///
    /// # Panics
    ///
    /// Panics if the CEL expression fails to compile (baked in at codegen time).
    pub fn eval_value(&self, this: Value) -> Result<(), Violation> {
        let program = self.program.get_or_init(|| {
            Program::compile(self.expression)
                .unwrap_or_else(|e| panic!("CEL compile failed for {}: {e}", self.id))
        });
        let mut ctx = Context::default();
        ctx.add_variable("this", this).expect("cel: 'this' binding");
        ctx.add_variable("now", Value::Timestamp(chrono::Utc::now().fixed_offset()))
            .expect("cel: 'now' binding");
        register_custom_functions(&mut ctx);
        let result = program
            .execute(&ctx)
            .map_err(|e| self.violation(Cow::Owned(format!("cel runtime error: {e}"))))?;
        match result {
            Value::Bool(true) => Ok(()),
            Value::String(s) if s.is_empty() => Ok(()),
            Value::Bool(false) => Err(self.violation(Cow::Borrowed(self.message))),
            Value::String(s) => {
                if self.message.is_empty() {
                    Err(self.violation(Cow::Owned(s.to_string())))
                } else {
                    Err(self.violation(Cow::Borrowed(self.message)))
                }
            }
            other => Err(self.violation(Cow::Owned(format!(
                "cel returned non-bool/string: {other:?}"
            )))),
        }
    }

    /// Evaluate with `this` bound via the [`AsCelValue`] trait.
    ///
    /// # Errors
    ///
    /// Returns a [`Violation`] when the CEL expression rejects `this` or when
    /// a non-skippable runtime error occurs.
    ///
    /// # Panics
    ///
    /// Panics if the CEL expression fails to compile (baked in at codegen time).
    pub fn eval<T: AsCelValue>(&self, this: &T) -> Result<(), Violation> {
        use cel_interpreter::ExecutionError;
        let program = self.program.get_or_init(|| {
            Program::compile(self.expression)
                .unwrap_or_else(|e| panic!("CEL compile failed for {}: {e}", self.id))
        });

        let mut ctx = Context::default();
        ctx.add_variable("this", this.as_cel_value())
            .expect("cel: 'this' binding");
        ctx.add_variable("now", Value::Timestamp(chrono::Utc::now().fixed_offset()))
            .expect("cel: 'now' binding");
        register_custom_functions(&mut ctx);

        // Execute. `NoSuchKey` on message-level eval is not a hard error —
        // protovalidate semantics treat missing submessages as zero-valued,
        // so we skip the rule. `UnexpectedType` is surfaced as a marker
        // violation (`rule_id = "__cel_runtime_error__"`) that the caller
        // lifts into `ValidationError::runtime_error`.
        let result = match program.execute(&ctx) {
            Ok(v) => v,
            Err(ExecutionError::NoSuchKey(_)) => return Ok(()),
            Err(e @ ExecutionError::UnexpectedType { .. }) => {
                // Surface as a runtime-error violation. The caller lifts this
                // into the enclosing `ValidationError::runtime_error` slot.
                return Err(Violation {
                    field: FieldPath::default(),
                    rule: FieldPath::default(),
                    rule_id: Cow::Borrowed("__cel_runtime_error__"),
                    message: Cow::Owned(e.to_string()),
                    for_key: false,
                });
            }
            Err(e) => return Err(self.violation(Cow::Owned(format!("cel runtime error: {e}")))),
        };

        match result {
            Value::Bool(true) => Ok(()),
            Value::String(s) if s.is_empty() => Ok(()),
            Value::Bool(false) => Err(self.violation(Cow::Borrowed(self.message))),
            Value::String(s) => {
                if self.message.is_empty() {
                    Err(self.violation(Cow::Owned(s.to_string())))
                } else {
                    Err(self.violation(Cow::Borrowed(self.message)))
                }
            }
            other => Err(self.violation(Cow::Owned(format!(
                "cel returned non-bool/string: {other:?}"
            )))),
        }
    }

    fn violation(&self, message: Cow<'static, str>) -> Violation {
        Violation {
            field: FieldPath::default(),
            rule: FieldPath::default(),
            rule_id: Cow::Borrowed(self.id),
            message,
            for_key: false,
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one registration per CEL function — splitting scatters related registrations"
)]
fn register_custom_functions(ctx: &mut Context<'_>) {
    // Helper: coerce a cel arg to i64 if numeric, None if Null/missing.
    // Hoisted to top to satisfy `items_after_statements`.
    const fn arg_i64(v: Option<&Value>) -> Option<i64> {
        match v {
            Some(Value::Int(n)) => Some(*n),
            #[expect(
                clippy::cast_possible_wrap,
                reason = "CEL coerces u64 → i64 per spec; wrap is intended"
            )]
            Some(Value::UInt(n)) => Some(*n as i64),
            _ => None,
        }
    }
    const fn arg_bool(v: Option<&Value>) -> Option<bool> {
        if let Some(Value::Bool(b)) = v {
            Some(*b)
        } else {
            None
        }
    }

    // int() override: support Timestamp → Unix seconds (and pass-through for
    // other types via Arguments dispatch). cel-interpreter's builtin int()
    // only handles primitive conversions.
    // `dyn(x)` — identity pass-through for dynamic typing (cel-go behavior).
    // Split by Value variant since a Value return type isn't supported.
    ctx.add_function("dyn", |This(v): This<i64>| -> i64 { v });

    // Override `int()` to support Timestamp → Unix seconds. Use This<Value>
    // since cel-interpreter treats the first arg to `f(x)` as the receiver.
    ctx.add_function("int", |This(v): This<Value>| -> i64 {
        match v {
            Value::Timestamp(t) => t.timestamp(),
            Value::Int(i) => i,
            #[expect(clippy::cast_possible_wrap, reason = "CEL int() on u64 wraps per spec")]
            Value::UInt(u) => u as i64,
            #[expect(
                clippy::cast_possible_truncation,
                reason = "CEL int() truncates float per spec"
            )]
            Value::Float(f) => f as i64,
            Value::String(s) => s.parse::<i64>().unwrap_or(0),
            Value::Bool(b) => i64::from(b),
            _ => 0,
        }
    });
    // String format checks. Signatures match the canonical cel-go `protovalidate`
    // library. The rule helpers module owns the implementations.
    //
    // The `This<Arc<String>>` receiver pattern enables method-call syntax:
    // `this.ref_id.isUuid()` — same pattern as `startsWith` / `endsWith` in the
    // cel-interpreter standard library.
    ctx.add_function("isUuid", |This(this): This<Arc<String>>| -> bool {
        crate::rules::string::is_uuid(&this)
    });
    ctx.add_function("isHostname", |This(this): This<Arc<String>>| -> bool {
        crate::rules::string::is_hostname(&this)
    });
    ctx.add_function(
        "isHostAndPort",
        |This(this): This<Arc<String>>, port_required: bool| -> bool {
            if crate::rules::string::is_host_and_port(&this) {
                return true;
            }
            if port_required {
                return false;
            }
            // port optional: accept bare hostname, IPv4, or [ipv6]/ipv6.
            if crate::rules::string::is_hostname(&this)
                || crate::rules::string::is_ipv4(&this)
                || crate::rules::string::is_ipv6(&this)
            {
                return true;
            }
            // Bracketed IPv6 without port: `[::1]`.
            if let Some(inner) = this.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
                return crate::rules::string::is_ipv6(inner);
            }
            false
        },
    );
    ctx.add_function("isEmail", |This(this): This<Arc<String>>| -> bool {
        crate::rules::string::is_email(&this)
    });
    ctx.add_function("isUri", |This(this): This<Arc<String>>| -> bool {
        crate::rules::string::is_uri(&this)
    });
    ctx.add_function("isUriRef", |This(this): This<Arc<String>>| -> bool {
        crate::rules::string::is_uri_ref(&this)
    });
    // isIp / isIpPrefix accept 0..=2 optional args (version, strict).
    // Register with variadic Arguments and dispatch on value types.
    ctx.add_function(
        "isIp",
        |This(this): This<Arc<String>>, Arguments(args): Arguments| -> bool {
            let ver = arg_i64(args.first()).unwrap_or(0);
            match ver {
                0 => crate::rules::string::is_ip(&this),
                4 => crate::rules::string::is_ipv4(&this),
                6 => crate::rules::string::is_ipv6(&this),
                _ => false,
            }
        },
    );
    ctx.add_function(
        "isIpPrefix",
        |This(this): This<Arc<String>>, Arguments(args): Arguments| -> bool {
            // Each arg may be Null (absent proto3 optional). Try numeric then bool.
            let (ver, strict) = {
                let a0 = args.first();
                let a1 = args.get(1);
                let v_i = arg_i64(a0);
                let v_b = arg_bool(a0);
                let i_i = arg_i64(a1);
                let i_b = arg_bool(a1);
                // Position semantics: (ver, strict) or (ver,) or (strict,) depending on types.
                if let (Some(n), Some(b)) = (v_i, i_b) {
                    (n, Some(b))
                } else if let Some(n) = v_i {
                    (n, i_b)
                } else if let Some(b) = v_b {
                    (i_i.unwrap_or(0), Some(b))
                } else {
                    (0, i_b)
                }
            };
            let strict = strict.unwrap_or(false);
            let addr_ok = match ver {
                0 => true,
                4 => {
                    this.parse::<::std::net::Ipv4Addr>().is_ok()
                        || crate::rules::string::is_ipv4_with_prefixlen(&this)
                }
                6 => {
                    this.parse::<::std::net::Ipv6Addr>().is_ok()
                        || crate::rules::string::is_ipv6_with_prefixlen(&this)
                }
                _ => return false,
            };
            if !addr_ok {
                return false;
            }
            if strict {
                match ver {
                    4 => crate::rules::string::is_ipv4_prefix(&this),
                    6 => crate::rules::string::is_ipv6_prefix(&this),
                    _ => crate::rules::string::is_ip_prefix(&this),
                }
            } else {
                match ver {
                    4 => crate::rules::string::is_ipv4_with_prefixlen(&this),
                    6 => crate::rules::string::is_ipv6_with_prefixlen(&this),
                    _ => crate::rules::string::is_ip_with_prefixlen(&this),
                }
            }
        },
    );
}
