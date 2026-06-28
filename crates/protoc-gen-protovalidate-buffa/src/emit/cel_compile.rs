#![expect(
    clippy::similar_names,
    clippy::unused_self,
    clippy::many_single_char_names,
    reason = "CEL→Rust transpiler — typed AST walker with many single-arg helpers; converting all to free fns or threading state ergonomically would fight the otherwise readable visitor pattern."
)]
//! Compile-time expansion of CEL expressions into native Rust.
//!
//! # Architecture
//!
//! For each protovalidate CEL rule, the plugin parses the expression with
//! the upstream `cel-interpreter` parser (used as a parse-only dependency)
//! and walks the resulting AST through a typed visitor. The visitor emits
//! a `TokenStream` that the surrounding `emit::cel` module splices into
//! the generated `validate()` method.
//!
//! Every CEL value is statically typed during the walk via [`CelType`]:
//! `Int → i64`, `UInt → u64`, `Double → f64`, `Bool → bool`,
//! `Str { owned } → &str | String`, `Bytes { owned } → &[u8] | Vec<u8>`,
//! `List<T>`, `Map<K, V>` (carrying both the widened CEL type and the
//! underlying Rust scalar so map indexing can recover the original
//! `HashMap` key type), `Duration`, `Timestamp`, `Message(schema)` for
//! the `this` binding in message-level rules, and `MessageRef(fqn)` for
//! sub-message field selects (resolved lazily through a `SchemaLookup`
//! index so cyclic message types don't blow up).
//!
//! # `Result` semantics
//!
//! [`Compiler::compile`] returns <code>Ok([CompileOutput])</code> on
//! success — the emitted [`TokenStream`], the result's [`CelType`], and
//! a `needs_now` flag indicating whether the body referenced the `now`
//! binding. Internally the visitor also tracks compile-time literal
//! values so things like `rule.foo` in a predefined CEL rule fold to a
//! Rust literal at codegen time. On failure the visitor returns
//! <code>Err([FallbackReason])</code> with one of two kinds:
//!
//! - [`FallbackKind::Unsupported`] — the construct isn't (yet) handled by
//!   the transpiler. The emit pipeline emits a `__cel_runtime_error__`
//!   violation marker.
//! - [`FallbackKind::RuntimeError`] — the transpiler proved the rule
//!   would always raise a CEL runtime error at evaluation time (e.g.
//!   `dyn(this).<unknown_field>`). Same treatment: a runtime-error
//!   violation marker is emitted in place of an evaluator call.
//!
//! Both kinds reach the same runtime-error sink — distinguishing them
//! lets the emit code report better diagnostic messages in the violation
//! payload.
//!
//! See `emit_message_level` in `emit/cel.rs` for the integration point.

use std::collections::BTreeMap;

use cel::common::ast::{
    CallExpr, ComprehensionExpr, EntryExpr, Expr, IdedExpr, ListExpr, LiteralValue, MapExpr,
    SelectExpr, operators as op,
};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

/// Why a CEL expression could not be transpiled.
///
/// Most reasons are "unsupported by the transpiler", but a small set
/// represent rules that the transpiler determined would *always* fail at
/// runtime (e.g. `dyn(this).<unknown_field>`). The emit pipeline routes
/// the latter to a pre-pushed `__cel_runtime_error__` violation marker so
/// the runtime interpreter isn't needed for such rules either.
#[derive(Debug, Clone)]
pub struct FallbackReason {
    pub message: String,
    pub kind: FallbackKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackKind {
    /// The transpiler doesn't (yet) handle this construct. With no
    /// runtime interpreter to fall back to, callers emit a
    /// `__cel_runtime_error__` violation with the original expression
    /// in the message so users see a clear runtime signal.
    Unsupported,
    /// The transpiler proved the rule would always raise a CEL runtime
    /// error (e.g. field access through `dyn()` to a field that doesn't
    /// exist). Callers emit a `__cel_runtime_error__` violation —
    /// distinguished from `Unsupported` only by the error message, but
    /// kept as its own variant so diagnostics can be sharpened.
    RuntimeError,
}

impl FallbackReason {
    fn new(s: impl Into<String>) -> Self {
        Self {
            message: s.into(),
            kind: FallbackKind::Unsupported,
        }
    }

    fn runtime_error(s: impl Into<String>) -> Self {
        Self {
            message: s.into(),
            kind: FallbackKind::RuntimeError,
        }
    }
}

/// Static type of a compiled CEL expression. The transpiler tracks this so it
/// can pick the right Rust operator/coercion at every node.
#[derive(Debug, Clone, PartialEq)]
pub enum CelType {
    Int,
    UInt,
    Double,
    Bool,
    /// CEL `string`. We always represent the value as `&str` (borrowed) when
    /// possible; the `owned` field distinguishes a freshly-built `String`
    /// from a borrowed view.
    Str {
        owned: bool,
    },
    /// CEL `bytes`. Same borrowed/owned distinction as `Str`.
    Bytes {
        owned: bool,
    },
    Null,
    /// CEL `duration` — Rust `chrono::Duration`.
    Duration,
    /// CEL `timestamp` — Rust `chrono::DateTime<chrono::FixedOffset>`.
    Timestamp,
    /// Homogeneous list with a known element type.
    List(Box<Self>),
    /// Homogeneous map with known key + value types. The `key_rust` /
    /// `value_rust` strings encode the underlying Rust type names so the
    /// `_[_]` operator can emit `.get(&(<key> as <key_rust>))` for an
    /// accurate `HashMap` lookup.
    Map(Box<MapTy>),
    /// A proto message type — used for the `this` binding in
    /// `(message).cel` rules. Field selections (`this.foo`) become typed
    /// Rust field accesses.
    Message(Box<MessageSchema>),
    /// A proto message type referenced by FQN. Resolves against the
    /// `Compiler`'s `SchemaIndex` at field-selection time, enabling chained
    /// access like `this.e.a == this.f.a` without forcing the plugin to
    /// embed (potentially cyclic) sub-schemas at construction time.
    MessageRef(String),
    /// CEL `optional<T>` — represented in Rust as `Option<T>`. Built via
    /// `optional.of(x)` / `optional.none()` / `optional.ofNonZeroValue(x)`
    /// and consumed via `.hasValue()` / `.orValue(d)` / `.value()`. The
    /// `OPT_INDEX` (`m[?k]`) and `OPT_SELECT` (`o?.field`) operators also
    /// produce values of this type.
    Optional(Box<Self>),
    /// Anything we don't statically know. Operations on `Dyn` typically force
    /// a fallback.
    Dyn,
}

/// Schema info for a message-typed binding: ordered map from proto field
/// name → (Rust accessor expression template applied to the operand,
/// `CelType`, and the `FieldKind` for presence/coercion decisions).
#[derive(Debug, Clone, PartialEq)]
pub struct MessageSchema {
    pub fields: Vec<MessageFieldEntry>,
}

/// Static type of a map: the CEL key/value types plus a "raw Rust" hint that
/// determines how the index op casts CEL-widened keys back to the
/// `HashMap`'s actual key type.
#[derive(Debug, Clone, PartialEq)]
pub struct MapTy {
    pub key_cel: CelType,
    pub value_cel: CelType,
    pub key_rust: RustScalar,
    pub value_rust: RustScalar,
}

/// Identifies a concrete Rust scalar / wrapper type that backs a CEL value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustScalar {
    I32,
    I64,
    U32,
    U64,
    F32,
    F64,
    Bool,
    Str,
    Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MessageFieldEntry {
    /// Proto field name (e.g. `"first_name"`).
    pub proto_name: String,
    /// Rust field accessor identifier (e.g. `first_name`).
    pub rust_ident: String,
    /// CEL static type of the field value when present.
    pub ty: CelType,
    /// Presence semantics for `has()` and "this.field is set" checks. We
    /// only need to distinguish a few categories:
    pub kind: SchemaFieldKind,
}

/// Field-kind categories the transpiler cares about for presence and
/// access shape. Mirrors a subset of `scan::FieldKind`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaFieldKind {
    /// Singular scalar / enum / bool — `has()` returns true iff non-default.
    Scalar,
    /// String / bytes — `has()` returns true iff non-empty.
    StringLike,
    /// Singular sub-message — `has()` returns true iff present. The
    /// optional `proto_fqn` enables nested field access via the schema
    /// index.
    Message { proto_fqn: Option<String> },
    /// `Option<T>` (proto2 / editions explicit) — `has()` returns true iff
    /// `Some`.
    Optional,
    /// `MessageField<WrapperType>` — `has()` returns true iff `Some`.
    Wrapper,
    /// `Vec<T>` — `has()` returns true iff non-empty.
    Repeated,
}

impl CelType {
    const fn is_numeric(&self) -> bool {
        matches!(self, Self::Int | Self::UInt | Self::Double)
    }
    const fn is_string(&self) -> bool {
        matches!(self, Self::Str { .. })
    }
    const fn is_bytes(&self) -> bool {
        matches!(self, Self::Bytes { .. })
    }
}

/// A compile-time-known scalar/list value.
///
/// Used to inline the `rule` binding of predefined-CEL rules so each
/// `rule.<x>` reference resolves to a literal at codegen time, and to track
/// downstream literal folding in list/comparison ops.
#[derive(Debug, Clone)]
pub enum ConstValue {
    Bool(bool),
    Int(i64),
    UInt(u64),
    Double(f64),
    Str(String),
    Bytes(Vec<u8>),
    Null,
    List(Vec<Self>),
}

/// One named binding in the compile environment (e.g., `this`, `rule`, `now`).
#[derive(Debug, Clone)]
pub struct Binding {
    /// Rust expression that yields the binding's value (used unless `constant`
    /// is set, in which case the constant inlines).
    pub rust_expr: TokenStream,
    pub ty: CelType,
    /// When set, the binding's value is known at compile time and field
    /// accesses on it fold to constants.
    pub constant: Option<ConstValue>,
}

/// A compiled Rust expression together with its static CEL type.
#[derive(Debug, Clone)]
struct Compiled {
    tokens: TokenStream,
    ty: CelType,
    /// Whether this expression is a compile-time constant; used for further
    /// folding (e.g. `rule.gte` → known int → simplifies `has(rule.gte)`).
    constant: Option<ConstValue>,
}

/// Compile-time-known presence of a name. Used by `has(x.y)` against a const
/// `rule` binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HasInfo {
    /// Statically known to be absent (null / unset).
    Absent,
    /// Unknown — must emit runtime check (or fall back).
    Unknown,
}

/// Top-level compiler.
#[derive(Default)]
pub struct Compiler<'a> {
    bindings: BTreeMap<String, Binding>,
    /// Whether to inject a `let now = chrono::Utc::now().fixed_offset();` at
    /// the top of the generated body. Set to true the first time `now` is
    /// referenced.
    needs_now: bool,
    /// Lookup table for `CelType::MessageRef`. When `None`, message refs
    /// cannot be resolved and field-selection on them falls back.
    schemas: Option<&'a dyn SchemaLookup>,
}

/// Trait-object-style lookup for sub-message schemas. Implemented by the
/// caller (typically a `BTreeMap<String, MessageSchema>`).
pub trait SchemaLookup {
    fn get(&self, proto_fqn: &str) -> Option<MessageSchema>;
}

impl SchemaLookup for BTreeMap<String, MessageSchema> {
    fn get(&self, proto_fqn: &str) -> Option<MessageSchema> {
        Self::get(self, proto_fqn).cloned()
    }
}

impl<'a> Compiler<'a> {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_schemas(mut self, schemas: &'a dyn SchemaLookup) -> Self {
        self.schemas = Some(schemas);
        self
    }

    pub fn bind(&mut self, name: &str, binding: Binding) {
        self.bindings.insert(name.to_string(), binding);
    }

    /// Bind a name to a compile-time-known proto extension value (the `rule`
    /// binding for predefined-CEL rules).
    pub fn bind_rule_const(&mut self, name: &str, rc: &crate::scan::RuleConst) {
        let constant = const_from_rule(rc);
        let ty = constant.cel_type();
        let tokens = constant.to_tokens();
        self.bind(
            name,
            Binding {
                rust_expr: tokens,
                ty,
                constant: Some(constant),
            },
        );
    }

    /// Compile a CEL expression source string. On success, returns the Rust
    /// expression tokens and its static CEL type. On failure, returns a
    /// `FallbackReason` describing why the transpiler gave up.
    ///
    /// # Errors
    ///
    /// Returns `Err(FallbackReason)` if the expression cannot be parsed by the
    /// cel parser, or contains any construct the transpiler does not support.
    /// Callers emit a `__cel_runtime_error__` violation marker for the rule.
    pub fn compile(&mut self, source: &str) -> Result<CompileOutput, FallbackReason> {
        let parser = cel::parser::Parser::new().enable_optional_syntax(true);
        let ast = parser
            .parse(source)
            .map_err(|e| FallbackReason::new(format!("parse: {e:?}")))?;
        let c = self.expr(&ast)?;
        Ok(CompileOutput {
            tokens: c.tokens,
            ty: c.ty,
            needs_now: self.needs_now,
        })
    }

    fn expr(&mut self, e: &IdedExpr) -> Result<Compiled, FallbackReason> {
        match &e.expr {
            Expr::Literal(lit) => Ok(literal(lit)),
            Expr::Ident(name) => self.ident(name),
            Expr::Select(sel) => self.select(sel),
            Expr::Call(call) => self.call(call),
            Expr::List(list) => self.list_lit(list),
            Expr::Map(m) => self.map_lit(m),
            Expr::Comprehension(c) => self.comprehension(c),
            Expr::Struct(_) => Err(FallbackReason::new(
                "struct/message literal — proto message construction \
                 inside CEL requires a proto-FQN → Rust-type mapping the \
                 plugin doesn't currently expose; rules can typically \
                 avoid this by constructing the message in Rust and \
                 referencing it via a binding",
            )),
            Expr::Unspecified => Err(FallbackReason::new("unspecified expr")),
        }
    }

    fn ident(&mut self, name: &str) -> Result<Compiled, FallbackReason> {
        if name == "now" {
            self.needs_now = true;
            return Ok(Compiled {
                tokens: quote! { now },
                ty: CelType::Timestamp,
                constant: None,
            });
        }
        // Bindings take precedence so users can shadow the type-marker
        // keywords if they really want to. Otherwise treat CEL type
        // keywords (`int`, `uint`, ...) as type-marker constants —
        // primarily to make `type(x) == int` etc. work.
        if !self.bindings.contains_key(name)
            && let Some(marker) = cel_type_marker_ident(name)
        {
            return Ok(Compiled {
                tokens: quote! { #marker },
                ty: CelType::Str { owned: false },
                constant: Some(ConstValue::Str(marker.to_string())),
            });
        }
        let binding = self
            .bindings
            .get(name)
            .ok_or_else(|| FallbackReason::new(format!("unknown ident: {name}")))?;
        Ok(Compiled {
            tokens: binding.rust_expr.clone(),
            ty: binding.ty.clone(),
            constant: binding.constant.clone(),
        })
    }

    fn select(&mut self, sel: &SelectExpr) -> Result<Compiled, FallbackReason> {
        // `has(x.y)` arrives here with `test == true`.
        if sel.test {
            return self.select_has(sel);
        }
        let operand = self.expr(&sel.operand)?;
        if let CelType::Message(schema) = &operand.ty {
            return select_message_field(&operand.tokens, schema.as_ref(), &sel.field);
        }
        if let CelType::MessageRef(fqn) = &operand.ty {
            let schema = self
                .schemas
                .and_then(|s| s.get(fqn))
                .ok_or_else(|| FallbackReason::new(format!("MessageRef({fqn}) not in index")))?;
            return select_message_field(&operand.tokens, &schema, &sel.field);
        }
        if matches!(operand.ty, CelType::Dyn) {
            // `dyn(x).<field>` — type-erased access. cel-go semantics:
            // succeeds if the runtime value exposes <field>, otherwise a
            // runtime error. We can't know at codegen time, so emit a
            // runtime-error violation marker.
            return Err(FallbackReason::runtime_error(format!(
                "dyn field access: .{}",
                sel.field
            )));
        }
        Err(FallbackReason::new(format!(
            "field selection on {:?}.{}",
            operand.ty, sel.field
        )))
    }

    fn select_has(&mut self, sel: &SelectExpr) -> Result<Compiled, FallbackReason> {
        let operand = self.expr(&sel.operand)?;
        if let CelType::Message(schema) = &operand.ty {
            return has_message_field(&operand.tokens, schema.as_ref(), &sel.field);
        }
        if let CelType::MessageRef(fqn) = &operand.ty {
            let schema = self
                .schemas
                .and_then(|s| s.get(fqn))
                .ok_or_else(|| FallbackReason::new(format!("MessageRef({fqn}) not in index")))?;
            return has_message_field(&operand.tokens, &schema, &sel.field);
        }
        if matches!(operand.ty, CelType::Dyn) {
            return Err(FallbackReason::runtime_error(format!(
                "has(dyn .{}) cannot be resolved at codegen",
                sel.field
            )));
        }
        match has_for(&operand, &sel.field) {
            HasInfo::Absent => Ok(Compiled {
                tokens: quote! { false },
                ty: CelType::Bool,
                constant: Some(ConstValue::Bool(false)),
            }),
            HasInfo::Unknown => Err(FallbackReason::new(format!(
                "has(.{}) requires runtime presence check",
                sel.field
            ))),
        }
    }

    fn call(&mut self, call: &CallExpr) -> Result<Compiled, FallbackReason> {
        // Operator dispatch comes first — everything below is "named function
        // calls" (builtins, string library, etc).
        if call.target.is_none()
            && let Some(r) = self.try_operator(call)?
        {
            return Ok(r);
        }
        self.try_method_or_function(call)
    }

    /// Attempt to compile a function call that's actually a CEL operator
    /// (logical/arithmetic/comparison/in/conditional/negate).
    fn try_operator(&mut self, call: &CallExpr) -> Result<Option<Compiled>, FallbackReason> {
        let name = call.func_name.as_str();
        match name {
            op::CONDITIONAL => self.op_conditional(&call.args).map(Some),
            op::LOGICAL_AND => self.op_logical(&call.args, true).map(Some),
            op::LOGICAL_OR => self.op_logical(&call.args, false).map(Some),
            op::LOGICAL_NOT => self.op_not(&call.args).map(Some),
            op::NEGATE => self.op_negate(&call.args).map(Some),
            op::ADD | op::SUBSTRACT | op::MULTIPLY | op::DIVIDE | op::MODULO => {
                self.op_arith(name, &call.args).map(Some)
            }
            op::EQUALS
            | op::NOT_EQUALS
            | op::GREATER
            | op::GREATER_EQUALS
            | op::LESS
            | op::LESS_EQUALS => self.op_cmp(name, &call.args).map(Some),
            op::IN => self.op_in(&call.args).map(Some),
            op::INDEX => self.op_index(&call.args).map(Some),
            op::OPT_INDEX => self.op_opt_index(&call.args).map(Some),
            op::OPT_SELECT => self.op_opt_select(&call.args).map(Some),
            op::NOT_STRICTLY_FALSE => {
                // Only generated by comprehension expanders; we should never
                // encounter it at the top level.
                Err(FallbackReason::new(
                    "@not_strictly_false outside comprehension",
                ))
            }
            _ => Ok(None),
        }
    }

    fn try_method_or_function(&mut self, call: &CallExpr) -> Result<Compiled, FallbackReason> {
        // `format()` needs the raw AST args (to honor %s/%d/%f directives
        // typed against each argument's CEL type). Handle it before the
        // generic "compile args" path.
        let name = call.func_name.as_str();
        if name == "format"
            && let Some(target) = call.target.as_ref()
            && call.args.len() == 1
        {
            return self.str_format_raw(target, &call.args[0]);
        }
        // Two-variable comprehension intercept. cel-rs's macro expander
        // only matches the 2-arg forms (`.all(x, P)`), so the 3-arg form
        // `.all(k, v, P)` (and friends) arrives here as a plain method
        // call with `k` and `v` un-bound. Recognize the shape before the
        // generic arg-compilation path, which would fail to resolve them.
        if let Some(out) = self.try_two_var_comprehension(call)? {
            return Ok(out);
        }
        // `math.<name>(...)` intercept. cel-rs parses `math.abs(x)` as a
        // `Call` whose `target` is `Ident("math")`. `math` isn't bound, so
        // the generic dispatch's first move (compile target) would fail.
        // Recognize the namespace prefix here and route to `math_call`.
        if let Some(target_expr) = call.target.as_ref()
            && let Expr::Ident(ns) = &target_expr.expr
            && ns == "math"
            && !self.bindings.contains_key("math")
        {
            return self.math_call(name, &call.args);
        }
        // `optional.<name>(...)` — same pattern. `optional.of(x)` /
        // `optional.none()` / `optional.ofNonZeroValue(x)` create
        // `Optional<T>` values.
        if let Some(target_expr) = call.target.as_ref()
            && let Expr::Ident(ns) = &target_expr.expr
            && ns == "optional"
            && !self.bindings.contains_key("optional")
        {
            return self.optional_builder(name, &call.args);
        }
        let target = call.target.as_ref().map(|t| self.expr(t)).transpose()?;
        let args: Vec<Compiled> = call
            .args
            .iter()
            .map(|a| self.expr(a))
            .collect::<Result<_, _>>()?;
        match name {
            // --- casts (global, single arg) ---
            "int" if target.is_none() && args.len() == 1 => self.cast_int(&args[0]),
            "uint" if target.is_none() && args.len() == 1 => self.cast_uint(&args[0]),
            "double" if target.is_none() && args.len() == 1 => self.cast_double(&args[0]),
            "string" if target.is_none() && args.len() == 1 => self.cast_string(&args[0]),
            "bytes" if target.is_none() && args.len() == 1 => self.cast_bytes(&args[0]),
            "bool" if target.is_none() && args.len() == 1 => self.cast_bool(&args[0]),
            "dyn" if target.is_none() && args.len() == 1 => {
                // Type-erase: `dyn(x)` returns the same value but with
                // CelType::Dyn so subsequent operations follow CEL's
                // runtime-checked semantics. Any field access on the
                // result is therefore "would be a runtime error if the
                // field doesn't exist".
                let inner = args.into_iter().next().unwrap();
                Ok(Compiled {
                    tokens: inner.tokens,
                    ty: CelType::Dyn,
                    constant: inner.constant,
                })
            }
            "duration" if target.is_none() && args.len() == 1 => self.duration_ctor(&args[0]),
            "timestamp" if target.is_none() && args.len() == 1 => self.timestamp_ctor(&args[0]),
            "type" if target.is_none() && args.len() == 1 => {
                // `type(x)` returns a CEL type value. We don't model the
                // type kind in our type system, so fold to the static
                // type's CEL name as a string constant — `type(x) == int`
                // then reduces to a string == string compare.
                let name = static_type_marker(&args[0].ty);
                Ok(Compiled {
                    tokens: quote! { #name },
                    ty: CelType::Str { owned: false },
                    constant: Some(ConstValue::Str(name.to_string())),
                })
            }
            "type" => Err(FallbackReason::new("type() arity")),
            // --- size / len ---
            "size" if args.len() == 1 && target.is_none() => self.builtin_size(&args[0]),
            "size" if target.is_some() && args.is_empty() => {
                self.builtin_size(target.as_ref().unwrap())
            }
            // --- string / bytes methods (receiver-style) ---
            "startsWith" | "endsWith" | "contains" | "matches"
                if target.is_some() && args.len() == 1 =>
            {
                self.str_method(name, target.as_ref().unwrap(), &args[0])
            }
            "charAt" if target.is_some() && args.len() == 1 => {
                self.str_char_at(target.as_ref().unwrap(), &args[0])
            }
            "indexOf" | "lastIndexOf"
                if target.is_some() && (args.len() == 1 || args.len() == 2) =>
            {
                self.str_index_of(name, target.as_ref().unwrap(), &args)
            }
            "substring" if target.is_some() && (args.len() == 1 || args.len() == 2) => {
                self.str_substring(target.as_ref().unwrap(), &args)
            }
            "replace" if target.is_some() && args.len() == 2 => {
                self.str_replace(target.as_ref().unwrap(), &args[0], &args[1])
            }
            "split" if target.is_some() && args.len() == 1 => {
                self.str_split(target.as_ref().unwrap(), &args[0])
            }
            "join" if target.is_some() && (args.is_empty() || args.len() == 1) => {
                self.list_join(target.as_ref().unwrap(), args.first())
            }
            "lowerAscii" | "upperAscii" if target.is_some() && args.is_empty() => {
                Ok(self.str_case(name, target.as_ref().unwrap()))
            }
            "trim" if target.is_some() && args.is_empty() => {
                Ok(self.str_trim(target.as_ref().unwrap()))
            }
            // --- float predicates ---
            "isNan" if target.is_some() && args.is_empty() => {
                self.float_predicate("is_nan", target.as_ref().unwrap())
            }
            "isInf" if target.is_some() && args.is_empty() => {
                self.float_predicate("is_infinite", target.as_ref().unwrap())
            }
            "isFinite" if target.is_some() && args.is_empty() => {
                self.float_predicate("is_finite", target.as_ref().unwrap())
            }
            // --- optional<T> methods ---
            // `.hasValue()` (no args), `.orValue(d)` (1 arg), `.value()`
            // (no args). All require an Optional-typed receiver.
            "hasValue" | "orValue" | "value"
                if target.is_some()
                    && matches!(target.as_ref().unwrap().ty, CelType::Optional(_)) =>
            {
                Self::optional_method(name, target.as_ref().unwrap(), &args)
            }
            // --- list / string reverse + distinct ---
            "reverse" if target.is_some() && args.is_empty() => {
                Self::reverse_call(target.as_ref().unwrap())
            }
            "distinct" if target.is_some() && args.is_empty() => {
                Self::distinct_call(target.as_ref().unwrap())
            }
            // --- protovalidate string library ---
            "isUuid" | "isHostname" | "isEmail" | "isUri" | "isUriRef"
                if target.is_some() && args.is_empty() =>
            {
                self.proto_string_predicate(name, target.as_ref().unwrap())
            }
            "isHostAndPort" if target.is_some() && args.len() == 1 => {
                self.is_host_and_port(target.as_ref().unwrap(), &args[0])
            }
            "isIp" | "isIpPrefix" if target.is_some() => {
                self.is_ip(name, target.as_ref().unwrap(), &args)
            }
            // --- duration / timestamp accessors ---
            // Duration: getSeconds / getMilliseconds / getMinutes / getHours
            // (no args). Timestamp: same four plus getFullYear / getMonth /
            // getDate / getDayOfMonth / getDayOfWeek / getDayOfYear, all
            // accepting an optional timezone-string arg per CEL spec.
            "getSeconds" | "getMilliseconds" | "getMinutes" | "getHours" | "getFullYear"
            | "getMonth" | "getDate" | "getDayOfMonth" | "getDayOfWeek" | "getDayOfYear"
                if target.is_some() && args.len() <= 1 =>
            {
                self.dur_accessor(name, target.as_ref().unwrap(), &args)
            }
            _ => Err(FallbackReason::new(format!(
                "unsupported call: {}{}({})",
                target.map_or(String::new(), |_| "<recv>.".to_string()),
                name,
                args.len()
            ))),
        }
    }

    /// `duration("10s")` constructor. Pattern: protobuf duration accepts a
    /// signed decimal with one of `ns`, `us`, `µs`, `ms`, `s`, `m`, `h`
    /// suffixes. Literal arg folds at codegen time into a
    /// `duration_from_secs_nanos` call; dynamic arg falls back to a
    /// runtime parse via `protovalidate_buffa::cel::parse_duration`.
    /// Parse failure at runtime panics — CEL spec maps it to a runtime
    /// error, but emitting a structured error here would require
    /// violation-construction context the inner expression doesn't have.
    fn duration_ctor(&self, arg: &Compiled) -> Result<Compiled, FallbackReason> {
        if let Some(ConstValue::Str(s)) = &arg.constant {
            let parsed = parse_cel_duration(s)
                .ok_or_else(|| FallbackReason::new(format!("duration() parse: {s}")))?;
            let (secs, nanos) = parsed;
            return Ok(Compiled {
                tokens: quote! {
                    ::protovalidate_buffa::cel::duration_from_secs_nanos(#secs as i64, #nanos as i32)
                },
                ty: CelType::Duration,
                constant: None,
            });
        }
        if !matches!(arg.ty, CelType::Str { .. }) {
            return Err(FallbackReason::new(format!(
                "duration() arg type {:?} not string",
                arg.ty
            )));
        }
        let s_tok = string_as_str(arg);
        Ok(Compiled {
            tokens: quote! {
                ::protovalidate_buffa::cel::parse_duration(#s_tok)
                    .expect("CEL duration() parse")
            },
            ty: CelType::Duration,
            constant: None,
        })
    }

    fn timestamp_ctor(&self, arg: &Compiled) -> Result<Compiled, FallbackReason> {
        if let Some(ConstValue::Str(s)) = &arg.constant {
            // Literal: cache the parse in a `OnceLock` so it runs once.
            let s_lit = s.clone();
            return Ok(Compiled {
                tokens: quote! {
                    ({
                        static __TS: ::std::sync::OnceLock<::chrono::DateTime<::chrono::FixedOffset>> =
                            ::std::sync::OnceLock::new();
                        *__TS.get_or_init(|| {
                            ::chrono::DateTime::parse_from_rfc3339(#s_lit)
                                .expect("CEL timestamp() literal parse")
                        })
                    })
                },
                ty: CelType::Timestamp,
                constant: None,
            });
        }
        if !matches!(arg.ty, CelType::Str { .. }) {
            return Err(FallbackReason::new(format!(
                "timestamp() arg type {:?} not string",
                arg.ty
            )));
        }
        let s_tok = string_as_str(arg);
        Ok(Compiled {
            tokens: quote! {
                ::protovalidate_buffa::cel::parse_timestamp(#s_tok)
                    .expect("CEL timestamp() parse")
            },
            ty: CelType::Timestamp,
            constant: None,
        })
    }

    fn cast_int(&self, c: &Compiled) -> Result<Compiled, FallbackReason> {
        let t = c.tokens.clone();
        let tokens = match c.ty {
            CelType::Int => return Ok(c.clone()),
            CelType::UInt => quote! { ((#t) as i64) },
            CelType::Double => quote! { ((#t) as i64) },
            CelType::Bool => quote! { (if (#t) { 1i64 } else { 0i64 }) },
            CelType::Str { .. } => {
                let s = string_as_str(c);
                quote! { ::core::str::FromStr::from_str(#s).unwrap_or(0i64) }
            }
            CelType::Timestamp => quote! { (#t).timestamp() },
            _ => return Err(FallbackReason::new(format!("int() from {:?}", c.ty))),
        };
        Ok(Compiled {
            tokens,
            ty: CelType::Int,
            constant: None,
        })
    }

    fn cast_uint(&self, c: &Compiled) -> Result<Compiled, FallbackReason> {
        let t = c.tokens.clone();
        let tokens = match c.ty {
            CelType::UInt => return Ok(c.clone()),
            CelType::Int => quote! { ((#t) as u64) },
            CelType::Double => quote! { ((#t) as u64) },
            CelType::Str { .. } => {
                let s = string_as_str(c);
                quote! { ::core::str::FromStr::from_str(#s).unwrap_or(0u64) }
            }
            _ => return Err(FallbackReason::new(format!("uint() from {:?}", c.ty))),
        };
        Ok(Compiled {
            tokens,
            ty: CelType::UInt,
            constant: None,
        })
    }

    fn cast_double(&self, c: &Compiled) -> Result<Compiled, FallbackReason> {
        let t = c.tokens.clone();
        let tokens = match c.ty {
            CelType::Double => return Ok(c.clone()),
            CelType::Int | CelType::UInt => quote! { ((#t) as f64) },
            CelType::Str { .. } => {
                let s = string_as_str(c);
                quote! { ::core::str::FromStr::from_str(#s).unwrap_or(0f64) }
            }
            _ => return Err(FallbackReason::new(format!("double() from {:?}", c.ty))),
        };
        Ok(Compiled {
            tokens,
            ty: CelType::Double,
            constant: None,
        })
    }

    fn cast_string(&self, c: &Compiled) -> Result<Compiled, FallbackReason> {
        let t = c.tokens.clone();
        let tokens = match &c.ty {
            CelType::Str { .. } => return Ok(c.clone()),
            CelType::Bytes { .. } => {
                let s = bytes_as_slice(c);
                quote! { ::std::string::String::from_utf8((#s).to_vec()).unwrap_or_default() }
            }
            CelType::Int | CelType::UInt | CelType::Double | CelType::Bool => {
                quote! { ::std::format!("{}", #t) }
            }
            _ => return Err(FallbackReason::new(format!("string() from {:?}", c.ty))),
        };
        Ok(Compiled {
            tokens,
            ty: CelType::Str { owned: true },
            constant: None,
        })
    }

    fn cast_bytes(&self, c: &Compiled) -> Result<Compiled, FallbackReason> {
        match &c.ty {
            CelType::Bytes { .. } => Ok(c.clone()),
            CelType::Str { .. } => {
                let s = string_as_str(c);
                Ok(Compiled {
                    tokens: quote! { (#s).as_bytes() },
                    ty: CelType::Bytes { owned: false },
                    constant: None,
                })
            }
            _ => Err(FallbackReason::new(format!("bytes() from {:?}", c.ty))),
        }
    }

    fn cast_bool(&self, c: &Compiled) -> Result<Compiled, FallbackReason> {
        match &c.ty {
            CelType::Bool => Ok(c.clone()),
            CelType::Str { .. } => {
                let s = string_as_str(c);
                Ok(Compiled {
                    tokens: quote! { ::core::str::FromStr::from_str(#s).unwrap_or(false) },
                    ty: CelType::Bool,
                    constant: None,
                })
            }
            _ => Err(FallbackReason::new(format!("bool() from {:?}", c.ty))),
        }
    }

    fn builtin_size(&self, c: &Compiled) -> Result<Compiled, FallbackReason> {
        let tokens = match &c.ty {
            CelType::Str { .. } => {
                let s = string_as_str(c);
                // CEL `size(string)` returns the number of Unicode code points.
                quote! { (#s.chars().count() as i64) }
            }
            CelType::Bytes { .. } => {
                let s = bytes_as_slice(c);
                quote! { ((#s).len() as i64) }
            }
            CelType::List(_) | CelType::Map(_) => {
                let t = c.tokens.clone();
                quote! { ((#t).len() as i64) }
            }
            _ => return Err(FallbackReason::new(format!("size() on {:?}", c.ty))),
        };
        Ok(Compiled {
            tokens,
            ty: CelType::Int,
            constant: None,
        })
    }

    fn str_method(
        &self,
        name: &str,
        target: &Compiled,
        arg: &Compiled,
    ) -> Result<Compiled, FallbackReason> {
        if !target.ty.is_string() || !arg.ty.is_string() {
            return Err(FallbackReason::new(format!("{name} on non-string")));
        }
        let s = string_as_str(target);
        let a = string_as_str(arg);
        let tokens = match name {
            "startsWith" => quote! { (#s).starts_with(#a) },
            "endsWith" => quote! { (#s).ends_with(#a) },
            "contains" => quote! { (#s).contains(#a) },
            "matches" => self.regex_match(&s, arg)?,
            _ => unreachable!(),
        };
        Ok(Compiled {
            tokens,
            ty: CelType::Bool,
            constant: None,
        })
    }

    fn regex_match(
        &self,
        target_str: &TokenStream,
        pattern: &Compiled,
    ) -> Result<TokenStream, FallbackReason> {
        // Literal pattern: bake into a `OnceLock<Regex>` so the compile
        // happens once at first call. Dynamic pattern: compile per-call.
        // The dynamic path returns `false` on an invalid pattern instead
        // of raising — CEL's `matches()` raises a runtime error on an
        // unparseable regex, but emitting one here would require a
        // violation-construction site the inner expression doesn't have;
        // false is the safe under-approximation (the resulting rule will
        // simply not match).
        if let Some(ConstValue::Str(p)) = &pattern.constant {
            let pat = p.clone();
            return Ok(quote! {
                ({
                    static __RE: ::std::sync::OnceLock<::regex::Regex> = ::std::sync::OnceLock::new();
                    let re = __RE.get_or_init(|| ::regex::Regex::new(#pat).expect("CEL regex compile"));
                    re.is_match(#target_str)
                })
            });
        }
        if !matches!(pattern.ty, CelType::Str { .. }) {
            return Err(FallbackReason::new(format!(
                "matches(): pattern type {:?} not string",
                pattern.ty
            )));
        }
        let pat_str = string_as_str(pattern);
        Ok(quote! {
            (::regex::Regex::new(#pat_str).map(|__re| __re.is_match(#target_str)).unwrap_or(false))
        })
    }

    /// Compile `<literal_fmt_str>.format([a, b, ...])`. The pattern is fixed
    /// at codegen time so we resolve each directive against the argument's
    /// static CEL type. Supports %s, %d, %f.
    fn str_format_raw(
        &mut self,
        target: &IdedExpr,
        args: &IdedExpr,
    ) -> Result<Compiled, FallbackReason> {
        // Format string must be a literal.
        let Expr::Literal(LiteralValue::String(fmt_lit)) = &target.expr else {
            return Err(FallbackReason::new("format(): receiver not literal string"));
        };
        let fmt = fmt_lit.inner().to_string();
        // Args must be a list literal so we can match per-element types.
        let Expr::List(list) = &args.expr else {
            return Err(FallbackReason::new("format(): args not a list literal"));
        };
        let mut compiled_args: Vec<Compiled> = Vec::with_capacity(list.elements.len());
        for el in &list.elements {
            compiled_args.push(self.expr(el)?);
        }
        let mut out_parts: Vec<TokenStream> = Vec::new();
        let mut arg_idx: usize = 0;
        let chars: Vec<char> = fmt.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c == '%' && i + 1 < chars.len() {
                let d = chars[i + 1];
                if d == '%' {
                    out_parts.push(quote! { "%" });
                    i += 2;
                    continue;
                }
                if arg_idx >= compiled_args.len() {
                    return Err(FallbackReason::new("format(): too few args"));
                }
                let a = &compiled_args[arg_idx];
                let arg_tokens = a.tokens.clone();
                let formatted: TokenStream = match d {
                    's' => {
                        // CEL `%s` is "anything reasonable".
                        match &a.ty {
                            CelType::Str { .. } => {
                                let s = string_as_str(a);
                                quote! { ::std::string::String::from(#s) }
                            }
                            CelType::Bool | CelType::Int | CelType::UInt | CelType::Double => {
                                quote! { ::std::format!("{}", #arg_tokens) }
                            }
                            CelType::Bytes { .. } => {
                                let b = bytes_as_slice(a);
                                quote! {
                                    ::std::string::String::from_utf8_lossy(#b)
                                        .into_owned()
                                }
                            }
                            CelType::Null => quote! { ::std::string::String::from("null") },
                            CelType::List(elem)
                                if matches!(
                                    elem.as_ref(),
                                    CelType::Int
                                        | CelType::UInt
                                        | CelType::Double
                                        | CelType::Bool
                                        | CelType::Str { .. }
                                ) =>
                            {
                                quote! {
                                    ({
                                        let mut s = ::std::string::String::from("[");
                                        let mut __it = (#arg_tokens).iter();
                                        if let Some(x) = __it.next() {
                                            s.push_str(&::std::format!("{}", x));
                                            for x in __it {
                                                s.push_str(", ");
                                                s.push_str(&::std::format!("{}", x));
                                            }
                                        }
                                        s.push(']');
                                        s
                                    })
                                }
                            }
                            _ => {
                                return Err(FallbackReason::new(format!(
                                    "format %s on {:?}",
                                    a.ty
                                )));
                            }
                        }
                    }
                    'd' => {
                        if !matches!(a.ty, CelType::Int | CelType::UInt) {
                            return Err(FallbackReason::new(format!("format %d on {:?}", a.ty)));
                        }
                        quote! { ::std::format!("{}", #arg_tokens) }
                    }
                    'f' => {
                        if !matches!(a.ty, CelType::Double | CelType::Int | CelType::UInt) {
                            return Err(FallbackReason::new(format!("format %f on {:?}", a.ty)));
                        }
                        // CEL `%f` default precision is 6.
                        quote! { ::std::format!("{:.6}", ((#arg_tokens) as f64)) }
                    }
                    'e' => {
                        if !matches!(a.ty, CelType::Double | CelType::Int | CelType::UInt) {
                            return Err(FallbackReason::new(format!("format %e on {:?}", a.ty)));
                        }
                        // Scientific notation, CEL spec matches `printf %e`
                        // (default 6 digits after the decimal).
                        quote! { ::std::format!("{:.6e}", ((#arg_tokens) as f64)) }
                    }
                    'x' => {
                        if !matches!(a.ty, CelType::Int | CelType::UInt) {
                            return Err(FallbackReason::new(format!("format %x on {:?}", a.ty)));
                        }
                        // Hex (lower-case). CEL spec: unsigned representation,
                        // so signed ints are reinterpreted as their two's-
                        // complement bit pattern via `as u64`.
                        quote! { ::std::format!("{:x}", ((#arg_tokens) as u64)) }
                    }
                    'X' => {
                        if !matches!(a.ty, CelType::Int | CelType::UInt) {
                            return Err(FallbackReason::new(format!("format %X on {:?}", a.ty)));
                        }
                        quote! { ::std::format!("{:X}", ((#arg_tokens) as u64)) }
                    }
                    'o' => {
                        if !matches!(a.ty, CelType::Int | CelType::UInt) {
                            return Err(FallbackReason::new(format!("format %o on {:?}", a.ty)));
                        }
                        quote! { ::std::format!("{:o}", ((#arg_tokens) as u64)) }
                    }
                    'b' => {
                        if !matches!(a.ty, CelType::Int | CelType::UInt) {
                            return Err(FallbackReason::new(format!("format %b on {:?}", a.ty)));
                        }
                        quote! { ::std::format!("{:b}", ((#arg_tokens) as u64)) }
                    }
                    _ => {
                        return Err(FallbackReason::new(format!(
                            "format directive %{d} unsupported"
                        )));
                    }
                };
                out_parts.push(formatted);
                arg_idx += 1;
                i += 2;
            } else {
                let mut lit = String::new();
                while i < chars.len() && chars[i] != '%' {
                    lit.push(chars[i]);
                    i += 1;
                }
                out_parts.push(quote! { #lit });
            }
        }
        Ok(Compiled {
            tokens: quote! {
                ({
                    let mut __s = ::std::string::String::new();
                    #( __s.push_str(&#out_parts); )*
                    __s
                })
            },
            ty: CelType::Str { owned: true },
            constant: None,
        })
    }

    fn str_char_at(&self, target: &Compiled, index: &Compiled) -> Result<Compiled, FallbackReason> {
        if !target.ty.is_string() || !matches!(index.ty, CelType::Int) {
            return Err(FallbackReason::new("charAt argument types"));
        }
        let s = string_as_str(target);
        let i = index.tokens.clone();
        Ok(Compiled {
            tokens: quote! {
                ({
                    let __s = #s;
                    let __i = (#i) as usize;
                    __s.chars().nth(__i).map_or_else(
                        ::std::string::String::new,
                        |c| c.to_string(),
                    )
                })
            },
            ty: CelType::Str { owned: true },
            constant: None,
        })
    }

    fn str_index_of(
        &self,
        name: &str,
        target: &Compiled,
        args: &[Compiled],
    ) -> Result<Compiled, FallbackReason> {
        if !target.ty.is_string() || !args[0].ty.is_string() {
            return Err(FallbackReason::new("indexOf arg types"));
        }
        let s = string_as_str(target);
        let needle = string_as_str(&args[0]);
        let from: TokenStream = args.get(1).map_or_else(
            || quote! { 0usize },
            |start| {
                let t = start.tokens.clone();
                quote! { ((#t) as usize) }
            },
        );
        let body = match name {
            "indexOf" => quote! {
                ({
                    let __s = #s;
                    let __from: usize = #from;
                    if __from > __s.chars().count() { -1i64 }
                    else {
                        let byte_off: usize = __s.char_indices().nth(__from).map_or(__s.len(), |(i, _)| i);
                        match __s[byte_off..].find(#needle) {
                            None => -1i64,
                            Some(b) => {
                                let abs = byte_off + b;
                                __s[..abs].chars().count() as i64
                            }
                        }
                    }
                })
            },
            "lastIndexOf" => quote! {
                ({
                    let __s = #s;
                    let __from: usize = #from;
                    let __nchars = __s.chars().count();
                    if __from > __nchars { -1i64 }
                    else {
                        let byte_off_end: usize = __s.char_indices().nth(__from).map_or(__s.len(), |(i, _)| i);
                        // CEL semantics: search the entire string, but only
                        // return positions <= start.
                        match __s.rfind(#needle) {
                            None => -1i64,
                            Some(b) if b <= byte_off_end => __s[..b].chars().count() as i64,
                            Some(_) => -1i64,
                        }
                    }
                })
            },
            _ => unreachable!(),
        };
        Ok(Compiled {
            tokens: body,
            ty: CelType::Int,
            constant: None,
        })
    }

    fn str_substring(
        &self,
        target: &Compiled,
        args: &[Compiled],
    ) -> Result<Compiled, FallbackReason> {
        if !target.ty.is_string() {
            return Err(FallbackReason::new("substring on non-string"));
        }
        let s = string_as_str(target);
        let start = args[0].tokens.clone();
        let end_tokens: TokenStream = args.get(1).map_or_else(
            || quote! { __s.chars().count() },
            |c| {
                let t = c.tokens.clone();
                quote! { ((#t) as usize) }
            },
        );
        Ok(Compiled {
            tokens: quote! {
                ({
                    let __s = #s;
                    let __start = ((#start) as usize);
                    let __end = #end_tokens;
                    let __bs = __s.char_indices().nth(__start).map_or(__s.len(), |(i, _)| i);
                    let __be = __s.char_indices().nth(__end).map_or(__s.len(), |(i, _)| i);
                    if __be < __bs { ::std::string::String::new() }
                    else { __s[__bs..__be].to_string() }
                })
            },
            ty: CelType::Str { owned: true },
            constant: None,
        })
    }

    fn str_replace(
        &self,
        target: &Compiled,
        from: &Compiled,
        to: &Compiled,
    ) -> Result<Compiled, FallbackReason> {
        if !target.ty.is_string() || !from.ty.is_string() || !to.ty.is_string() {
            return Err(FallbackReason::new("replace types"));
        }
        let s = string_as_str(target);
        let f = string_as_str(from);
        let t = string_as_str(to);
        Ok(Compiled {
            tokens: quote! { (#s).replace(#f, #t) },
            ty: CelType::Str { owned: true },
            constant: None,
        })
    }

    fn str_split(&self, target: &Compiled, sep: &Compiled) -> Result<Compiled, FallbackReason> {
        if !target.ty.is_string() || !sep.ty.is_string() {
            return Err(FallbackReason::new("split types"));
        }
        let s = string_as_str(target);
        let sep_t = string_as_str(sep);
        Ok(Compiled {
            tokens: quote! { (#s).split(#sep_t).map(::std::string::String::from).collect::<::std::vec::Vec<::std::string::String>>() },
            ty: CelType::List(Box::new(CelType::Str { owned: true })),
            constant: None,
        })
    }

    fn list_join(
        &self,
        target: &Compiled,
        sep: Option<&Compiled>,
    ) -> Result<Compiled, FallbackReason> {
        let CelType::List(elem) = &target.ty else {
            return Err(FallbackReason::new("join on non-list"));
        };
        let sep_t = sep.map_or_else(
            || quote! { "" },
            |s| {
                let t = string_as_str(s);
                quote! { #t }
            },
        );
        let target_t = target.tokens.clone();
        // For primitive element types other than string, fall back to
        // `Display`-based formatting. CEL `[1,2,3].join(",")` → `"1,2,3"`.
        let push_first: TokenStream;
        let push_more: TokenStream;
        match elem.as_ref() {
            CelType::Str { .. } => {
                push_first = quote! {
                    __out.push_str(::core::convert::AsRef::<str>::as_ref(first));
                };
                push_more = quote! {
                    __out.push_str(::core::convert::AsRef::<str>::as_ref(x));
                };
            }
            CelType::Int | CelType::UInt | CelType::Double | CelType::Bool => {
                push_first = quote! { __out.push_str(&::std::format!("{}", first)); };
                push_more = quote! { __out.push_str(&::std::format!("{}", x)); };
            }
            CelType::Bytes { .. } => {
                // Bytes → lossy utf-8 string, matching `%s` formatting.
                push_first = quote! {
                    __out.push_str(&::std::string::String::from_utf8_lossy(
                        ::core::convert::AsRef::<[u8]>::as_ref(first),
                    ));
                };
                push_more = quote! {
                    __out.push_str(&::std::string::String::from_utf8_lossy(
                        ::core::convert::AsRef::<[u8]>::as_ref(x),
                    ));
                };
            }
            other => {
                return Err(FallbackReason::new(format!("join element type {other:?}")));
            }
        }
        Ok(Compiled {
            tokens: quote! {
                ({
                    let __sep = #sep_t;
                    let mut __it = (#target_t).iter();
                    let mut __out = ::std::string::String::new();
                    if let ::core::option::Option::Some(first) = __it.next() {
                        #push_first
                        for x in __it {
                            __out.push_str(__sep);
                            #push_more
                        }
                    }
                    __out
                })
            },
            ty: CelType::Str { owned: true },
            constant: None,
        })
    }

    fn str_case(&self, name: &str, target: &Compiled) -> Compiled {
        let s = string_as_str(target);
        let tokens = match name {
            "lowerAscii" => quote! { (#s).to_ascii_lowercase() },
            "upperAscii" => quote! { (#s).to_ascii_uppercase() },
            _ => unreachable!(),
        };
        Compiled {
            tokens,
            ty: CelType::Str { owned: true },
            constant: None,
        }
    }

    fn str_trim(&self, target: &Compiled) -> Compiled {
        let s = string_as_str(target);
        Compiled {
            tokens: quote! { (#s).trim().to_string() },
            ty: CelType::Str { owned: true },
            constant: None,
        }
    }

    /// CEL `math.*` extension. `name` is the function on `math` (without
    /// the namespace); we compile each arg, then emit Rust expressions
    /// that match the spec. Numerics promote within the call's args.
    fn math_call(&mut self, name: &str, args: &[IdedExpr]) -> Result<Compiled, FallbackReason> {
        let compiled_args: Vec<Compiled> = args
            .iter()
            .map(|a| self.expr(a))
            .collect::<Result<_, _>>()?;
        match (name, compiled_args.as_slice()) {
            // Unary: abs, ceil, floor, round, trunc, sign, isFinite,
            // isNaN, isInf.
            ("abs", [x]) => {
                let t = x.tokens.clone();
                match x.ty {
                    CelType::Int => Ok(Compiled {
                        tokens: quote! { ((#t).wrapping_abs()) },
                        ty: CelType::Int,
                        constant: None,
                    }),
                    CelType::Double => Ok(Compiled {
                        tokens: quote! { ((#t).abs()) },
                        ty: CelType::Double,
                        constant: None,
                    }),
                    CelType::UInt => Ok(x.clone()),
                    _ => Err(FallbackReason::new(format!("math.abs on {:?}", x.ty))),
                }
            }
            ("ceil" | "floor" | "round" | "trunc", [x]) => {
                let t = x.tokens.clone();
                let m = format_ident!("{name}");
                let coerced = if matches!(x.ty, CelType::Double) {
                    t
                } else if x.ty.is_numeric() {
                    quote! { ((#t) as f64) }
                } else {
                    return Err(FallbackReason::new(format!("math.{name} on {:?}", x.ty)));
                };
                Ok(Compiled {
                    tokens: quote! { ((#coerced).#m()) },
                    ty: CelType::Double,
                    constant: None,
                })
            }
            ("sign", [x]) => {
                let t = x.tokens.clone();
                match x.ty {
                    CelType::Int => Ok(Compiled {
                        tokens: quote! { ((#t).signum() as i64) },
                        ty: CelType::Int,
                        constant: None,
                    }),
                    CelType::Double => Ok(Compiled {
                        tokens: quote! {
                            (if (#t).is_nan() { f64::NAN }
                             else if (#t) > 0.0 { 1.0f64 }
                             else if (#t) < 0.0 { -1.0f64 }
                             else { 0.0f64 })
                        },
                        ty: CelType::Double,
                        constant: None,
                    }),
                    CelType::UInt => Ok(Compiled {
                        // sign of a uint: 1 if nonzero, 0 otherwise.
                        tokens: quote! { (if (#t) > 0u64 { 1u64 } else { 0u64 }) },
                        ty: CelType::UInt,
                        constant: None,
                    }),
                    _ => Err(FallbackReason::new(format!("math.sign on {:?}", x.ty))),
                }
            }
            ("isFinite" | "isNaN" | "isInf", [x]) => {
                let m = match name {
                    "isFinite" => "is_finite",
                    "isNaN" => "is_nan",
                    "isInf" => "is_infinite",
                    _ => unreachable!(),
                };
                self.float_predicate(m, x)
            }
            // n-ary greatest / least. Reduces with > / <.
            ("greatest" | "least", xs) if !xs.is_empty() => {
                let op_tok = if name == "greatest" {
                    quote! { > }
                } else {
                    quote! { < }
                };
                let result_ty = xs
                    .iter()
                    .try_fold(xs[0].ty.clone(), |acc, c| promote_numeric(&acc, &c.ty))?;
                // Build `if a > b { a } else { b }` chain over the args
                // widened to the promoted type.
                let mut iter = xs.iter().map(|c| numeric_cast(c, &result_ty));
                let first = iter.next().unwrap();
                let chained = iter.fold(first, |acc, next| {
                    quote! {
                        ({
                            let __a = (#acc);
                            let __b = (#next);
                            if __a #op_tok __b { __a } else { __b }
                        })
                    }
                });
                Ok(Compiled {
                    tokens: chained,
                    ty: result_ty,
                    constant: None,
                })
            }
            // Bit ops on uints (int gets reinterpreted as u64).
            ("bitAnd" | "bitOr" | "bitXor", [a, b]) => {
                let op = match name {
                    "bitAnd" => quote! { & },
                    "bitOr" => quote! { | },
                    "bitXor" => quote! { ^ },
                    _ => unreachable!(),
                };
                let result_ty = promote_numeric(&a.ty, &b.ty)?;
                if !matches!(result_ty, CelType::Int | CelType::UInt) {
                    return Err(FallbackReason::new(format!("math.{name} on non-integer")));
                }
                let at = numeric_cast(a, &result_ty);
                let bt = numeric_cast(b, &result_ty);
                Ok(Compiled {
                    tokens: quote! { ((#at) #op (#bt)) },
                    ty: result_ty,
                    constant: None,
                })
            }
            ("bitNot", [x]) => {
                if !matches!(x.ty, CelType::Int | CelType::UInt) {
                    return Err(FallbackReason::new(format!("math.bitNot on {:?}", x.ty)));
                }
                let t = x.tokens.clone();
                Ok(Compiled {
                    tokens: quote! { (!(#t)) },
                    ty: x.ty.clone(),
                    constant: None,
                })
            }
            ("bitShiftLeft" | "bitShiftRight", [a, b]) => {
                let op = if name == "bitShiftLeft" {
                    quote! { << }
                } else {
                    quote! { >> }
                };
                if !matches!(a.ty, CelType::Int | CelType::UInt) {
                    return Err(FallbackReason::new(format!("math.{name} lhs {:?}", a.ty)));
                }
                if !matches!(b.ty, CelType::Int | CelType::UInt) {
                    return Err(FallbackReason::new(format!("math.{name} rhs {:?}", b.ty)));
                }
                let at = a.tokens.clone();
                let bt = numeric_cast(b, &CelType::UInt);
                Ok(Compiled {
                    tokens: quote! { ((#at) #op ((#bt) as u32)) },
                    ty: a.ty.clone(),
                    constant: None,
                })
            }
            _ => Err(FallbackReason::new(format!(
                "math.{name}({} args)",
                compiled_args.len()
            ))),
        }
    }

    /// `optional.of(x)` / `optional.none()` / `optional.ofNonZeroValue(x)`
    /// — produce `CelType::Optional(T)` values backed by Rust `Option<T>`.
    fn optional_builder(
        &mut self,
        name: &str,
        args: &[IdedExpr],
    ) -> Result<Compiled, FallbackReason> {
        match (name, args.len()) {
            ("of", 1) => {
                let inner = self.expr(&args[0])?;
                let t = inner.tokens.clone();
                Ok(Compiled {
                    tokens: quote! { ::core::option::Option::Some(#t) },
                    ty: CelType::Optional(Box::new(inner.ty)),
                    constant: None,
                })
            }
            ("none", 0) => Ok(Compiled {
                // The element type is unknown at the call site; type as
                // `Optional<Dyn>` so `unify_branches` / `coerce` can
                // adapt to the matched `Optional<T>` when this appears in
                // a ternary. Emit the bare `None` so Rust's type inference
                // picks up the right `T` from the use site.
                tokens: quote! { ::core::option::Option::None },
                ty: CelType::Optional(Box::new(CelType::Dyn)),
                constant: None,
            }),
            ("ofNonZeroValue", 1) => {
                let inner = self.expr(&args[0])?;
                let t = inner.tokens.clone();
                // CEL spec: returns Some(x) if x is non-zero/empty, else
                // None. The check shape depends on the inner type.
                let check = match &inner.ty {
                    CelType::Int => quote! { ((#t) != 0i64) },
                    CelType::UInt => quote! { ((#t) != 0u64) },
                    CelType::Double => quote! { ((#t) != 0f64) },
                    CelType::Bool => quote! { (#t) },
                    CelType::Str { .. } => quote! { (!(#t).is_empty()) },
                    CelType::Bytes { .. } => quote! { (!(#t).is_empty()) },
                    CelType::List(_) => quote! { (!(#t).is_empty()) },
                    CelType::Map(_) => quote! { (!(#t).is_empty()) },
                    other => {
                        return Err(FallbackReason::new(format!(
                            "optional.ofNonZeroValue on {other:?}"
                        )));
                    }
                };
                let inner_ty = inner.ty;
                Ok(Compiled {
                    tokens: quote! {
                        (if #check {
                            ::core::option::Option::Some(#t)
                        } else {
                            ::core::option::Option::None
                        })
                    },
                    ty: CelType::Optional(Box::new(inner_ty)),
                    constant: None,
                })
            }
            _ => Err(FallbackReason::new(format!(
                "optional.{name}({} args)",
                args.len()
            ))),
        }
    }

    /// `<optional>.hasValue()` / `.orValue(d)` / `.value()` — methods on
    /// an `Optional<T>` receiver. The static type of the receiver carries
    /// the inner `T`, which we use to type-check `orValue`'s default.
    fn optional_method(
        name: &str,
        target: &Compiled,
        args: &[Compiled],
    ) -> Result<Compiled, FallbackReason> {
        let CelType::Optional(inner) = &target.ty else {
            return Err(FallbackReason::new(format!(
                "optional method on {:?}",
                target.ty
            )));
        };
        let inner_ty = inner.as_ref().clone();
        let t = target.tokens.clone();
        match (name, args.len()) {
            ("hasValue", 0) => Ok(Compiled {
                tokens: quote! { ((#t).is_some()) },
                ty: CelType::Bool,
                constant: None,
            }),
            ("orValue", 1) => {
                let default = coerce(&args[0], &inner_ty)?;
                Ok(Compiled {
                    tokens: quote! { ((#t).unwrap_or(#default)) },
                    ty: inner_ty,
                    constant: None,
                })
            }
            ("value", 0) => Ok(Compiled {
                tokens: quote! { ((#t).expect("CEL optional.value() on None")) },
                ty: inner_ty,
                constant: None,
            }),
            _ => Err(FallbackReason::new(format!(
                "optional.{name}({} args) on receiver",
                args.len()
            ))),
        }
    }

    /// `<list>.reverse()` / `<string>.reverse()`. Strings reverse by
    /// codepoint (chars), not bytes, matching CEL's unicode-string model.
    /// Lists collect references into a `Vec<&T>` and reverse in place —
    /// no per-element clone, which matters when elements are large
    /// (bytes-typed lists, message-typed lists). Result element type is
    /// marked `owned: false` for Str/Bytes so downstream iteration uses
    /// the borrowed path.
    fn reverse_call(target: &Compiled) -> Result<Compiled, FallbackReason> {
        match &target.ty {
            CelType::Str { .. } => {
                let s = string_as_str(target);
                Ok(Compiled {
                    tokens: quote! {
                        ((#s).chars().rev().collect::<::std::string::String>())
                    },
                    ty: CelType::Str { owned: true },
                    constant: None,
                })
            }
            CelType::List(elem) => {
                let t = target.tokens.clone();
                let elem_ty = match elem.as_ref() {
                    CelType::Str { .. } => CelType::Str { owned: false },
                    CelType::Bytes { .. } => CelType::Bytes { owned: false },
                    other => other.clone(),
                };
                Ok(Compiled {
                    tokens: quote! {
                        ({
                            let mut __v: ::std::vec::Vec<_> = (#t).iter().collect();
                            __v.reverse();
                            __v
                        })
                    },
                    ty: CelType::List(Box::new(elem_ty)),
                    constant: None,
                })
            }
            _ => Err(FallbackReason::new(format!("reverse on {:?}", target.ty))),
        }
    }

    /// `<list>.distinct()` — dedup preserving order. Element type must be
    /// `Eq` + `Hash` for our HashSet-based emission; floats / nested lists
    /// / maps don't qualify and fall back.
    fn distinct_call(target: &Compiled) -> Result<Compiled, FallbackReason> {
        let CelType::List(elem) = &target.ty else {
            return Err(FallbackReason::new(format!("distinct on {:?}", target.ty)));
        };
        let elem_ty = elem.as_ref().clone();
        if !matches!(
            elem_ty,
            CelType::Int
                | CelType::UInt
                | CelType::Bool
                | CelType::Str { .. }
                | CelType::Bytes { .. }
        ) {
            return Err(FallbackReason::new(format!(
                "distinct element type {elem_ty:?} not hashable"
            )));
        }
        let t = target.tokens.clone();
        // Preserve insertion order: walk the list, push to the result if
        // the element wasn't already seen. For Str/Bytes elements push
        // the reference (`&T`) — cloning a large bytes payload per
        // retained element would dominate the cost. For Copy scalars,
        // duplicate the value cheaply. Result element type is borrowed
        // for non-Copy types so downstream iteration matches the shape.
        let (push, out_elem_ty) = match &elem_ty {
            CelType::Str { .. } => (quote! { __out.push(__el); }, CelType::Str { owned: false }),
            CelType::Bytes { .. } => (
                quote! { __out.push(__el); },
                CelType::Bytes { owned: false },
            ),
            _ => (quote! { __out.push(*__el); }, elem_ty.clone()),
        };
        Ok(Compiled {
            tokens: quote! {
                ({
                    let mut __seen: ::std::collections::HashSet<_> = ::std::collections::HashSet::new();
                    let mut __out: ::std::vec::Vec<_> = ::std::vec::Vec::new();
                    for __el in (#t).iter() {
                        if __seen.insert(__el) {
                            #push
                        }
                    }
                    __out
                })
            },
            ty: CelType::List(Box::new(out_elem_ty)),
            constant: None,
        })
    }

    fn float_predicate(&self, method: &str, target: &Compiled) -> Result<Compiled, FallbackReason> {
        let t = target.tokens.clone();
        let m = format_ident!("{}", method);
        let coerced = if matches!(target.ty, CelType::Double) {
            quote! { (#t) }
        } else if target.ty.is_numeric() {
            quote! { ((#t) as f64) }
        } else {
            return Err(FallbackReason::new(format!("{method} on non-float")));
        };
        Ok(Compiled {
            tokens: quote! { (#coerced).#m() },
            ty: CelType::Bool,
            constant: None,
        })
    }

    fn proto_string_predicate(
        &self,
        name: &str,
        target: &Compiled,
    ) -> Result<Compiled, FallbackReason> {
        if !target.ty.is_string() {
            return Err(FallbackReason::new(format!("{name} on non-string")));
        }
        let s = string_as_str(target);
        let fn_name = match name {
            "isUuid" => quote! { is_uuid },
            "isHostname" => quote! { is_hostname },
            "isEmail" => quote! { is_email },
            "isUri" => quote! { is_uri },
            "isUriRef" => quote! { is_uri_ref },
            _ => return Err(FallbackReason::new("unknown string predicate")),
        };
        Ok(Compiled {
            tokens: quote! { ::protovalidate_buffa::rules::string::#fn_name(#s) },
            ty: CelType::Bool,
            constant: None,
        })
    }

    fn is_host_and_port(
        &self,
        target: &Compiled,
        port_required: &Compiled,
    ) -> Result<Compiled, FallbackReason> {
        if !target.ty.is_string() || !matches!(port_required.ty, CelType::Bool) {
            return Err(FallbackReason::new("isHostAndPort types"));
        }
        let s = string_as_str(target);
        let pr = port_required.tokens.clone();
        // Mirrors the dispatch in register_custom_functions in cel.rs.
        Ok(Compiled {
            tokens: quote! {
                ({
                    let __s: &str = #s;
                    let __pr: bool = #pr;
                    if ::protovalidate_buffa::rules::string::is_host_and_port(__s) { true }
                    else if __pr { false }
                    else if ::protovalidate_buffa::rules::string::is_hostname(__s)
                        || ::protovalidate_buffa::rules::string::is_ipv4(__s)
                        || ::protovalidate_buffa::rules::string::is_ipv6(__s) { true }
                    else if let ::core::option::Option::Some(inner) =
                        __s.strip_prefix('[').and_then(|r| r.strip_suffix(']'))
                    {
                        ::protovalidate_buffa::rules::string::is_ipv6(inner)
                    } else { false }
                })
            },
            ty: CelType::Bool,
            constant: None,
        })
    }

    /// Emit a dynamic-args `isIp` / `isIpPrefix` matching the runtime
    /// dispatch in `register_custom_functions`. Args may be int (version) or
    /// bool (strict), as `Option<...>` or bare.
    fn is_ip_dynamic(&self, name: &str, s: &TokenStream, args: &[Compiled]) -> Compiled {
        let arg0 = args.first().map(|c| {
            let t = c.tokens.clone();
            let ty = c.ty.clone();
            (t, ty)
        });
        let arg1 = args.get(1).map(|c| {
            let t = c.tokens.clone();
            let ty = c.ty.clone();
            (t, ty)
        });
        let arg_i64_local = |a: &Option<(TokenStream, CelType)>| -> TokenStream {
            match a {
                Some((t, CelType::Int)) => quote! { ::core::option::Option::Some(#t) },
                Some((t, CelType::UInt)) => quote! { ::core::option::Option::Some(#t as i64) },
                _ => quote! { ::core::option::Option::<i64>::None },
            }
        };
        let arg_bool_local = |a: &Option<(TokenStream, CelType)>| -> TokenStream {
            if let Some((t, CelType::Bool)) = a {
                quote! { ::core::option::Option::Some(#t) }
            } else {
                quote! { ::core::option::Option::<bool>::None }
            }
        };
        let a0_i = arg_i64_local(&arg0);
        let a0_b = arg_bool_local(&arg0);
        let a1_i = arg_i64_local(&arg1);
        let a1_b = arg_bool_local(&arg1);
        let tokens = if name == "isIp" {
            quote! {
                ({
                    let __s: &str = #s;
                    let __ver: i64 = (#a0_i).unwrap_or(0i64);
                    match __ver {
                        0i64 => ::protovalidate_buffa::rules::string::is_ip(__s),
                        4i64 => ::protovalidate_buffa::rules::string::is_ipv4(__s),
                        6i64 => ::protovalidate_buffa::rules::string::is_ipv6(__s),
                        _ => false,
                    }
                })
            }
        } else {
            quote! {
                ({
                    let __s: &str = #s;
                    let __v_i: ::core::option::Option<i64> = #a0_i;
                    let __v_b: ::core::option::Option<bool> = #a0_b;
                    let __s_i: ::core::option::Option<i64> = #a1_i;
                    let __s_b: ::core::option::Option<bool> = #a1_b;
                    let (__ver, __strict_opt): (i64, ::core::option::Option<bool>) =
                        if let (Some(n), Some(b)) = (__v_i, __s_b) {
                            (n, ::core::option::Option::Some(b))
                        } else if let Some(n) = __v_i {
                            (n, __s_b)
                        } else if let Some(b) = __v_b {
                            (__s_i.unwrap_or(0i64), ::core::option::Option::Some(b))
                        } else {
                            (0i64, __s_b)
                        };
                    let __strict: bool = __strict_opt.unwrap_or(false);
                    let (__addr_ok, __ver_valid) = match __ver {
                        0i64 => (true, true),
                        4i64 => (
                            __s.parse::<::std::net::Ipv4Addr>().is_ok()
                                || ::protovalidate_buffa::rules::string::is_ipv4_with_prefixlen(__s),
                            true,
                        ),
                        6i64 => (
                            __s.parse::<::std::net::Ipv6Addr>().is_ok()
                                || ::protovalidate_buffa::rules::string::is_ipv6_with_prefixlen(__s),
                            true,
                        ),
                        _ => (false, false),
                    };
                    if !__ver_valid {
                        false
                    } else if !__addr_ok {
                        false
                    } else if __strict {
                        match __ver {
                            4i64 => ::protovalidate_buffa::rules::string::is_ipv4_prefix(__s),
                            6i64 => ::protovalidate_buffa::rules::string::is_ipv6_prefix(__s),
                            _ => ::protovalidate_buffa::rules::string::is_ip_prefix(__s),
                        }
                    } else {
                        match __ver {
                            4i64 => ::protovalidate_buffa::rules::string::is_ipv4_with_prefixlen(__s),
                            6i64 => ::protovalidate_buffa::rules::string::is_ipv6_with_prefixlen(__s),
                            _ => ::protovalidate_buffa::rules::string::is_ip_with_prefixlen(__s),
                        }
                    }
                })
            }
        };
        Compiled {
            tokens,
            ty: CelType::Bool,
            constant: None,
        }
    }

    fn is_ip(
        &self,
        name: &str,
        target: &Compiled,
        args: &[Compiled],
    ) -> Result<Compiled, FallbackReason> {
        if !target.ty.is_string() {
            return Err(FallbackReason::new(format!("{name} on non-string")));
        }
        if args
            .iter()
            .any(|a| matches!(a.ty, CelType::Dyn | CelType::Null))
        {
            return Err(FallbackReason::new(format!("{name} arg type unclear")));
        }
        // If any arg is dynamic, emit a runtime dispatch that matches CEL's
        // semantics for any `(ver, strict)` combo.
        let dynamic = args.iter().any(|a| a.constant.is_none());
        let s = string_as_str(target);
        if dynamic {
            return Ok(self.is_ip_dynamic(name, &s, args));
        }
        let ver: i64 = match args.first() {
            None => 0,
            Some(c) => match &c.constant {
                Some(ConstValue::Int(n)) => *n,
                Some(ConstValue::UInt(n)) => *n as i64,
                _ => return Err(FallbackReason::new(format!("{name} non-const ver"))),
            },
        };
        let strict: Option<bool> = match args.get(1) {
            None => None,
            Some(c) => match &c.constant {
                Some(ConstValue::Bool(b)) => Some(*b),
                _ => return Err(FallbackReason::new(format!("{name} non-const strict"))),
            },
        };
        let s = string_as_str(target);
        let tokens = if name == "isIp" {
            match ver {
                0 => quote! { ::protovalidate_buffa::rules::string::is_ip(#s) },
                4 => quote! { ::protovalidate_buffa::rules::string::is_ipv4(#s) },
                6 => quote! { ::protovalidate_buffa::rules::string::is_ipv6(#s) },
                _ => quote! { false },
            }
        } else {
            // isIpPrefix
            let strict = strict.unwrap_or(false);
            let addr_ok = match ver {
                0 => quote! { true },
                4 => quote! { (#s).parse::<::std::net::Ipv4Addr>().is_ok()
                || ::protovalidate_buffa::rules::string::is_ipv4_with_prefixlen(#s) },
                6 => quote! { (#s).parse::<::std::net::Ipv6Addr>().is_ok()
                || ::protovalidate_buffa::rules::string::is_ipv6_with_prefixlen(#s) },
                _ => {
                    return Ok(Compiled {
                        tokens: quote! { false },
                        ty: CelType::Bool,
                        constant: Some(ConstValue::Bool(false)),
                    });
                }
            };
            let body = if strict {
                match ver {
                    4 => quote! { ::protovalidate_buffa::rules::string::is_ipv4_prefix(#s) },
                    6 => quote! { ::protovalidate_buffa::rules::string::is_ipv6_prefix(#s) },
                    _ => quote! { ::protovalidate_buffa::rules::string::is_ip_prefix(#s) },
                }
            } else {
                match ver {
                    4 => {
                        quote! { ::protovalidate_buffa::rules::string::is_ipv4_with_prefixlen(#s) }
                    }
                    6 => {
                        quote! { ::protovalidate_buffa::rules::string::is_ipv6_with_prefixlen(#s) }
                    }
                    _ => quote! { ::protovalidate_buffa::rules::string::is_ip_with_prefixlen(#s) },
                }
            };
            quote! {
                ({
                    let __s = #s;
                    if !(#addr_ok) { false } else { #body }
                })
            }
        };
        Ok(Compiled {
            tokens,
            ty: CelType::Bool,
            constant: None,
        })
    }

    fn dur_accessor(
        &self,
        name: &str,
        target: &Compiled,
        args: &[Compiled],
    ) -> Result<Compiled, FallbackReason> {
        let t = target.tokens.clone();
        if args.len() > 1 {
            return Err(FallbackReason::new(format!(
                "{name}: too many args ({})",
                args.len()
            )));
        }
        // Duration accessors take no arguments. Timestamp accessors take an
        // optional time-zone-name string (CEL spec); a non-empty arg only
        // makes sense for Timestamp targets.
        if !args.is_empty() && !matches!(target.ty, CelType::Timestamp) {
            return Err(FallbackReason::new(format!(
                "{name} on {:?} takes no args",
                target.ty
            )));
        }
        if let Some(arg) = args.first()
            && !matches!(arg.ty, CelType::Str { .. })
        {
            return Err(FallbackReason::new(format!(
                "{name} tz arg type {:?} not string",
                arg.ty
            )));
        }
        // Compute (ts_expr, ts_ty_path) — `ts_expr` is the DateTime the
        // accessor reads from, `ts_ty_path` is its concrete Rust type
        // (used as the receiver-type in UFCS so we don't need traits in
        // scope). With a tz arg, convert to chrono_tz::Tz; otherwise use
        // the stored FixedOffset.
        let (ts_expr, ts_ty_path) = args.first().map_or_else(
            || match &target.ty {
                CelType::Timestamp => (
                    t.clone(),
                    quote! { ::chrono::DateTime<::chrono::FixedOffset> },
                ),
                _ => (t.clone(), quote! {}),
            },
            |tz_arg| {
                let tz_tok = string_as_str(tz_arg);
                let converted = quote! {
                    {
                        let __cel_tz: ::protovalidate_buffa::chrono_tz::Tz =
                            (#tz_tok).parse().expect("CEL timestamp accessor: tz parse");
                        (#t).with_timezone(&__cel_tz)
                    }
                };
                (
                    converted,
                    quote! { ::chrono::DateTime<::protovalidate_buffa::chrono_tz::Tz> },
                )
            },
        );
        let body = match (name, &target.ty) {
            // --- Duration (no tz arg path) ---
            ("getSeconds", CelType::Duration) => quote! { (#t).num_seconds() },
            ("getMilliseconds", CelType::Duration) => quote! { (#t).num_milliseconds() },
            ("getMinutes", CelType::Duration) => quote! { (#t).num_minutes() },
            ("getHours", CelType::Duration) => quote! { (#t).num_hours() },
            // --- Timestamp ---
            // Date components.
            ("getFullYear", CelType::Timestamp) => quote! {
                (i64::from(<#ts_ty_path as ::chrono::Datelike>::year(&(#ts_expr))))
            },
            ("getMonth", CelType::Timestamp) => quote! {
                // CEL `getMonth` is 0-based; chrono's `month()` is 1-based.
                (i64::from(<#ts_ty_path as ::chrono::Datelike>::month(&(#ts_expr))) - 1)
            },
            ("getDate" | "getDayOfMonth", CelType::Timestamp) => quote! {
                // CEL is 0-based per cel-go; chrono's `day()` is 1-based.
                (i64::from(<#ts_ty_path as ::chrono::Datelike>::day(&(#ts_expr))) - 1)
            },
            ("getDayOfWeek", CelType::Timestamp) => quote! {
                // CEL: Sunday = 0.
                (i64::from(<#ts_ty_path as ::chrono::Datelike>::weekday(&(#ts_expr)).num_days_from_sunday()))
            },
            ("getDayOfYear", CelType::Timestamp) => quote! {
                // CEL is 0-based; chrono's `ordinal()` is 1-based.
                (i64::from(<#ts_ty_path as ::chrono::Datelike>::ordinal(&(#ts_expr))) - 1)
            },
            // Time components.
            ("getHours", CelType::Timestamp) => quote! {
                (i64::from(<#ts_ty_path as ::chrono::Timelike>::hour(&(#ts_expr))))
            },
            ("getMinutes", CelType::Timestamp) => quote! {
                (i64::from(<#ts_ty_path as ::chrono::Timelike>::minute(&(#ts_expr))))
            },
            ("getSeconds", CelType::Timestamp) => quote! {
                (i64::from(<#ts_ty_path as ::chrono::Timelike>::second(&(#ts_expr))))
            },
            ("getMilliseconds", CelType::Timestamp) => quote! {
                // chrono `nanosecond()` is sub-second nanos; convert to ms.
                (i64::from(<#ts_ty_path as ::chrono::Timelike>::nanosecond(&(#ts_expr)) / 1_000_000))
            },
            _ => return Err(FallbackReason::new(format!("{name} on {:?}", target.ty))),
        };
        Ok(Compiled {
            tokens: body,
            ty: CelType::Int,
            constant: None,
        })
    }

    fn op_conditional(&mut self, args: &[IdedExpr]) -> Result<Compiled, FallbackReason> {
        if args.len() != 3 {
            return Err(FallbackReason::new("conditional arity"));
        }
        let cond = self.expr(&args[0])?;
        if cond.ty != CelType::Bool {
            return Err(FallbackReason::new("conditional non-bool cond"));
        }
        let then_branch = self.expr(&args[1])?;
        let else_branch = self.expr(&args[2])?;
        let ty = unify_branches(&then_branch.ty, &else_branch.ty)?;
        let cond_t = cond.tokens;
        let then_t = coerce(&then_branch, &ty)?;
        let else_t = coerce(&else_branch, &ty)?;
        Ok(Compiled {
            tokens: quote! { (if #cond_t { #then_t } else { #else_t }) },
            ty,
            constant: None,
        })
    }

    fn op_logical(&mut self, args: &[IdedExpr], is_and: bool) -> Result<Compiled, FallbackReason> {
        if args.len() != 2 {
            return Err(FallbackReason::new("logical arity"));
        }
        let lhs = self.expr(&args[0])?;
        let rhs = self.expr(&args[1])?;
        if lhs.ty != CelType::Bool || rhs.ty != CelType::Bool {
            return Err(FallbackReason::new("logical non-bool"));
        }
        let lt = lhs.tokens;
        let rt = rhs.tokens;
        let tokens = if is_and {
            quote! { (#lt && #rt) }
        } else {
            quote! { (#lt || #rt) }
        };
        Ok(Compiled {
            tokens,
            ty: CelType::Bool,
            constant: None,
        })
    }

    fn op_not(&mut self, args: &[IdedExpr]) -> Result<Compiled, FallbackReason> {
        if args.len() != 1 {
            return Err(FallbackReason::new("not arity"));
        }
        let a = self.expr(&args[0])?;
        if a.ty != CelType::Bool {
            return Err(FallbackReason::new("not non-bool"));
        }
        let t = a.tokens;
        Ok(Compiled {
            tokens: quote! { (!#t) },
            ty: CelType::Bool,
            constant: None,
        })
    }

    fn op_negate(&mut self, args: &[IdedExpr]) -> Result<Compiled, FallbackReason> {
        if args.len() != 1 {
            return Err(FallbackReason::new("negate arity"));
        }
        let a = self.expr(&args[0])?;
        let t = a.tokens;
        match a.ty {
            CelType::Int => Ok(Compiled {
                tokens: quote! { (-(#t)) },
                ty: CelType::Int,
                constant: None,
            }),
            CelType::Double => Ok(Compiled {
                tokens: quote! { (-(#t)) },
                ty: CelType::Double,
                constant: None,
            }),
            CelType::UInt => Ok(Compiled {
                // CEL unary minus on uint coerces to int per spec.
                tokens: quote! { (-(#t as i64)) },
                ty: CelType::Int,
                constant: None,
            }),
            _ => Err(FallbackReason::new("negate non-numeric")),
        }
    }

    fn op_arith(&mut self, name: &str, args: &[IdedExpr]) -> Result<Compiled, FallbackReason> {
        if args.len() != 2 {
            return Err(FallbackReason::new("arith arity"));
        }
        let lhs = self.expr(&args[0])?;
        let rhs = self.expr(&args[1])?;
        // String concatenation via `+`.
        if name == op::ADD && lhs.ty.is_string() && rhs.ty.is_string() {
            let l = string_as_str(&lhs);
            let r = string_as_str(&rhs);
            return Ok(Compiled {
                tokens: quote! { ({ let mut s = ::std::string::String::with_capacity(#l.len() + #r.len()); s.push_str(#l); s.push_str(#r); s }) },
                ty: CelType::Str { owned: true },
                constant: None,
            });
        }
        if name == op::ADD && lhs.ty.is_bytes() && rhs.ty.is_bytes() {
            let l = bytes_as_slice(&lhs);
            let r = bytes_as_slice(&rhs);
            return Ok(Compiled {
                tokens: quote! { ({ let mut v: ::std::vec::Vec<u8> = ::std::vec::Vec::with_capacity(#l.len() + #r.len()); v.extend_from_slice(#l); v.extend_from_slice(#r); v }) },
                ty: CelType::Bytes { owned: true },
                constant: None,
            });
        }
        // Numeric arithmetic with CEL promotion rules.
        if !lhs.ty.is_numeric() || !rhs.ty.is_numeric() {
            return Err(FallbackReason::new(format!(
                "arith on non-numeric: {:?} {} {:?}",
                lhs.ty, name, rhs.ty
            )));
        }
        let result_ty = promote_numeric(&lhs.ty, &rhs.ty)?;
        let lt = numeric_cast(&lhs, &result_ty);
        let rt = numeric_cast(&rhs, &result_ty);
        let op_tok = match name {
            op::ADD => quote! { + },
            op::SUBSTRACT => quote! { - },
            op::MULTIPLY => quote! { * },
            op::DIVIDE => quote! { / },
            op::MODULO => quote! { % },
            _ => unreachable!(),
        };
        Ok(Compiled {
            tokens: quote! { ((#lt) #op_tok (#rt)) },
            ty: result_ty,
            constant: None,
        })
    }

    fn op_cmp(&mut self, name: &str, args: &[IdedExpr]) -> Result<Compiled, FallbackReason> {
        if args.len() != 2 {
            return Err(FallbackReason::new("cmp arity"));
        }
        let lhs = self.expr(&args[0])?;
        let rhs = self.expr(&args[1])?;
        let op_tok = match name {
            op::EQUALS => quote! { == },
            op::NOT_EQUALS => quote! { != },
            op::GREATER => quote! { > },
            op::GREATER_EQUALS => quote! { >= },
            op::LESS => quote! { < },
            op::LESS_EQUALS => quote! { <= },
            _ => unreachable!(),
        };
        let (lt, rt) = match (&lhs.ty, &rhs.ty) {
            (CelType::Str { .. }, CelType::Str { .. }) => {
                (string_as_str(&lhs), string_as_str(&rhs))
            }
            (CelType::Bytes { .. }, CelType::Bytes { .. }) => {
                (bytes_as_slice(&lhs), bytes_as_slice(&rhs))
            }
            (CelType::Bool, CelType::Bool) => (lhs.tokens.clone(), rhs.tokens.clone()),
            (CelType::Null, CelType::Null) => {
                return Ok(Compiled {
                    tokens: match name {
                        op::EQUALS => quote! { true },
                        op::NOT_EQUALS => quote! { false },
                        _ => return Err(FallbackReason::new("ord cmp on null")),
                    },
                    ty: CelType::Bool,
                    constant: None,
                });
            }
            (CelType::Duration, CelType::Duration) | (CelType::Timestamp, CelType::Timestamp) => {
                (lhs.tokens.clone(), rhs.tokens.clone())
            }
            (a, b) if a.is_numeric() && b.is_numeric() => {
                // CEL spec: int and uint compare by mathematical value
                // regardless of the wider type rules used for arithmetic.
                // Promote both to i128 — i64 and u64 each fit exactly, so
                // the comparison is lossless. Falls through to the normal
                // numeric promotion for all other numeric pairings (e.g.
                // int + double).
                if matches!(
                    (a, b),
                    (CelType::Int, CelType::UInt) | (CelType::UInt, CelType::Int)
                ) {
                    let lt = lhs.tokens.clone();
                    let rt = rhs.tokens.clone();
                    (quote! { ((#lt) as i128) }, quote! { ((#rt) as i128) })
                } else {
                    let t = promote_numeric(a, b)?;
                    (numeric_cast(&lhs, &t), numeric_cast(&rhs, &t))
                }
            }
            (a, b) => {
                return Err(FallbackReason::new(format!(
                    "cmp type mismatch: {a:?} vs {b:?}"
                )));
            }
        };
        Ok(Compiled {
            tokens: quote! { (#lt #op_tok #rt) },
            ty: CelType::Bool,
            constant: None,
        })
    }

    fn op_index(&mut self, args: &[IdedExpr]) -> Result<Compiled, FallbackReason> {
        if args.len() != 2 {
            return Err(FallbackReason::new("index arity"));
        }
        let operand = self.expr(&args[0])?;
        let key = self.expr(&args[1])?;
        match &operand.ty {
            CelType::Map(map_ty) => {
                let MapTy {
                    key_cel,
                    value_cel: val_ty,
                    key_rust,
                    ..
                } = map_ty.as_ref();
                let key_t = coerce(&key, key_cel)?;
                // For String / Bytes keys the HashMap stores `String` /
                // `Vec<u8>` and `.get` accepts `&str` / `&[u8]` directly
                // (via Borrow). For scalar keys we wrap in `&` to satisfy
                // `Borrow<K>`.
                let key_lookup_raw = cast_to_rust_scalar(&key_t, key_cel, *key_rust);
                let key_lookup = if matches!(key_rust, RustScalar::Str | RustScalar::Bytes) {
                    quote! { #key_lookup_raw }
                } else {
                    quote! { &(#key_lookup_raw) }
                };
                let op_t = operand.tokens;
                // For string / bytes values, return `&str` / `&[u8]` to
                // avoid cloning. For scalars, copy. The protovalidate
                // pattern guarantees the key is present (because the
                // comprehension iterates the map's own keys).
                let (tokens, ty) = match val_ty {
                    CelType::Str { .. } => (
                        quote! {
                            ((#op_t).get(#key_lookup).map_or("", |__v| __v.as_str()))
                        },
                        CelType::Str { owned: false },
                    ),
                    CelType::Bytes { .. } => (
                        quote! {
                            ((#op_t).get(#key_lookup).map_or(&[][..], |__v| __v.as_slice()))
                        },
                        CelType::Bytes { owned: false },
                    ),
                    CelType::Int => (
                        quote! {
                            ((#op_t).get(#key_lookup).map_or(0i64, |__v| ::protovalidate_buffa::cel::CelScalar::cel_int(*__v)))
                        },
                        CelType::Int,
                    ),
                    CelType::UInt => (
                        quote! {
                            ((#op_t).get(#key_lookup).map_or(0u64, |__v| ::protovalidate_buffa::cel::CelScalar::cel_uint(*__v)))
                        },
                        CelType::UInt,
                    ),
                    CelType::Double => (
                        quote! {
                            ((#op_t).get(#key_lookup).map_or(0f64, |__v| ::protovalidate_buffa::cel::CelScalar::cel_double(*__v)))
                        },
                        CelType::Double,
                    ),
                    CelType::Bool => (
                        quote! {
                            ((#op_t).get(#key_lookup).copied().unwrap_or(false))
                        },
                        CelType::Bool,
                    ),
                    CelType::Message(schema) => {
                        // Return a `&Msg` reference. For typical
                        // protovalidate usage (`this.all(k, this[k]...)`
                        // over the map's own keys), the key is guaranteed
                        // present; we use `.expect()` since a missing
                        // value here would indicate a CEL program bug
                        // rather than a validation failure.
                        (
                            quote! {
                                (#op_t).get(#key_lookup).expect("CEL map index miss")
                            },
                            CelType::Message(schema.clone()),
                        )
                    }
                    _ => {
                        return Err(FallbackReason::new(format!("index on map<_, {val_ty:?}>")));
                    }
                };
                Ok(Compiled {
                    tokens,
                    ty,
                    constant: None,
                })
            }
            CelType::List(elem_ty) => {
                // CEL `xs[i]` is an int-indexed lookup. Out-of-range is a
                // runtime error in CEL — we mirror that via `.expect()`,
                // matching the protovalidate convention used for map
                // indexing where the comprehension guarantees presence.
                let key_t = coerce(&key, &CelType::Int)?;
                let op_t = operand.tokens;
                // List of `T` is emitted either as `&[T]` (from a literal
                // via `[…].as_slice()`) or as `&Vec<T>` (from a field
                // access). Both support indexing by `usize`; cast the i64
                // CEL index here.
                let idx_t = quote! { ((#key_t) as usize) };
                let (tokens, ty) = match elem_ty.as_ref() {
                    CelType::Str { .. } => (
                        quote! {
                            ({
                                let __cel_v = &(#op_t)[#idx_t];
                                ::core::convert::AsRef::<str>::as_ref(__cel_v)
                            })
                        },
                        CelType::Str { owned: false },
                    ),
                    CelType::Bytes { .. } => (
                        quote! {
                            ({
                                let __cel_v = &(#op_t)[#idx_t];
                                ::core::convert::AsRef::<[u8]>::as_ref(__cel_v)
                            })
                        },
                        CelType::Bytes { owned: false },
                    ),
                    CelType::Int => (
                        quote! {
                            (::protovalidate_buffa::cel::CelScalar::cel_int((#op_t)[#idx_t]))
                        },
                        CelType::Int,
                    ),
                    CelType::UInt => (
                        quote! {
                            (::protovalidate_buffa::cel::CelScalar::cel_uint((#op_t)[#idx_t]))
                        },
                        CelType::UInt,
                    ),
                    CelType::Double => (
                        quote! {
                            (::protovalidate_buffa::cel::CelScalar::cel_double((#op_t)[#idx_t]))
                        },
                        CelType::Double,
                    ),
                    CelType::Bool => (quote! { ((#op_t)[#idx_t]) }, CelType::Bool),
                    CelType::Message(schema) => (
                        quote! { (&(#op_t)[#idx_t]) },
                        CelType::Message(schema.clone()),
                    ),
                    other => {
                        return Err(FallbackReason::new(format!(
                            "list index on element type {other:?}"
                        )));
                    }
                };
                Ok(Compiled {
                    tokens,
                    ty,
                    constant: None,
                })
            }
            _ => Err(FallbackReason::new(format!("index on {:?}", operand.ty))),
        }
    }

    /// Optional indexing: `m[?k]` on a map, `xs[?i]` on a list. Returns
    /// `Optional<V>` / `Optional<E>` — `Some(value)` if the key/index is
    /// present, `None` otherwise. Unlike `_[_]`, never panics on a miss.
    fn op_opt_index(&mut self, args: &[IdedExpr]) -> Result<Compiled, FallbackReason> {
        if args.len() != 2 {
            return Err(FallbackReason::new("opt_index arity"));
        }
        let operand = self.expr(&args[0])?;
        let key = self.expr(&args[1])?;
        match &operand.ty {
            CelType::Map(map_ty) => {
                let MapTy {
                    key_cel,
                    value_cel: val_ty,
                    key_rust,
                    ..
                } = map_ty.as_ref();
                let key_t = coerce(&key, key_cel)?;
                let key_lookup_raw = cast_to_rust_scalar(&key_t, key_cel, *key_rust);
                let key_lookup = if matches!(key_rust, RustScalar::Str | RustScalar::Bytes) {
                    quote! { #key_lookup_raw }
                } else {
                    quote! { &(#key_lookup_raw) }
                };
                let op_t = operand.tokens;
                // Per-value-type extraction. Strings/bytes return
                // borrowed views (`Option<&str>` / `Option<&[u8]>`) —
                // cloning would copy the whole value, which can be
                // arbitrarily large (a `bytes` proto field is often the
                // dominant cost in a request). Scalars use `.copied()`
                // since duplicating a fixed-size scalar is cheap.
                let (tokens, val_owned_ty) = match val_ty {
                    CelType::Str { .. } => (
                        quote! {
                            ((#op_t).get(#key_lookup).map(|__v| ::core::convert::AsRef::<str>::as_ref(__v)))
                        },
                        CelType::Str { owned: false },
                    ),
                    CelType::Bytes { .. } => (
                        quote! {
                            ((#op_t).get(#key_lookup).map(|__v| ::core::convert::AsRef::<[u8]>::as_ref(__v)))
                        },
                        CelType::Bytes { owned: false },
                    ),
                    CelType::Int => (
                        quote! { ((#op_t).get(#key_lookup).copied().map(|__v| ::protovalidate_buffa::cel::CelScalar::cel_int(__v))) },
                        CelType::Int,
                    ),
                    CelType::UInt => (
                        quote! { ((#op_t).get(#key_lookup).copied().map(|__v| ::protovalidate_buffa::cel::CelScalar::cel_uint(__v))) },
                        CelType::UInt,
                    ),
                    CelType::Double => (
                        quote! { ((#op_t).get(#key_lookup).copied().map(|__v| ::protovalidate_buffa::cel::CelScalar::cel_double(__v))) },
                        CelType::Double,
                    ),
                    CelType::Bool => (
                        quote! { ((#op_t).get(#key_lookup).copied()) },
                        CelType::Bool,
                    ),
                    other => {
                        return Err(FallbackReason::new(format!(
                            "opt_index on map<_, {other:?}>"
                        )));
                    }
                };
                Ok(Compiled {
                    tokens,
                    ty: CelType::Optional(Box::new(val_owned_ty)),
                    constant: None,
                })
            }
            CelType::List(elem_ty) => {
                let key_t = coerce(&key, &CelType::Int)?;
                let op_t = operand.tokens;
                let idx_t = quote! { ((#key_t) as usize) };
                let (tokens, owned_ty) = match elem_ty.as_ref() {
                    // Strings/bytes: borrow, don't clone — see opt_index
                    // map arm above for the rationale.
                    CelType::Str { .. } => (
                        quote! {
                            ((#op_t).get(#idx_t).map(|__v| ::core::convert::AsRef::<str>::as_ref(__v)))
                        },
                        CelType::Str { owned: false },
                    ),
                    CelType::Bytes { .. } => (
                        quote! {
                            ((#op_t).get(#idx_t).map(|__v| ::core::convert::AsRef::<[u8]>::as_ref(__v)))
                        },
                        CelType::Bytes { owned: false },
                    ),
                    CelType::Int => (
                        quote! { ((#op_t).get(#idx_t).copied().map(|__v| ::protovalidate_buffa::cel::CelScalar::cel_int(__v))) },
                        CelType::Int,
                    ),
                    CelType::UInt => (
                        quote! { ((#op_t).get(#idx_t).copied().map(|__v| ::protovalidate_buffa::cel::CelScalar::cel_uint(__v))) },
                        CelType::UInt,
                    ),
                    CelType::Double => (
                        quote! { ((#op_t).get(#idx_t).copied().map(|__v| ::protovalidate_buffa::cel::CelScalar::cel_double(__v))) },
                        CelType::Double,
                    ),
                    CelType::Bool => (quote! { ((#op_t).get(#idx_t).copied()) }, CelType::Bool),
                    other => {
                        return Err(FallbackReason::new(format!("opt_index on list<{other:?}>")));
                    }
                };
                Ok(Compiled {
                    tokens,
                    ty: CelType::Optional(Box::new(owned_ty)),
                    constant: None,
                })
            }
            _ => Err(FallbackReason::new(format!(
                "opt_index on {:?}",
                operand.ty
            ))),
        }
    }

    /// Optional select: `o?.field` on `Optional<Message>` — `Some(field)`
    /// if `o.is_some()`, else `None`. Only supported when the operand is
    /// already typed as `Optional<Message>` or `Optional<MessageRef>`.
    fn op_opt_select(&mut self, args: &[IdedExpr]) -> Result<Compiled, FallbackReason> {
        if args.len() != 2 {
            return Err(FallbackReason::new("opt_select arity"));
        }
        // The cel-rs parser produces `OPT_SELECT(operand, Ident(field))`.
        let operand = self.expr(&args[0])?;
        let Expr::Ident(field_name) = &args[1].expr else {
            return Err(FallbackReason::new("opt_select: field not ident"));
        };
        let CelType::Optional(inner_ty) = &operand.ty else {
            return Err(FallbackReason::new(format!(
                "opt_select on non-optional {:?}",
                operand.ty
            )));
        };
        // Inner type must be a Message we can resolve.
        let schema = match inner_ty.as_ref() {
            CelType::Message(s) => s.as_ref().clone(),
            CelType::MessageRef(fqn) => self
                .schemas
                .and_then(|s| s.get(fqn))
                .ok_or_else(|| FallbackReason::new(format!("MessageRef({fqn}) not in index")))?,
            other => {
                return Err(FallbackReason::new(format!(
                    "opt_select: inner type {other:?} not a message"
                )));
            }
        };
        let entry = schema
            .fields
            .iter()
            .find(|e| e.proto_name == *field_name)
            .ok_or_else(|| {
                FallbackReason::new(format!("opt_select: unknown field {field_name}"))
            })?;
        let rust_ident = crate::emit::field_ident(&entry.rust_ident);
        let op_t = operand.tokens;
        // Map `Option<&Message>` through `.map(|m| m.<field>)`. The exact
        // shape depends on the field's CEL type and the binding semantics
        // of `select_message_field`. Use the simple by-value clone path.
        let (tokens, out_ty) = match &entry.ty {
            CelType::Int => (
                quote! {
                    ((#op_t).as_ref().map(|__m| ::protovalidate_buffa::cel::CelScalar::cel_int(__m.#rust_ident)))
                },
                CelType::Int,
            ),
            CelType::UInt => (
                quote! {
                    ((#op_t).as_ref().map(|__m| ::protovalidate_buffa::cel::CelScalar::cel_uint(__m.#rust_ident)))
                },
                CelType::UInt,
            ),
            CelType::Double => (
                quote! {
                    ((#op_t).as_ref().map(|__m| ::protovalidate_buffa::cel::CelScalar::cel_double(__m.#rust_ident)))
                },
                CelType::Double,
            ),
            CelType::Bool => (
                quote! { ((#op_t).as_ref().map(|__m| __m.#rust_ident)) },
                CelType::Bool,
            ),
            CelType::Str { .. } => (
                // Return a borrowed `&str` view; allocating a String here
                // would duplicate a potentially large field every time
                // `o?.field` was evaluated.
                quote! {
                    ((#op_t).as_ref().map(|__m| ::core::convert::AsRef::<str>::as_ref(&__m.#rust_ident)))
                },
                CelType::Str { owned: false },
            ),
            other => {
                return Err(FallbackReason::new(format!(
                    "opt_select: field type {other:?} not supported"
                )));
            }
        };
        Ok(Compiled {
            tokens,
            ty: CelType::Optional(Box::new(out_ty)),
            constant: None,
        })
    }

    fn op_in(&mut self, args: &[IdedExpr]) -> Result<Compiled, FallbackReason> {
        if args.len() != 2 {
            return Err(FallbackReason::new("in arity"));
        }
        let needle = self.expr(&args[0])?;
        let hay = self.expr(&args[1])?;
        match &hay.ty {
            CelType::Map(map_ty) => {
                // CEL: `key in map` tests key presence. Mirrors the key
                // coercion in `op_index` — coerce the needle to the map's
                // CEL key type, then cast back to the underlying Rust
                // scalar; `Str` / `Bytes` keys hand off a `&str` / `&[u8]`
                // directly (HashMap accepts via `Borrow`), other scalars
                // get a `&` reference.
                let MapTy {
                    key_cel, key_rust, ..
                } = map_ty.as_ref();
                let needle_coerced = coerce(&needle, key_cel)?;
                let key_lookup_raw = cast_to_rust_scalar(&needle_coerced, key_cel, *key_rust);
                let key_lookup = if matches!(key_rust, RustScalar::Str | RustScalar::Bytes) {
                    quote! { #key_lookup_raw }
                } else {
                    quote! { &(#key_lookup_raw) }
                };
                let hay_t = hay.tokens;
                Ok(Compiled {
                    tokens: quote! { ((#hay_t).contains_key(#key_lookup)) },
                    ty: CelType::Bool,
                    constant: None,
                })
            }
            CelType::List(elem_ty) => {
                // Coerce needle to element type for numeric/string lists.
                let needle_c = coerce(&needle, elem_ty)?;
                let hay_t = hay.tokens;
                let target = match elem_ty.as_ref() {
                    CelType::Str { .. } => {
                        quote! { (#hay_t).iter().any(|__x| {
                            let __l: &str = ::core::convert::AsRef::as_ref(&__x);
                            __l == (#needle_c)
                        }) }
                    }
                    CelType::Bytes { .. } => {
                        quote! { (#hay_t).iter().any(|__x| {
                            let __l: &[u8] = ::core::convert::AsRef::as_ref(&__x);
                            __l == (#needle_c)
                        }) }
                    }
                    _ => quote! { (#hay_t).iter().any(|__x| (*__x) == (#needle_c)) },
                };
                Ok(Compiled {
                    tokens: target,
                    ty: CelType::Bool,
                    constant: None,
                })
            }
            _ => Err(FallbackReason::new("in: rhs must be list")),
        }
    }

    fn list_lit(&mut self, list: &ListExpr) -> Result<Compiled, FallbackReason> {
        if !list.optional_indices.is_empty() {
            return Err(FallbackReason::new("optional list elements"));
        }
        if list.elements.is_empty() {
            return Ok(Compiled {
                tokens: quote! { (&[] as &[i64]) },
                ty: CelType::List(Box::new(CelType::Dyn)),
                constant: Some(ConstValue::List(Vec::new())),
            });
        }
        // Compile each element; compute the list's element type. For
        // heterogeneous numeric lists (e.g. `[1, 2.0]`), promote to the
        // widest numeric — int → uint → double — so we don't truncate
        // Double down to Int.
        let mut compiled: Vec<Compiled> = Vec::with_capacity(list.elements.len());
        for el in &list.elements {
            compiled.push(self.expr(el)?);
        }
        let mut elem_ty = compiled[0].ty.clone();
        for c in &compiled[1..] {
            if c.ty == elem_ty {
                continue;
            }
            if c.ty.is_numeric() && elem_ty.is_numeric() {
                elem_ty = promote_numeric(&elem_ty, &c.ty)?;
                continue;
            }
            return Err(FallbackReason::new("heterogeneous list literal"));
        }
        let coerced: Vec<TokenStream> = compiled
            .iter()
            .map(|c| coerce(c, &elem_ty))
            .collect::<Result<_, _>>()?;
        let constant_vals: Option<Vec<ConstValue>> =
            compiled.iter().map(|c| c.constant.clone()).collect();
        let constant = constant_vals.map(ConstValue::List);
        Ok(Compiled {
            tokens: quote! { [ #( #coerced ),* ].as_slice() },
            ty: CelType::List(Box::new(elem_ty)),
            constant,
        })
    }

    fn map_lit(&mut self, m: &MapExpr) -> Result<Compiled, FallbackReason> {
        // Empty literal — concrete type doesn't matter because the only
        // useful op is `size({}) == 0`, which works for any HashMap.
        if m.entries.is_empty() {
            return Ok(Compiled {
                tokens: quote! { ::std::collections::HashMap::<i64, i64>::new() },
                ty: CelType::Map(Box::new(MapTy {
                    key_cel: CelType::Dyn,
                    value_cel: CelType::Dyn,
                    key_rust: RustScalar::I64,
                    value_rust: RustScalar::I64,
                })),
                constant: None,
            });
        }
        let mut entries: Vec<(Compiled, Compiled)> = Vec::with_capacity(m.entries.len());
        for entry in &m.entries {
            let EntryExpr::MapEntry(me) = &entry.expr else {
                return Err(FallbackReason::new("non-map entry in map literal"));
            };
            if me.optional {
                return Err(FallbackReason::new("optional map entry"));
            }
            let k = self.expr(&me.key)?;
            let v = self.expr(&me.value)?;
            entries.push((k, v));
        }
        let key_ty = entries[0].0.ty.clone();
        let value_ty = entries[0].1.ty.clone();
        for (k, v) in &entries[1..] {
            if k.ty != key_ty {
                return Err(FallbackReason::new("heterogeneous map literal keys"));
            }
            if v.ty != value_ty {
                return Err(FallbackReason::new("heterogeneous map literal values"));
            }
        }
        // CEL map keys must be hashable (bool / int / uint / string).
        // f64 has no Hash impl; double keys are rejected here.
        let key_rust = match &key_ty {
            CelType::Int => RustScalar::I64,
            CelType::UInt => RustScalar::U64,
            CelType::Bool => RustScalar::Bool,
            CelType::Str { .. } => RustScalar::Str,
            _ => {
                return Err(FallbackReason::new(format!(
                    "map literal key type {key_ty:?} not hashable"
                )));
            }
        };
        let value_rust = match &value_ty {
            CelType::Int => RustScalar::I64,
            CelType::UInt => RustScalar::U64,
            CelType::Double => RustScalar::F64,
            CelType::Bool => RustScalar::Bool,
            CelType::Str { .. } => RustScalar::Str,
            CelType::Bytes { .. } => RustScalar::Bytes,
            _ => {
                return Err(FallbackReason::new(format!(
                    "map literal value type {value_ty:?} not supported"
                )));
            }
        };
        let owned_key = matches!(key_rust, RustScalar::Str);
        let owned_value = matches!(value_rust, RustScalar::Str | RustScalar::Bytes);
        let entry_toks = entries.iter().map(|(k, v)| {
            let kt = &k.tokens;
            let vt = &v.tokens;
            let kt = if owned_key {
                quote! { ::std::string::String::from(#kt) }
            } else {
                quote! { #kt }
            };
            let vt = match value_rust {
                RustScalar::Str => quote! { ::std::string::String::from(#vt) },
                RustScalar::Bytes => quote! { (#vt).to_vec() },
                _ => quote! { #vt },
            };
            let _ = owned_value; // silence unused warning; pattern is for readability
            quote! { (#kt, #vt) }
        });
        Ok(Compiled {
            tokens: quote! {
                ::std::collections::HashMap::from([ #(#entry_toks),* ])
            },
            ty: CelType::Map(Box::new(MapTy {
                key_cel: key_ty,
                value_cel: value_ty,
                key_rust,
                value_rust,
            })),
            constant: None,
        })
    }

    /// Handle `xs.all(k, v, P)` / `xs.exists(...)` / `xs.exists_one(...)`
    /// / `xs.filter(...)` / `xs.map(...)` — the 3-/4-arg comprehension
    /// shapes cel-rs's macro expander doesn't recognize. Returns
    /// `Ok(None)` when the call's name + arity don't match a two-var
    /// comprehension shape; the caller falls through to normal method
    /// dispatch.
    fn try_two_var_comprehension(
        &mut self,
        call: &CallExpr,
    ) -> Result<Option<Compiled>, FallbackReason> {
        let Some(target_expr) = call.target.as_ref() else {
            return Ok(None);
        };
        let name = call.func_name.as_str();
        let kind = match (name, call.args.len()) {
            ("all" | "exists" | "exists_one" | "existsOne" | "filter", 3) => name,
            // cel-rs's macro expander handles 2-arg and 3-arg `.map` as
            // single-var (filter-and-map) comprehensions, so 3-arg map
            // never reaches this path. Only the 4-arg
            // `.map(k, v, filter, mapped)` shape is ours.
            ("map", 4) => name,
            _ => return Ok(None),
        };
        // First two args must be plain idents (the iter-var names).
        let Expr::Ident(name1) = &call.args[0].expr else {
            return Ok(None);
        };
        let Expr::Ident(name2) = &call.args[1].expr else {
            return Ok(None);
        };
        // The source must be iterable. Compile after the shape check so
        // we don't pay for it on non-comprehension calls.
        let target = self.expr(target_expr)?;
        let var_ident1 = format_ident!("__cel_iter_{}", name1);
        let var_ident2 = format_ident!("__cel_iter_{}", name2);
        let target_t = target.tokens.clone();
        // Iteration shape: `iter_expr` is the iterator producing pairs;
        // `bind1` / `bind2` are the `(rust_expr, cel_type)` for the two
        // user-visible variables; `elem_ty` is the value type (used as
        // the output element type for `.filter`).
        let (iter_expr, bind1, bind2, elem_ty) = match &target.ty {
            CelType::List(et) => {
                let et = et.as_ref().clone();
                let elem_rust = element_binding_expr(&var_ident2, &et);
                (
                    quote! { (#target_t).iter().enumerate() },
                    (quote! { (#var_ident1 as i64) }, CelType::Int),
                    (elem_rust, et.clone()),
                    et,
                )
            }
            CelType::Map(map_ty) => {
                let key_ty = map_ty.key_cel.clone();
                let val_ty = map_ty.value_cel.clone();
                let k_rust = element_binding_expr(&var_ident1, &key_ty);
                let v_rust = element_binding_expr(&var_ident2, &val_ty);
                (
                    quote! { (#target_t).iter() },
                    (k_rust, key_ty),
                    (v_rust, val_ty.clone()),
                    val_ty,
                )
            }
            other => {
                return Err(FallbackReason::new(format!(
                    "two-var comprehension over {other:?}"
                )));
            }
        };
        // Bind both vars; save any prior bindings to restore at the end.
        let n1 = name1.clone();
        let n2 = name2.clone();
        let saved1 = self.bindings.remove(&n1);
        let saved2 = self.bindings.remove(&n2);
        self.bindings.insert(
            n1.clone(),
            Binding {
                rust_expr: bind1.0,
                ty: bind1.1,
                constant: None,
            },
        );
        self.bindings.insert(
            n2.clone(),
            Binding {
                rust_expr: bind2.0,
                ty: bind2.1,
                constant: None,
            },
        );
        let body_args = &call.args[2..];
        let body_pat = quote! { (#var_ident1, #var_ident2) };
        let result: Result<Compiled, FallbackReason> = match kind {
            "all" => {
                let pred = self.expr(&body_args[0])?;
                if pred.ty == CelType::Bool {
                    let pred_t = pred.tokens;
                    Ok(Compiled {
                        tokens: quote! {
                            ({
                                let mut __cel_ok = true;
                                for #body_pat in #iter_expr {
                                    if !(#pred_t) { __cel_ok = false; break; }
                                }
                                __cel_ok
                            })
                        },
                        ty: CelType::Bool,
                        constant: None,
                    })
                } else {
                    Err(FallbackReason::new(format!(
                        "two-var all pred not bool: {:?}",
                        pred.ty
                    )))
                }
            }
            "exists" => {
                let pred = self.expr(&body_args[0])?;
                if pred.ty == CelType::Bool {
                    let pred_t = pred.tokens;
                    Ok(Compiled {
                        tokens: quote! {
                            ({
                                let mut __cel_hit = false;
                                for #body_pat in #iter_expr {
                                    if #pred_t { __cel_hit = true; break; }
                                }
                                __cel_hit
                            })
                        },
                        ty: CelType::Bool,
                        constant: None,
                    })
                } else {
                    Err(FallbackReason::new(format!(
                        "two-var exists pred not bool: {:?}",
                        pred.ty
                    )))
                }
            }
            "exists_one" | "existsOne" => {
                let pred = self.expr(&body_args[0])?;
                if pred.ty == CelType::Bool {
                    let pred_t = pred.tokens;
                    Ok(Compiled {
                        tokens: quote! {
                            ({
                                let mut __cel_count: u32 = 0u32;
                                for #body_pat in #iter_expr {
                                    if #pred_t {
                                        __cel_count += 1;
                                        if __cel_count > 1 { break; }
                                    }
                                }
                                __cel_count == 1
                            })
                        },
                        ty: CelType::Bool,
                        constant: None,
                    })
                } else {
                    Err(FallbackReason::new("two-var exists_one pred not bool"))
                }
            }
            "filter" => {
                let pred = self.expr(&body_args[0])?;
                if pred.ty == CelType::Bool {
                    let pred_t = pred.tokens;
                    // Filter over a map yields a list of *values* matching
                    // the predicate, per cel-go's comprehension v2.
                    // For Str/Bytes elements push the reference so the
                    // resulting list doesn't clone potentially-large
                    // payloads. For Copy scalars duplicate the value.
                    let (push_v, out_elem_ty) = match &elem_ty {
                        CelType::Str { .. } => (
                            quote! { __cel_out.push(#var_ident2); },
                            CelType::Str { owned: false },
                        ),
                        CelType::Bytes { .. } => (
                            quote! { __cel_out.push(#var_ident2); },
                            CelType::Bytes { owned: false },
                        ),
                        _ => (
                            quote! { __cel_out.push((*#var_ident2).clone()); },
                            elem_ty.clone(),
                        ),
                    };
                    Ok(Compiled {
                        tokens: quote! {
                            ({
                                let mut __cel_out: ::std::vec::Vec<_> = ::std::vec::Vec::new();
                                for #body_pat in #iter_expr {
                                    if #pred_t { #push_v }
                                }
                                __cel_out
                            })
                        },
                        ty: CelType::List(Box::new(out_elem_ty)),
                        constant: None,
                    })
                } else {
                    Err(FallbackReason::new("two-var filter pred not bool"))
                }
            }
            "map" => {
                let filter_c = self.expr(&body_args[0])?;
                if filter_c.ty == CelType::Bool {
                    let mapped = self.expr(&body_args[1])?;
                    let out_ty = mapped.ty.clone();
                    let filter_t = filter_c.tokens;
                    let mapped_t = mapped.tokens;
                    Ok(Compiled {
                        tokens: quote! {
                            ({
                                let mut __cel_out: ::std::vec::Vec<_> = ::std::vec::Vec::new();
                                for #body_pat in #iter_expr {
                                    if #filter_t {
                                        __cel_out.push(#mapped_t);
                                    }
                                }
                                __cel_out
                            })
                        },
                        ty: CelType::List(Box::new(out_ty)),
                        constant: None,
                    })
                } else {
                    Err(FallbackReason::new("two-var map filter not bool"))
                }
            }
            _ => unreachable!(),
        };
        // Restore prior bindings.
        match saved2 {
            Some(b) => {
                self.bindings.insert(n2, b);
            }
            None => {
                self.bindings.remove(&n2);
            }
        }
        match saved1 {
            Some(b) => {
                self.bindings.insert(n1, b);
            }
            None => {
                self.bindings.remove(&n1);
            }
        }
        result.map(Some)
    }

    fn comprehension(&mut self, c: &ComprehensionExpr) -> Result<Compiled, FallbackReason> {
        let kind = classify_comprehension(c)?;
        let range = self.expr(&c.iter_range)?;
        // Short-circuit: a statically empty source determines the result
        // without typing the predicate. CEL spec — `[].all(x, P) → true`,
        // `[].exists(x, P) → false`, `[].map(...) / [].filter(...) → []`.
        // Without this, the predicate type-checks against the empty list
        // literal's `Dyn` element type and fails (e.g. `Dyn > Int`).
        if matches!(&range.constant, Some(ConstValue::List(v)) if v.is_empty()) {
            return Ok(match &kind {
                ComprehensionKind::All => Compiled {
                    tokens: quote! { true },
                    ty: CelType::Bool,
                    constant: Some(ConstValue::Bool(true)),
                },
                ComprehensionKind::Exists | ComprehensionKind::ExistsOne { .. } => Compiled {
                    tokens: quote! { false },
                    ty: CelType::Bool,
                    constant: Some(ConstValue::Bool(false)),
                },
                ComprehensionKind::Map { .. }
                | ComprehensionKind::MapFilter { .. }
                | ComprehensionKind::Filter { .. } => Compiled {
                    tokens: quote! { (&[] as &[i64]) },
                    ty: CelType::List(Box::new(CelType::Dyn)),
                    constant: Some(ConstValue::List(Vec::new())),
                },
            });
        }
        // Single-variable comprehension. cel-rs's parser only emits
        // these — see `classify_comprehension` for the `iter_var2`
        // upstream-rejection note.
        let iter_var = c.iter_var.clone();
        let var_ident = format_ident!("__cel_iter_{}", iter_var);
        let (elem_ty, range_iter_tokens) = match &range.ty {
            CelType::List(et) => {
                let t = range.tokens.clone();
                (et.as_ref().clone(), quote! { (#t).iter() })
            }
            CelType::Map(map_ty) => {
                let t = range.tokens.clone();
                (map_ty.key_cel.clone(), quote! { (#t).keys() })
            }
            _ => return Err(FallbackReason::new("comprehension over non-list / non-map")),
        };
        let elem_rust = element_binding_expr(&var_ident, &elem_ty);
        let iter_pat = quote! { #var_ident };
        let elem_ty = Box::new(elem_ty);
        let saved = self.bindings.remove(&iter_var);
        self.bindings.insert(
            iter_var.clone(),
            Binding {
                rust_expr: elem_rust,
                ty: (*elem_ty).clone(),
                constant: None,
            },
        );
        let result: Result<Compiled, FallbackReason> = (|s: &mut Self| match &kind {
            ComprehensionKind::All | ComprehensionKind::Exists => {
                let Expr::Call(step_call) = &c.loop_step.expr else {
                    return Err(FallbackReason::new("bool comp: step not call"));
                };
                let pred = s.expr(&step_call.args[1])?;
                if pred.ty != CelType::Bool {
                    return Err(FallbackReason::new(format!(
                        "comp pred not bool: {:?}",
                        pred.ty
                    )));
                }
                let method = match kind {
                    ComprehensionKind::All => quote! { all },
                    ComprehensionKind::Exists => quote! { any },
                    _ => unreachable!(),
                };
                let iter_t = range_iter_tokens.clone();
                let pred_t = pred.tokens;
                Ok(Compiled {
                    tokens: quote! {
                        ((#iter_t).#method(|#iter_pat| #pred_t))
                    },
                    ty: CelType::Bool,
                    constant: None,
                })
            }
            ComprehensionKind::Map { mapped } => {
                let mapped_c = s.expr(mapped)?;
                let out_ty = mapped_c.ty.clone();
                let mapped_t = mapped_c.tokens;
                let iter_t = range_iter_tokens.clone();
                Ok(Compiled {
                    tokens: quote! {
                        ({
                            let __cel_mapped: ::std::vec::Vec<_> = (#iter_t)
                                .map(|#iter_pat| (#mapped_t))
                                .collect();
                            __cel_mapped
                        })
                    },
                    ty: CelType::List(Box::new(out_ty)),
                    constant: None,
                })
            }
            ComprehensionKind::MapFilter { filter, mapped } => {
                let filter_c = s.expr(filter)?;
                if filter_c.ty != CelType::Bool {
                    return Err(FallbackReason::new("map-filter: filter not bool"));
                }
                let mapped_c = s.expr(mapped)?;
                let out_ty = mapped_c.ty.clone();
                let filter_t = filter_c.tokens;
                let mapped_t = mapped_c.tokens;
                let iter_t = range_iter_tokens.clone();
                Ok(Compiled {
                    tokens: quote! {
                        ({
                            let __cel_mapped: ::std::vec::Vec<_> = (#iter_t)
                                .filter(|#iter_pat| (#filter_t))
                                .map(|#iter_pat| (#mapped_t))
                                .collect();
                            __cel_mapped
                        })
                    },
                    ty: CelType::List(Box::new(out_ty)),
                    constant: None,
                })
            }
            ComprehensionKind::Filter { pred } => {
                let pred_c = s.expr(pred)?;
                if pred_c.ty != CelType::Bool {
                    return Err(FallbackReason::new("filter pred not bool"));
                }
                let pred_t = pred_c.tokens;
                let iter_t = range_iter_tokens.clone();
                let out_ty = (*elem_ty).clone();
                Ok(Compiled {
                    tokens: quote! {
                        ({
                            let __cel_filtered: ::std::vec::Vec<_> = (#iter_t)
                                .filter(|#iter_pat| (#pred_t))
                                .cloned()
                                .collect();
                            __cel_filtered
                        })
                    },
                    ty: CelType::List(Box::new(out_ty)),
                    constant: None,
                })
            }
            ComprehensionKind::ExistsOne { pred } => {
                let pred_c = s.expr(pred)?;
                if pred_c.ty != CelType::Bool {
                    return Err(FallbackReason::new(format!(
                        "exists_one pred not bool: {:?}",
                        pred_c.ty
                    )));
                }
                let pred_t = pred_c.tokens;
                let iter_t = range_iter_tokens.clone();
                // Early-exit once we see a second match — the result is
                // determined and we save the rest of the iteration.
                Ok(Compiled {
                    tokens: quote! {
                        ({
                            let mut __cel_count: u32 = 0u32;
                            for #iter_pat in (#iter_t) {
                                if #pred_t {
                                    __cel_count += 1;
                                    if __cel_count > 1 { break; }
                                }
                            }
                            __cel_count == 1
                        })
                    },
                    ty: CelType::Bool,
                    constant: None,
                })
            }
        })(self);
        match saved {
            Some(b) => {
                self.bindings.insert(iter_var, b);
            }
            None => {
                self.bindings.remove(&iter_var);
            }
        }
        result
    }
}

/// What the caller needs from a successful compile.
#[derive(Debug)]
pub struct CompileOutput {
    pub tokens: TokenStream,
    pub ty: CelType,
    pub needs_now: bool,
}

impl ConstValue {
    fn cel_type(&self) -> CelType {
        match self {
            Self::Bool(_) => CelType::Bool,
            Self::Int(_) => CelType::Int,
            Self::UInt(_) => CelType::UInt,
            Self::Double(_) => CelType::Double,
            Self::Str(_) => CelType::Str { owned: false },
            Self::Bytes(_) => CelType::Bytes { owned: false },
            Self::Null => CelType::Null,
            Self::List(elems) => {
                let elem = elems.first().map_or(CelType::Dyn, Self::cel_type);
                CelType::List(Box::new(elem))
            }
        }
    }

    fn to_tokens(&self) -> TokenStream {
        match self {
            Self::Bool(b) => quote! { (#b) },
            Self::Int(i) => {
                let lit = proc_macro2::Literal::i64_suffixed(*i);
                quote! { (#lit) }
            }
            Self::UInt(u) => {
                let lit = proc_macro2::Literal::u64_suffixed(*u);
                quote! { (#lit) }
            }
            Self::Double(d) => {
                let lit = proc_macro2::Literal::f64_suffixed(*d);
                quote! { (#lit) }
            }
            Self::Str(s) => quote! { (#s) },
            Self::Bytes(b) => {
                let bytes = proc_macro2::Literal::byte_string(b);
                quote! { (#bytes as &[u8]) }
            }
            Self::Null => quote! { () },
            Self::List(elems) => {
                let toks = elems.iter().map(Self::to_tokens);
                quote! { ([ #( #toks ),* ].as_slice()) }
            }
        }
    }
}

fn const_from_rule(rc: &crate::scan::RuleConst) -> ConstValue {
    match rc {
        crate::scan::RuleConst::Bool(b) => ConstValue::Bool(*b),
        crate::scan::RuleConst::Int(i) => ConstValue::Int(*i),
        crate::scan::RuleConst::UInt(u) => ConstValue::UInt(*u),
        crate::scan::RuleConst::Double(d) => ConstValue::Double(*d),
        crate::scan::RuleConst::Str(s) => ConstValue::Str(s.clone()),
        crate::scan::RuleConst::Bytes(b) => ConstValue::Bytes(b.clone()),
        crate::scan::RuleConst::List(l) => {
            ConstValue::List(l.iter().map(const_from_rule).collect())
        }
    }
}

#[derive(Debug, Clone)]
enum ComprehensionKind {
    /// `.all(x, pred)` → `iter().all(|x| pred)`.
    All,
    /// `.exists(x, pred)` → `iter().any(|x| pred)`.
    Exists,
    /// `.exists_one(x, pred)` → counter loop that breaks when `count > 1`,
    /// final result `count == 1`.
    ExistsOne { pred: IdedExpr },
    /// `.map(x, expr)` → `iter().map(|x| expr).collect()`. The mapped
    /// expression is the AST node we extract from the step.
    Map { mapped: IdedExpr },
    /// `.map(x, filter, expr)` → `iter().filter(|x| filter).map(|x| expr).collect()`.
    MapFilter { filter: IdedExpr, mapped: IdedExpr },
    /// `.filter(x, pred)` → `iter().filter(|x| pred).cloned().collect()`.
    Filter { pred: IdedExpr },
}

fn classify_comprehension(c: &ComprehensionExpr) -> Result<ComprehensionKind, FallbackReason> {
    if c.iter_var2.is_some() {
        // cel-rs's `find_expander` requires exactly two call args for
        // every comprehension macro, so the 3-arg `.all(k, v, P)` form is
        // parsed as a plain method call rather than expanded into a
        // Comprehension AST node. The transpiler intercepts that path in
        // `try_two_var_comprehension`. If a future cel-rs version does
        // emit `iter_var2`, we'd want to extend this function rather than
        // duplicate the binding logic — fail loudly here so we notice.
        return Err(FallbackReason::new(
            "comprehension with `iter_var2` — handled via the method-call \
             intercept in `try_two_var_comprehension`; the macro-expanded \
             path isn't reachable in cel-rs 0.13",
        ));
    }
    // .all/.exists: bool accumulator init, result is the accu ident.
    if let Expr::Literal(LiteralValue::Boolean(b)) = &c.accu_init.expr {
        let Expr::Ident(res) = &c.result.expr else {
            return Err(FallbackReason::new("bool-accu result not ident"));
        };
        if res != &c.accu_var {
            return Err(FallbackReason::new("bool-accu result != accu"));
        }
        return classify_bool_accu(c, *b.inner());
    }
    // .map / .filter: empty list accumulator init, result is the accu
    // ident.
    if let Expr::List(list) = &c.accu_init.expr {
        if !list.elements.is_empty() {
            return Err(FallbackReason::new("comprehension list-accu init nonempty"));
        }
        let Expr::Ident(res) = &c.result.expr else {
            return Err(FallbackReason::new("list-accu result not ident"));
        };
        if res != &c.accu_var {
            return Err(FallbackReason::new("list-accu result != accu"));
        }
        return classify_list_accu(c);
    }
    // .exists_one: int-0 accumulator init, step is `pred ? accu+1 : accu`,
    // result is `accu == 1`. Cel-go's macro expansion matches this shape.
    if let Expr::Literal(LiteralValue::Int(i)) = &c.accu_init.expr
        && *i.inner() == 0
    {
        return classify_exists_one(c);
    }
    Err(FallbackReason::new("comprehension accu_init shape"))
}

fn classify_exists_one(c: &ComprehensionExpr) -> Result<ComprehensionKind, FallbackReason> {
    let Expr::Call(step) = &c.loop_step.expr else {
        return Err(FallbackReason::new("exists_one step not call"));
    };
    if step.func_name != op::CONDITIONAL || step.args.len() != 3 {
        return Err(FallbackReason::new("exists_one step shape"));
    }
    let pred = step.args[0].clone();
    let Expr::Call(then_call) = &step.args[1].expr else {
        return Err(FallbackReason::new("exists_one then not call"));
    };
    if then_call.func_name != op::ADD || then_call.args.len() != 2 {
        return Err(FallbackReason::new("exists_one then not accu + 1"));
    }
    let Expr::Ident(then_lhs) = &then_call.args[0].expr else {
        return Err(FallbackReason::new("exists_one then lhs not ident"));
    };
    if then_lhs != &c.accu_var {
        return Err(FallbackReason::new("exists_one then lhs != accu"));
    }
    let Expr::Ident(else_id) = &step.args[2].expr else {
        return Err(FallbackReason::new("exists_one else not ident"));
    };
    if else_id != &c.accu_var {
        return Err(FallbackReason::new("exists_one else != accu"));
    }
    let Expr::Call(result) = &c.result.expr else {
        return Err(FallbackReason::new("exists_one result not call"));
    };
    if result.func_name != op::EQUALS || result.args.len() != 2 {
        return Err(FallbackReason::new("exists_one result not =="));
    }
    let Expr::Ident(rl) = &result.args[0].expr else {
        return Err(FallbackReason::new("exists_one result lhs not ident"));
    };
    if rl != &c.accu_var {
        return Err(FallbackReason::new("exists_one result lhs != accu"));
    }
    Ok(ComprehensionKind::ExistsOne { pred })
}

fn classify_bool_accu(
    c: &ComprehensionExpr,
    init: bool,
) -> Result<ComprehensionKind, FallbackReason> {
    let Expr::Call(step) = &c.loop_step.expr else {
        return Err(FallbackReason::new("bool-accu: step not a call"));
    };
    let is_and = step.func_name == op::LOGICAL_AND;
    let is_or = step.func_name == op::LOGICAL_OR;
    if !is_and && !is_or {
        return Err(FallbackReason::new("bool-accu: wrong op"));
    }
    if step.args.len() != 2 {
        return Err(FallbackReason::new("bool-accu: wrong arity"));
    }
    let Expr::Ident(lhs) = &step.args[0].expr else {
        return Err(FallbackReason::new("bool-accu: lhs not accu"));
    };
    if lhs != &c.accu_var {
        return Err(FallbackReason::new("bool-accu: lhs != accu"));
    }
    match (is_and, init) {
        (true, true) => Ok(ComprehensionKind::All),
        (false, false) => Ok(ComprehensionKind::Exists),
        _ => Err(FallbackReason::new("bool-accu: shape mismatch")),
    }
}

fn classify_list_accu(c: &ComprehensionExpr) -> Result<ComprehensionKind, FallbackReason> {
    // .map(x, expr):                     accu + [expr]
    // .map(x, filter, expr):    filter ? accu + [expr] : accu
    // .filter(x, pred):           pred ? accu + [x]    : accu
    if let Expr::Call(step) = &c.loop_step.expr {
        if step.func_name == op::ADD {
            // Plain .map() shape.
            let mapped = extract_map_step_mapped(step, &c.accu_var)?;
            return Ok(ComprehensionKind::Map { mapped });
        }
        if step.func_name == op::CONDITIONAL && step.args.len() == 3 {
            // Inspect the then/else shape. Both .map-with-filter and .filter
            // produce conditional with `step` and `accu` as branches.
            let Expr::Ident(else_ident) = &step.args[2].expr else {
                return Err(FallbackReason::new("list-accu cond: else not accu"));
            };
            if else_ident != &c.accu_var {
                return Err(FallbackReason::new("list-accu cond: else != accu"));
            }
            // then-branch is `accu + [<thing>]`.
            let Expr::Call(then_call) = &step.args[1].expr else {
                return Err(FallbackReason::new("list-accu cond: then not call"));
            };
            if then_call.func_name != op::ADD {
                return Err(FallbackReason::new("list-accu cond: then not +"));
            }
            let mapped_inside = extract_map_step_mapped(then_call, &c.accu_var)?;
            let filter_expr = step.args[0].clone();
            // Distinguish .filter (mapped == iter_var) vs .map-with-filter.
            if let Expr::Ident(id) = &mapped_inside.expr
                && id == &c.iter_var
            {
                return Ok(ComprehensionKind::Filter { pred: filter_expr });
            }
            return Ok(ComprehensionKind::MapFilter {
                filter: filter_expr,
                mapped: mapped_inside,
            });
        }
    }
    Err(FallbackReason::new("list-accu: unsupported shape"))
}

/// `accu + [<mapped>]` → returns the `<mapped>` AST. Errors if the shape
/// doesn't match.
fn extract_map_step_mapped(step: &CallExpr, accu_var: &str) -> Result<IdedExpr, FallbackReason> {
    if step.args.len() != 2 {
        return Err(FallbackReason::new("map step: wrong arity"));
    }
    let Expr::Ident(lhs) = &step.args[0].expr else {
        return Err(FallbackReason::new("map step: lhs not accu"));
    };
    if lhs != accu_var {
        return Err(FallbackReason::new("map step: lhs != accu"));
    }
    let Expr::List(list) = &step.args[1].expr else {
        return Err(FallbackReason::new("map step: rhs not list"));
    };
    if list.elements.len() != 1 {
        return Err(FallbackReason::new("map step: rhs list arity"));
    }
    Ok(list.elements[0].clone())
}

fn literal(lit: &LiteralValue) -> Compiled {
    match lit {
        LiteralValue::Boolean(b) => {
            let v = *b.inner();
            Compiled {
                tokens: quote! { #v },
                ty: CelType::Bool,
                constant: Some(ConstValue::Bool(v)),
            }
        }
        LiteralValue::Bytes(b) => {
            let v: Vec<u8> = b.inner().to_vec();
            let bytes = proc_macro2::Literal::byte_string(&v);
            Compiled {
                tokens: quote! { (#bytes as &[u8]) },
                ty: CelType::Bytes { owned: false },
                constant: Some(ConstValue::Bytes(v)),
            }
        }
        LiteralValue::Double(f) => {
            let v: f64 = *f.inner();
            Compiled {
                tokens: quote! { (#v as f64) },
                ty: CelType::Double,
                constant: Some(ConstValue::Double(v)),
            }
        }
        LiteralValue::Int(i) => {
            let v: i64 = *i.inner();
            Compiled {
                tokens: quote! { (#v as i64) },
                ty: CelType::Int,
                constant: Some(ConstValue::Int(v)),
            }
        }
        LiteralValue::Null => Compiled {
            tokens: quote! { () },
            ty: CelType::Null,
            constant: Some(ConstValue::Null),
        },
        LiteralValue::String(s) => {
            let v: String = s.inner().to_string();
            Compiled {
                tokens: quote! { #v },
                ty: CelType::Str { owned: false },
                constant: Some(ConstValue::Str(v)),
            }
        }
        LiteralValue::UInt(u) => {
            let v: u64 = *u.inner();
            Compiled {
                tokens: quote! { (#v as u64) },
                ty: CelType::UInt,
                constant: Some(ConstValue::UInt(v)),
            }
        }
    }
}

/// Bridge between heterogeneous typed exprs in branches of a `?:`.
fn unify_branches(a: &CelType, b: &CelType) -> Result<CelType, FallbackReason> {
    if a == b {
        return Ok(a.clone());
    }
    match (a, b) {
        (CelType::Str { .. }, CelType::Str { .. }) => Ok(CelType::Str { owned: true }),
        (CelType::Bytes { .. }, CelType::Bytes { .. }) => Ok(CelType::Bytes { owned: true }),
        (x, y) if x.is_numeric() && y.is_numeric() => promote_numeric(x, y),
        // `optional.none()` is typed as `Optional<Dyn>`; when paired with
        // another `Optional<T>` in a ternary, fold to the concrete `T`.
        (CelType::Optional(inner_a), CelType::Optional(inner_b)) => {
            let inner = if matches!(inner_a.as_ref(), CelType::Dyn) {
                inner_b.as_ref().clone()
            } else if matches!(inner_b.as_ref(), CelType::Dyn) {
                inner_a.as_ref().clone()
            } else {
                unify_branches(inner_a, inner_b)?
            };
            Ok(CelType::Optional(Box::new(inner)))
        }
        _ => Err(FallbackReason::new(format!(
            "branch unification: {a:?} vs {b:?}"
        ))),
    }
}

/// Coerce a typed expression to a target type, returning tokens.
/// Recognize CEL type-marker keywords (`int`, `uint`, etc.). Returned
/// string is the CEL canonical name; both this and `static_type_marker`
/// must produce identical strings for `type(x) == int`-style folds to
/// compare equal at runtime.
fn cel_type_marker_ident(name: &str) -> Option<&'static str> {
    match name {
        "int" => Some("int"),
        "uint" => Some("uint"),
        "double" => Some("double"),
        "bool" => Some("bool"),
        "string" => Some("string"),
        "bytes" => Some("bytes"),
        "list_type" => Some("list"),
        "map_type" => Some("map"),
        "null_type" => Some("null_type"),
        _ => None,
    }
}

/// CEL canonical type name for a static `CelType`. Mirrors
/// `cel_type_marker_ident` so equality between a `type(x)` result and a
/// type-keyword ident folds to the right boolean.
const fn static_type_marker(ty: &CelType) -> &'static str {
    match ty {
        CelType::Int => "int",
        CelType::UInt => "uint",
        CelType::Double => "double",
        CelType::Bool => "bool",
        CelType::Str { .. } => "string",
        CelType::Bytes { .. } => "bytes",
        CelType::List(_) => "list",
        CelType::Map(_) => "map",
        CelType::Optional(_) => "optional_type",
        CelType::Duration => "google.protobuf.Duration",
        CelType::Timestamp => "google.protobuf.Timestamp",
        CelType::Null => "null_type",
        CelType::Message(_) | CelType::MessageRef(_) | CelType::Dyn => "_unknown_",
    }
}

fn coerce(c: &Compiled, target: &CelType) -> Result<TokenStream, FallbackReason> {
    if c.ty == *target {
        return Ok(c.tokens.clone());
    }
    match (&c.ty, target) {
        (CelType::Str { .. }, CelType::Str { owned: true }) => {
            // Force owned form.
            let t = string_as_str(c);
            Ok(quote! { ::std::string::String::from(#t) })
        }
        (CelType::Str { owned: true }, CelType::Str { owned: false }) => {
            // String → &str.
            let t = c.tokens.clone();
            Ok(quote! { (&#t as &str) })
        }
        (CelType::Bytes { .. }, CelType::Bytes { owned: true }) => {
            let t = bytes_as_slice(c);
            Ok(quote! { #t.to_vec() })
        }
        (a, b) if a.is_numeric() && b.is_numeric() => Ok(numeric_cast(c, b)),
        // `optional.none()` is typed as `Optional<Dyn>` because the call
        // site doesn't carry an explicit element type. When a ternary or
        // other context forces an `Optional<T>`, we just pass the tokens
        // through — Rust's `None` is polymorphic and inference picks up
        // T from the use site.
        (CelType::Optional(inner_a), CelType::Optional(_))
            if matches!(inner_a.as_ref(), CelType::Dyn) =>
        {
            Ok(c.tokens.clone())
        }
        _ => Err(FallbackReason::new(format!(
            "coerce {a:?} → {b:?}",
            a = c.ty,
            b = target
        ))),
    }
}

/// CEL numeric promotion: float dominates, otherwise no implicit conversion
/// between int and uint (per CEL spec). We're slightly more permissive here:
/// we promote to the wider type when one side is a literal that fits.
fn promote_numeric(a: &CelType, b: &CelType) -> Result<CelType, FallbackReason> {
    use CelType::{Double, Int, UInt};
    Ok(match (a, b) {
        (Double, _) | (_, Double) => Double,
        (Int, Int) => Int,
        (UInt, UInt) => UInt,
        (Int, UInt) | (UInt, Int) => {
            return Err(FallbackReason::new("int/uint mix without cast"));
        }
        _ => return Err(FallbackReason::new("non-numeric in arith")),
    })
}

fn numeric_cast(c: &Compiled, target: &CelType) -> TokenStream {
    let t = c.tokens.clone();
    if c.ty == *target {
        return t;
    }
    match (target, &c.ty) {
        (CelType::Double, _) => quote! { ((#t) as f64) },
        (CelType::Int, _) => quote! { ((#t) as i64) },
        (CelType::UInt, _) => quote! { ((#t) as u64) },
        _ => t,
    }
}

/// Get a `&str` view of a string-typed expression regardless of owned/borrowed.
fn string_as_str(c: &Compiled) -> TokenStream {
    let t = c.tokens.clone();
    match c.ty {
        CelType::Str { owned: false } => quote! { (#t) },
        CelType::Str { owned: true } => quote! { (&(#t)[..]) },
        _ => quote! { (#t) },
    }
}

fn bytes_as_slice(c: &Compiled) -> TokenStream {
    let t = c.tokens.clone();
    match c.ty {
        CelType::Bytes { owned: false } => quote! { (#t) },
        CelType::Bytes { owned: true } => quote! { (&(#t)[..]) },
        _ => quote! { (#t) },
    }
}

/// Compute the Rust expression that yields one CEL element value from the
/// comprehension iteration variable (a `&T` produced by `.iter()`).
fn element_binding_expr(var_ident: &syn::Ident, elem_ty: &CelType) -> TokenStream {
    match elem_ty {
        CelType::Str { .. } => quote! { (#var_ident.as_str()) },
        CelType::Bytes { .. } => quote! { (#var_ident.as_slice()) },
        CelType::Int => quote! {
            (::protovalidate_buffa::cel::CelScalar::cel_int(*#var_ident))
        },
        CelType::UInt => quote! {
            (::protovalidate_buffa::cel::CelScalar::cel_uint(*#var_ident))
        },
        CelType::Double => quote! {
            (::protovalidate_buffa::cel::CelScalar::cel_double(*#var_ident))
        },
        CelType::Bool => quote! { (*#var_ident) },
        // `&T` for Message — pass the reference through so field selects
        // operate on the borrowed inner message directly.
        CelType::Message(_) => quote! { #var_ident },
        _ => quote! { (*#var_ident) },
    }
}

/// Parse a CEL duration string (e.g. `"10s"`, `"-1.5h"`) into `(seconds,
/// nanos)`. Returns `None` if the string can't be parsed; the transpiler
/// then surfaces the call as `Unsupported`.
fn parse_cel_duration(s: &str) -> Option<(i64, i32)> {
    let trimmed = s.trim();
    let (negative, rest) = match (trimmed.strip_prefix('-'), trimmed.strip_prefix('+')) {
        (Some(r), _) => (true, r),
        (None, Some(r)) => (false, r),
        (None, None) => (false, trimmed),
    };
    // Tokenize: number followed by unit. CEL only allows a single
    // (number, unit) pair per duration literal in the runtime cast,
    // so we mirror that.
    let split_at = rest
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit() && *c != '.')
        .map(|(i, _)| i)?;
    let (num_str, unit) = rest.split_at(split_at);
    let value: f64 = num_str.parse().ok()?;
    let factor_secs: f64 = match unit {
        "ns" => 1e-9,
        "us" | "µs" => 1e-6,
        "ms" => 1e-3,
        "s" => 1.0,
        "m" => 60.0,
        "h" => 3600.0,
        _ => return None,
    };
    let total = value * factor_secs;
    let secs = total.trunc() as i64;
    let nanos = ((total - total.trunc()) * 1e9).round() as i32;
    Some(if negative {
        (-secs, -nanos)
    } else {
        (secs, nanos)
    })
}

/// Cast a CEL-widened scalar expression back to its concrete Rust scalar.
/// Used at index lookups where `HashMap<K, V>::get(&K)` needs the raw `K`.
fn cast_to_rust_scalar(expr: &TokenStream, cel: &CelType, rust: RustScalar) -> TokenStream {
    match (cel, rust) {
        (CelType::Int, RustScalar::I32) => quote! { ((#expr) as i32) },
        (CelType::Int, RustScalar::I64) => quote! { (#expr) },
        (CelType::UInt, RustScalar::U32) => quote! { ((#expr) as u32) },
        (CelType::UInt, RustScalar::U64) => quote! { (#expr) },
        (CelType::Double, RustScalar::F32) => quote! { ((#expr) as f32) },
        (CelType::Double, RustScalar::F64) => quote! { (#expr) },
        (CelType::Bool, RustScalar::Bool) => quote! { (#expr) },
        (CelType::Str { .. }, RustScalar::Str) => quote! { (#expr) },
        (CelType::Bytes { .. }, RustScalar::Bytes) => quote! { (#expr) },
        _ => quote! { (#expr) },
    }
}

/// Emit a typed Rust field access for `<operand>.<field>` when the operand
/// is a known message type.
fn select_message_field(
    operand: &TokenStream,
    schema: &MessageSchema,
    field: &str,
) -> Result<Compiled, FallbackReason> {
    let entry = schema
        .fields
        .iter()
        .find(|e| e.proto_name == field)
        .ok_or_else(|| FallbackReason::new(format!("unknown field: {field}")))?;
    let rust_ident = crate::emit::field_ident(&entry.rust_ident);
    let access = match &entry.kind {
        SchemaFieldKind::StringLike => match &entry.ty {
            CelType::Str { .. } => quote! { (#operand.#rust_ident.as_str()) },
            CelType::Bytes { .. } => quote! { (#operand.#rust_ident.as_slice()) },
            _ => return Err(FallbackReason::new("schema StringLike with wrong CelType")),
        },
        SchemaFieldKind::Scalar => match &entry.ty {
            CelType::Int => {
                quote! { (::protovalidate_buffa::cel::CelScalar::cel_int(#operand.#rust_ident)) }
            }
            CelType::UInt => {
                quote! { (::protovalidate_buffa::cel::CelScalar::cel_uint(#operand.#rust_ident)) }
            }
            CelType::Double => {
                quote! { (::protovalidate_buffa::cel::CelScalar::cel_double(#operand.#rust_ident)) }
            }
            CelType::Bool => quote! { (#operand.#rust_ident) },
            _ => return Err(FallbackReason::new("schema Scalar with non-scalar CelType")),
        },
        SchemaFieldKind::Optional => {
            // `Option<T>` — emit a guarded extraction. CEL's null-handling
            // is "unset becomes the default"; using `.unwrap_or_default()`
            // here matches that for scalars.
            match &entry.ty {
                CelType::Int => {
                    quote! { (#operand.#rust_ident.map_or(0i64, ::protovalidate_buffa::cel::CelScalar::cel_int)) }
                }
                CelType::UInt => {
                    quote! { (#operand.#rust_ident.map_or(0u64, ::protovalidate_buffa::cel::CelScalar::cel_uint)) }
                }
                CelType::Double => {
                    quote! { (#operand.#rust_ident.map_or(0f64, ::protovalidate_buffa::cel::CelScalar::cel_double)) }
                }
                CelType::Bool => quote! { (#operand.#rust_ident.unwrap_or(false)) },
                CelType::Str { .. } => quote! { (#operand.#rust_ident.as_deref().unwrap_or("")) },
                CelType::Bytes { .. } => {
                    quote! { (#operand.#rust_ident.as_deref().unwrap_or(&[])) }
                }
                _ => {
                    return Err(FallbackReason::new(
                        "schema Optional with unsupported CelType",
                    ));
                }
            }
        }
        SchemaFieldKind::Repeated => quote! { (#operand.#rust_ident.as_slice()) },
        SchemaFieldKind::Wrapper => match &entry.ty {
            CelType::Int => {
                quote! { (#operand.#rust_ident.as_option().map_or(0i64, |w| ::protovalidate_buffa::cel::CelScalar::cel_int(w.value))) }
            }
            CelType::UInt => {
                quote! { (#operand.#rust_ident.as_option().map_or(0u64, |w| ::protovalidate_buffa::cel::CelScalar::cel_uint(w.value))) }
            }
            CelType::Double => {
                quote! { (#operand.#rust_ident.as_option().map_or(0f64, |w| ::protovalidate_buffa::cel::CelScalar::cel_double(w.value))) }
            }
            CelType::Bool => {
                quote! { (#operand.#rust_ident.as_option().map_or(false, |w| w.value)) }
            }
            CelType::Str { .. } => {
                quote! { (#operand.#rust_ident.as_option().map_or("", |w| w.value.as_str())) }
            }
            CelType::Bytes { .. } => {
                quote! { (#operand.#rust_ident.as_option().map_or(&[][..], |w| w.value.as_slice())) }
            }
            _ => {
                return Err(FallbackReason::new(
                    "schema Wrapper with unsupported CelType",
                ));
            }
        },
        SchemaFieldKind::Message { proto_fqn } => {
            // Nested sub-message access (`this.e.a == this.f.a`). The
            // generated code wraps the whole expression in a closure that
            // uses `?` to short-circuit when a sub-message is unset (which
            // matches protovalidate's NoSuchKey-as-skip semantics for
            // `(message).cel`). Emit a `MessageField::as_option()?` so the
            // closure short-circuits.
            let Some(fqn) = proto_fqn else {
                return Err(FallbackReason::new(format!(
                    "message field {field} has no proto FQN"
                )));
            };
            return Ok(Compiled {
                tokens: quote! { (#operand.#rust_ident.as_option()?) },
                ty: CelType::MessageRef(fqn.clone()),
                constant: None,
            });
        }
    };
    Ok(Compiled {
        tokens: access,
        ty: entry.ty.clone(),
        constant: None,
    })
}

fn has_message_field(
    operand: &TokenStream,
    schema: &MessageSchema,
    field: &str,
) -> Result<Compiled, FallbackReason> {
    let entry = schema
        .fields
        .iter()
        .find(|e| e.proto_name == field)
        .ok_or_else(|| FallbackReason::new(format!("unknown field for has: {field}")))?;
    let rust_ident = crate::emit::field_ident(&entry.rust_ident);
    let tokens = match &entry.kind {
        SchemaFieldKind::Scalar => match &entry.ty {
            CelType::Int => {
                quote! { (::protovalidate_buffa::cel::CelScalar::cel_int(#operand.#rust_ident) != 0i64) }
            }
            CelType::UInt => {
                quote! { (::protovalidate_buffa::cel::CelScalar::cel_uint(#operand.#rust_ident) != 0u64) }
            }
            CelType::Double => {
                quote! { (::protovalidate_buffa::cel::CelScalar::cel_double(#operand.#rust_ident) != 0f64) }
            }
            CelType::Bool => quote! { (#operand.#rust_ident) },
            _ => {
                return Err(FallbackReason::new(
                    "has on schema Scalar with wrong CelType",
                ));
            }
        },
        SchemaFieldKind::StringLike => quote! { (!#operand.#rust_ident.is_empty()) },
        SchemaFieldKind::Optional => quote! { (#operand.#rust_ident.is_some()) },
        SchemaFieldKind::Message { .. } | SchemaFieldKind::Wrapper => {
            quote! { (#operand.#rust_ident.is_set()) }
        }
        SchemaFieldKind::Repeated => quote! { (!#operand.#rust_ident.is_empty()) },
    };
    Ok(Compiled {
        tokens,
        ty: CelType::Bool,
        constant: None,
    })
}

/// Determine compile-time presence of `<operand>.<field>` for `has()`.
const fn has_for(operand: &Compiled, _field: &str) -> HasInfo {
    // For a scalar `this` binding, `has(this)` isn't legal in CEL — but
    // `has(this.x)` requires `this` to be a struct/message. We don't have
    // structured access yet, so:
    //   - if operand is `Null`, the inner has() is `false`
    //   - if operand has a const value of a list/scalar, no sub-field exists
    //     → unknown (we'd need a struct-typed const)
    //   - otherwise unknown.
    if matches!(operand.ty, CelType::Null) {
        return HasInfo::Absent;
    }
    HasInfo::Unknown
}

#[cfg(test)]
mod tests {
    //! Unit tests for the transpiler. These verify specific CEL → Rust
    //! translations as a fast regression guard — the conformance suite
    //! covers end-to-end correctness, but rebuilding it for a one-off
    //! change is slow. Tests here run in milliseconds.
    //!
    //! Each test compiles a CEL expression against a synthetic `this`
    //! binding, then asserts on the emitted `TokenStream` shape via
    //! string contains-checks (we don't pin exact whitespace because
    //! quote! formatting is implementation-detail).
    use super::*;

    fn compile_with_this(expr: &str, this_ty: CelType) -> CompileOutput {
        let mut c = Compiler::new();
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { __this },
                ty: this_ty,
                constant: None,
            },
        );
        let out = c.compile(expr).expect("expected successful compile");
        // Every emitted body must at least parse as a Rust expression.
        // Catches token-stream-shaped output that isn't valid Rust syntax
        // — a class of bug `TokenStream::to_string()`-based contains-checks
        // can miss entirely.
        assert_parses_as_expr(&out.tokens, expr);
        out
    }

    fn compile_fails(expr: &str, this_ty: CelType) -> FallbackReason {
        let mut c = Compiler::new();
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { __this },
                ty: this_ty,
                constant: None,
            },
        );
        c.compile(expr).expect_err("expected compile failure")
    }

    fn rendered(t: &TokenStream) -> String {
        t.to_string()
    }

    /// Parse the emitted `TokenStream` as a `syn::Expr` to catch
    /// transpiler bugs that emit token sequences which aren't valid Rust.
    /// Doesn't catch type or borrow-checker errors — those are covered by
    /// the integration test in `tests/emit_compiles.rs` which feeds the
    /// emitted tokens through a real Rust compile.
    fn assert_parses_as_expr(t: &TokenStream, source: &str) {
        if let Err(err) = syn::parse2::<syn::Expr>(t.clone()) {
            panic!(
                "emitted tokens for `{source}` don't parse as a Rust \
                 expression: {err}\n\nemitted:\n{}",
                t.clone(),
            );
        }
    }

    #[test]
    fn int_comparison_to_literal() {
        let out = compile_with_this("this > 0", CelType::Int);
        let s = rendered(&out.tokens);
        assert_eq!(out.ty, CelType::Bool);
        assert!(s.contains("> "), "expected > operator in: {s}");
        assert!(s.contains("__this"), "expected this binding in: {s}");
    }

    #[test]
    fn modulo_equals_emits_arithmetic() {
        let out = compile_with_this("this % 2 == 0", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("% "), "expected modulo in: {s}");
        assert!(s.contains("== "), "expected equality in: {s}");
    }

    #[test]
    fn string_starts_with() {
        let out = compile_with_this("this.startsWith('hello')", CelType::Str { owned: false });
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("starts_with"), "expected starts_with call: {s}");
    }

    #[test]
    fn ternary_string_result() {
        let out = compile_with_this("this > 0 ? '' : 'must be positive'", CelType::Int);
        // Branches are both borrowed-string literals — unify to the
        // borrowed form (no allocation).
        assert!(matches!(out.ty, CelType::Str { .. }));
    }

    #[test]
    fn all_comprehension_on_list() {
        let out = compile_with_this("this.all(x, x > 0)", CelType::List(Box::new(CelType::Int)));
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains(". iter (") || s.contains(".iter("),
            "expected iter call: {s}"
        );
        assert!(
            s.contains(". all (") || s.contains(".all("),
            "expected .all() call: {s}"
        );
    }

    #[test]
    fn exists_comprehension_on_list() {
        let out = compile_with_this(
            "this.exists(x, x == 5)",
            CelType::List(Box::new(CelType::Int)),
        );
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains(". any (") || s.contains(".any("),
            "expected .any() call: {s}"
        );
    }

    #[test]
    fn size_on_string() {
        let out = compile_with_this("size(this) > 5", CelType::Str { owned: false });
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains("chars"),
            "expected chars().count() for size on string: {s}"
        );
    }

    #[test]
    fn size_on_list() {
        let out = compile_with_this("size(this) >= 3", CelType::List(Box::new(CelType::Int)));
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains(". len (") || s.contains(".len("),
            "expected len() for list size: {s}"
        );
    }

    #[test]
    fn dyn_field_access_is_runtime_error() {
        // dyn() erases type → field access on it can't be statically
        // resolved, so the transpiler classifies it as a runtime error.
        let err = compile_fails("dyn(this).b == 'foo'", CelType::Int);
        assert_eq!(err.kind, FallbackKind::RuntimeError);
    }

    #[test]
    fn unsupported_function_falls_back() {
        // CEL functions the transpiler doesn't recognize fall back as
        // Unsupported rather than RuntimeError.
        let err = compile_fails(
            "this.someBuiltinThatDoesNotExist()",
            CelType::Str { owned: false },
        );
        assert_eq!(err.kind, FallbackKind::Unsupported);
    }

    #[test]
    fn float_isnan() {
        let out = compile_with_this("this.isNan()", CelType::Double);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("is_nan"), "expected is_nan call: {s}");
    }

    #[test]
    fn int_cast_from_timestamp() {
        let out = compile_with_this("int(this) > 1000", CelType::Timestamp);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains("timestamp"),
            "expected timestamp() call on chrono type: {s}"
        );
    }

    #[test]
    fn duration_literal_constructor() {
        let out = compile_with_this("this <= duration('10s')", CelType::Duration);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains("duration_from_secs_nanos"),
            "expected duration_from_secs_nanos: {s}",
        );
    }

    #[test]
    fn list_in_operator() {
        let out = compile_with_this("this in [1, 2, 3]", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains(". any (") || s.contains(".any("),
            "expected .any() for `in`: {s}"
        );
    }

    #[test]
    fn now_reference_sets_needs_now() {
        let out = compile_with_this("this < int(now)", CelType::Int);
        assert!(out.needs_now, "expected needs_now to be set");
    }

    #[test]
    fn no_now_means_no_now_prelude() {
        let out = compile_with_this("this > 0", CelType::Int);
        assert!(!out.needs_now, "expected needs_now to be false");
    }

    #[test]
    fn format_string_concatenation() {
        let out = compile_with_this(
            "this > 0 ? '' : 'must be > 0: %d'.format([this])",
            CelType::Int,
        );
        assert!(matches!(out.ty, CelType::Str { .. }));
        // The format directive %d unpacks to a runtime format!() call.
        let s = rendered(&out.tokens);
        assert!(
            s.contains("format !") || s.contains("format!"),
            "expected format!() call: {s}"
        );
    }

    #[test]
    fn map_dot_filter_collects_into_vec() {
        // `lst.filter(x, pred)` should desugar to .filter().cloned().collect().
        let out = compile_with_this(
            "this.filter(x, x > 0)",
            CelType::List(Box::new(CelType::Int)),
        );
        assert!(matches!(out.ty, CelType::List(_)));
        let s = rendered(&out.tokens);
        assert!(
            s.contains(". filter (") || s.contains(".filter("),
            "expected .filter(): {s}"
        );
    }

    #[test]
    fn rule_const_inlines_as_literal() {
        let mut c = Compiler::new();
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { __this },
                ty: CelType::Int,
                constant: None,
            },
        );
        c.bind_rule_const("rule", &crate::scan::RuleConst::Int(42));
        let out = c.compile("this == rule").expect("compile");
        let s = out.tokens.to_string();
        // The literal 42 should appear in the emitted tokens — the
        // `rule` reference folded away.
        assert!(s.contains("42"), "expected 42 inlined: {s}");
    }

    #[test]
    fn message_schema_resolves_scalar_field_select() {
        // `this.foo` on a Message binding resolves `foo` through the
        // schema and emits a direct Rust field access.
        let schema = MessageSchema {
            fields: vec![MessageFieldEntry {
                proto_name: "foo".to_string(),
                rust_ident: "foo".to_string(),
                ty: CelType::Int,
                kind: SchemaFieldKind::Scalar,
            }],
        };
        let mut c = Compiler::new();
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { self },
                ty: CelType::Message(Box::new(schema)),
                constant: None,
            },
        );
        let out = c.compile("this.foo == 5").expect("compile");
        let s = out.tokens.to_string();
        assert_eq!(out.ty, CelType::Bool);
        assert!(
            s.contains("self . foo") || s.contains("self.foo"),
            "expected self.foo: {s}"
        );
        assert!(s.contains("cel_int"), "expected scalar widening: {s}");
    }

    #[test]
    fn message_has_emits_presence_check() {
        // `has(this.foo)` on a Scalar-kind field becomes
        // `(self.foo != 0)` for int — non-default presence.
        let schema = MessageSchema {
            fields: vec![MessageFieldEntry {
                proto_name: "foo".to_string(),
                rust_ident: "foo".to_string(),
                ty: CelType::Int,
                kind: SchemaFieldKind::Scalar,
            }],
        };
        let mut c = Compiler::new();
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { self },
                ty: CelType::Message(Box::new(schema)),
                constant: None,
            },
        );
        let out = c.compile("has(this.foo)").expect("compile");
        assert_eq!(out.ty, CelType::Bool);
        let s = out.tokens.to_string();
        assert!(s.contains("!= 0"), "expected != 0 for Scalar has(): {s}");
    }

    // ====================================================================
    // Bucket 1: type-system edge cases
    //
    // We statically type every expression. If our coercion rules disagree
    // with CEL semantics we silently emit wrong code, so cross-type
    // comparisons / casts / arithmetic deserve direct coverage.
    // ====================================================================

    #[test]
    fn cross_type_int_uint_eq_promotes_to_i128() {
        // CEL: `int == uint` compares by mathematical value. We cast both
        // sides to i128 for the comparison (i64 and u64 each fit exactly).
        let out = compile_with_this("this == 1u", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("i128"), "expected i128 promotion: {s}");
        assert!(s.contains("== "), "expected equality op: {s}");
    }

    #[test]
    fn cross_type_int_uint_ord_promotes_to_i128() {
        let out = compile_with_this("this < 5u", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("i128"), "expected i128 promotion: {s}");
        assert!(s.contains("< "), "expected ord op: {s}");
    }

    #[test]
    fn cross_type_uint_int_ord_promotes_to_i128() {
        // Symmetric case: uint lhs, int rhs.
        let out = compile_with_this("this > 0", CelType::UInt);
        assert_eq!(out.ty, CelType::Bool);
        // Note: `0` parses as Int, so this is UInt vs Int — should
        // promote to i128.
        let s = rendered(&out.tokens);
        assert!(s.contains("i128"), "expected i128 promotion: {s}");
    }

    #[test]
    fn cross_type_int_double_eq() {
        let out = compile_with_this("this == 1.0", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn cast_int_to_uint_literal() {
        let out = compile_with_this("uint(this) > 0u", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains("as u64") || s.contains("u64"),
            "expected u64 cast: {s}"
        );
    }

    #[test]
    fn cast_double_to_int_truncates() {
        let out = compile_with_this("int(this) == 3", CelType::Double);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("as i64"), "expected i64 truncation cast: {s}");
    }

    #[test]
    fn cast_int_to_double() {
        let out = compile_with_this("double(this) > 0.0", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn cast_int_to_string() {
        let out = compile_with_this("string(this) == '42'", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn cast_string_to_bytes() {
        let out = compile_with_this("bytes(this) == b'abc'", CelType::Str { owned: false });
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn cast_bytes_to_string() {
        let out = compile_with_this("string(this) == 'abc'", CelType::Bytes { owned: false });
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn negation_int() {
        let out = compile_with_this("-this == -5", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains('-'), "expected negation: {s}");
    }

    #[test]
    fn negation_double() {
        let out = compile_with_this("-this < 0.0", CelType::Double);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn modulo_uint() {
        let out = compile_with_this("this % 2u == 0u", CelType::UInt);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("% "), "expected modulo: {s}");
    }

    #[test]
    fn division_int() {
        let out = compile_with_this("this / 2 == 5", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn arithmetic_chain() {
        let out = compile_with_this("(this + 1) * 2 > 10", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains("+ ") && s.contains("* "),
            "expected + and *: {s}"
        );
    }

    #[test]
    fn arithmetic_uint() {
        let out = compile_with_this("this + 5u >= 10u", CelType::UInt);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn bool_cast_is_no_op() {
        let out = compile_with_this("bool(this)", CelType::Bool);
        assert_eq!(out.ty, CelType::Bool);
    }

    // ====================================================================
    // Bucket 2: comprehensions
    //
    // `all` / `exists` / `map` / `filter` / `.map(filter, expr)` —
    // subtle iteration semantics, predicate capturing outer `this`,
    // nesting, empty-source behavior.
    // ====================================================================

    #[test]
    fn empty_list_all_short_circuits_to_true() {
        // CEL: `[].all(x, P) → true` vacuously. The transpiler detects
        // the statically empty source and emits a `true` constant without
        // typing the predicate.
        let out = compile_with_this("[].all(x, x > 0)", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert_eq!(s.trim(), "true");
    }

    #[test]
    fn empty_list_exists_short_circuits_to_false() {
        let out = compile_with_this("[].exists(x, x > 0)", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert_eq!(s.trim(), "false");
    }

    #[test]
    fn empty_list_filter_short_circuits_to_empty_list() {
        let out = compile_with_this("size([].filter(x, x > 0)) == 0", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn all_on_short_list_literal() {
        // `.all()` on a typed literal works (elements are typed Int).
        let out = compile_with_this("[1, 2, 3].all(x, x > 0)", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains(". all (") || s.contains(".all("),
            "expected .all(): {s}"
        );
    }

    #[test]
    fn exists_on_short_list_literal() {
        let out = compile_with_this("[1, 2, 3].exists(x, x == 2)", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains(". any (") || s.contains(".any("),
            "expected .any(): {s}"
        );
    }

    #[test]
    fn nested_all_on_list_of_lists() {
        let out = compile_with_this(
            "this.all(row, row.all(x, x > 0))",
            CelType::List(Box::new(CelType::List(Box::new(CelType::Int)))),
        );
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        // Two nested .all() calls.
        let occurrences = s.matches(". all (").count() + s.matches(".all(").count();
        assert!(occurrences >= 2, "expected at least 2 .all() calls: {s}");
    }

    #[test]
    fn map_three_arg_filter_form() {
        // `xs.map(x, x > 0, x * 2)` — filter then transform.
        let out = compile_with_this(
            "this.map(x, x > 0, x * 2)",
            CelType::List(Box::new(CelType::Int)),
        );
        assert!(matches!(out.ty, CelType::List(_)));
        let s = rendered(&out.tokens);
        assert!(
            s.contains("filter") && s.contains("map"),
            "expected filter+map: {s}"
        );
    }

    #[test]
    fn chained_filter_then_size() {
        let out = compile_with_this(
            "size(this.filter(x, x > 0)) >= 1",
            CelType::List(Box::new(CelType::Int)),
        );
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn map_to_typed_list() {
        // `xs.map(x, x * 2)` produces a List<same-element-type>.
        let out = compile_with_this(
            "this.map(x, x + 1).all(y, y > 0)",
            CelType::List(Box::new(CelType::Int)),
        );
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn comprehension_predicate_captures_outer_this() {
        // The inner `x` shadows nothing here; the outer `this` is
        // accessible via the bound `__this` ident. Verify both appear.
        let out = compile_with_this("this.all(x, x > 0)", CelType::List(Box::new(CelType::Int)));
        let s = rendered(&out.tokens);
        assert!(s.contains("__this"), "expected outer this binding: {s}");
    }

    #[test]
    fn exists_with_negated_predicate() {
        let out = compile_with_this(
            "this.exists(x, !(x > 0))",
            CelType::List(Box::new(CelType::Int)),
        );
        assert_eq!(out.ty, CelType::Bool);
    }

    // ====================================================================
    // Bucket 3: has() semantics
    //
    // has() must produce different code per schema kind. Most-at-risk
    // is the boundary between schema-aware paths (Message-typed `this`)
    // and the fallback path (scalar `this`).
    // ====================================================================

    fn message_with_field(name: &str, ty: CelType, kind: SchemaFieldKind) -> MessageSchema {
        MessageSchema {
            fields: vec![MessageFieldEntry {
                proto_name: name.to_string(),
                rust_ident: name.to_string(),
                ty,
                kind,
            }],
        }
    }

    fn compile_with_message_this(expr: &str, schema: MessageSchema) -> CompileOutput {
        let mut c = Compiler::new();
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { self },
                ty: CelType::Message(Box::new(schema)),
                constant: None,
            },
        );
        c.compile(expr).expect("expected successful compile")
    }

    fn compile_with_message_this_fails(expr: &str, schema: MessageSchema) -> FallbackReason {
        let mut c = Compiler::new();
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { self },
                ty: CelType::Message(Box::new(schema)),
                constant: None,
            },
        );
        c.compile(expr).expect_err("expected compile failure")
    }

    #[test]
    fn has_on_scalar_int_emits_zero_compare() {
        let s = message_with_field("x", CelType::Int, SchemaFieldKind::Scalar);
        let out = compile_with_message_this("has(this.x)", s);
        let r = rendered(&out.tokens);
        assert!(r.contains("!= 0"), "expected != 0 for scalar int: {r}");
    }

    #[test]
    fn has_on_scalar_uint_emits_zero_compare() {
        let s = message_with_field("x", CelType::UInt, SchemaFieldKind::Scalar);
        let out = compile_with_message_this("has(this.x)", s);
        let r = rendered(&out.tokens);
        assert!(
            r.contains("0u64") || r.contains("!= 0"),
            "expected != 0u64 cmp: {r}"
        );
    }

    #[test]
    fn has_on_scalar_double_emits_zero_compare() {
        let s = message_with_field("x", CelType::Double, SchemaFieldKind::Scalar);
        let out = compile_with_message_this("has(this.x)", s);
        let r = rendered(&out.tokens);
        assert!(
            r.contains("0f64") || r.contains("!= 0"),
            "expected != 0f64 cmp: {r}"
        );
    }

    #[test]
    fn has_on_scalar_bool_emits_raw_access() {
        let s = message_with_field("x", CelType::Bool, SchemaFieldKind::Scalar);
        let out = compile_with_message_this("has(this.x)", s);
        let r = rendered(&out.tokens);
        // Bool field's `has` just returns the value itself.
        assert!(
            r.contains("self . x") || r.contains("self.x"),
            "expected raw access: {r}"
        );
    }

    #[test]
    fn has_on_string_like_emits_is_empty_negation() {
        let s = message_with_field(
            "x",
            CelType::Str { owned: false },
            SchemaFieldKind::StringLike,
        );
        let out = compile_with_message_this("has(this.x)", s);
        let r = rendered(&out.tokens);
        assert!(r.contains("is_empty"), "expected !is_empty: {r}");
    }

    #[test]
    fn has_on_optional_emits_is_some() {
        let s = message_with_field("x", CelType::Int, SchemaFieldKind::Optional);
        let out = compile_with_message_this("has(this.x)", s);
        let r = rendered(&out.tokens);
        assert!(r.contains("is_some"), "expected is_some: {r}");
    }

    #[test]
    fn has_on_wrapper_emits_is_set() {
        let s = message_with_field("x", CelType::Int, SchemaFieldKind::Wrapper);
        let out = compile_with_message_this("has(this.x)", s);
        let r = rendered(&out.tokens);
        assert!(r.contains("is_set"), "expected is_set: {r}");
    }

    #[test]
    fn has_on_message_field_emits_is_set() {
        let s = message_with_field(
            "x",
            CelType::Dyn,
            SchemaFieldKind::Message {
                proto_fqn: Some("Inner".to_string()),
            },
        );
        let out = compile_with_message_this("has(this.x)", s);
        let r = rendered(&out.tokens);
        assert!(r.contains("is_set"), "expected is_set: {r}");
    }

    #[test]
    fn has_on_repeated_emits_is_empty_negation() {
        let s = message_with_field("x", CelType::Dyn, SchemaFieldKind::Repeated);
        let out = compile_with_message_this("has(this.x)", s);
        let r = rendered(&out.tokens);
        assert!(r.contains("is_empty"), "expected !is_empty: {r}");
    }

    #[test]
    fn has_on_unknown_field_fails() {
        let s = message_with_field("x", CelType::Int, SchemaFieldKind::Scalar);
        let err = compile_with_message_this_fails("has(this.nope)", s);
        // Unknown field shouldn't be a runtime error — it's a static
        // schema mismatch the plugin caught.
        assert_eq!(err.kind, FallbackKind::Unsupported);
    }

    #[test]
    fn has_through_dyn_is_runtime_error() {
        let err = compile_fails("has(dyn(this).foo)", CelType::Int);
        assert_eq!(err.kind, FallbackKind::RuntimeError);
    }

    // ====================================================================
    // Bucket 4: sub-message field resolution
    //
    // MessageRef + SchemaLookup is the tricky bit — it carries a
    // `proto_fqn` string that's resolved at field-selection time so
    // cyclic types don't blow up.
    // ====================================================================

    #[test]
    fn message_ref_missing_from_index_compile_fails() {
        // `this.x` where `x` is a Message field but the FQN isn't in
        // the schema index — compile error, not runtime error.
        let outer = MessageSchema {
            fields: vec![MessageFieldEntry {
                proto_name: "x".to_string(),
                rust_ident: "x".to_string(),
                ty: CelType::Dyn,
                kind: SchemaFieldKind::Message {
                    proto_fqn: Some("Missing".to_string()),
                },
            }],
        };
        let index: BTreeMap<String, MessageSchema> = BTreeMap::new();
        let mut c = Compiler::new().with_schemas(&index);
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { self },
                ty: CelType::Message(Box::new(outer)),
                constant: None,
            },
        );
        let err = c.compile("this.x.a > 0").expect_err("expected fail");
        assert_eq!(err.kind, FallbackKind::Unsupported);
    }

    #[test]
    fn deeply_nested_message_chain_resolves() {
        // a.b.c.x — three levels of MessageRef indirection.
        let leaf = MessageSchema {
            fields: vec![MessageFieldEntry {
                proto_name: "x".to_string(),
                rust_ident: "x".to_string(),
                ty: CelType::Int,
                kind: SchemaFieldKind::Scalar,
            }],
        };
        let mid = MessageSchema {
            fields: vec![MessageFieldEntry {
                proto_name: "c".to_string(),
                rust_ident: "c".to_string(),
                ty: CelType::Dyn,
                kind: SchemaFieldKind::Message {
                    proto_fqn: Some("Leaf".to_string()),
                },
            }],
        };
        let outer = MessageSchema {
            fields: vec![MessageFieldEntry {
                proto_name: "b".to_string(),
                rust_ident: "b".to_string(),
                ty: CelType::Dyn,
                kind: SchemaFieldKind::Message {
                    proto_fqn: Some("Mid".to_string()),
                },
            }],
        };
        let mut index: BTreeMap<String, MessageSchema> = BTreeMap::new();
        index.insert("Leaf".to_string(), leaf);
        index.insert("Mid".to_string(), mid);
        let mut c = Compiler::new().with_schemas(&index);
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { self },
                ty: CelType::Message(Box::new(outer)),
                constant: None,
            },
        );
        let out = c.compile("this.b.c.x > 0").expect("compile");
        assert_eq!(out.ty, CelType::Bool);
        let r = rendered(&out.tokens);
        // Both intermediate hops emit as_option()? — the closure
        // short-circuits if any link is unset.
        assert!(
            r.matches("as_option").count() >= 2,
            "expected ≥2 as_option(): {r}"
        );
    }

    #[test]
    fn self_referential_message_ref_via_lazy_lookup() {
        // A → A (linked-list shape). The MessageRef resolves only when
        // we actually descend, so the schema doesn't recursively embed.
        let a = MessageSchema {
            fields: vec![
                MessageFieldEntry {
                    proto_name: "v".to_string(),
                    rust_ident: "v".to_string(),
                    ty: CelType::Int,
                    kind: SchemaFieldKind::Scalar,
                },
                MessageFieldEntry {
                    proto_name: "next".to_string(),
                    rust_ident: "next".to_string(),
                    ty: CelType::Dyn,
                    kind: SchemaFieldKind::Message {
                        proto_fqn: Some("A".to_string()),
                    },
                },
            ],
        };
        let mut index: BTreeMap<String, MessageSchema> = BTreeMap::new();
        index.insert("A".to_string(), a.clone());
        let mut c = Compiler::new().with_schemas(&index);
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { self },
                ty: CelType::Message(Box::new(a)),
                constant: None,
            },
        );
        let out = c.compile("this.next.v > 0").expect("compile");
        assert_eq!(out.ty, CelType::Bool);
    }

    // ====================================================================
    // Bucket 5: string semantics
    //
    // CEL strings are Unicode codepoints; size() must count chars not
    // bytes, and string ops should map to the right Rust methods.
    // ====================================================================

    #[test]
    fn size_string_uses_chars_count_not_byte_len() {
        // `size(s)` on CEL strings counts codepoints. We emit
        // `s.chars().count()`, which is correct — `s.len()` would
        // give byte length and disagree on multi-byte chars.
        let out = compile_with_this("size(this)", CelType::Str { owned: false });
        let s = rendered(&out.tokens);
        assert!(
            s.contains("chars"),
            "expected chars() for unicode size: {s}"
        );
        assert!(
            !s.contains(". len ()") && !s.contains(".len()"),
            "must not emit byte-length len(): {s}"
        );
    }

    #[test]
    fn string_concat_to_owned() {
        // `'a' + 'b'` — string concat in CEL produces a new string.
        // The transpiler returns an owned `String`.
        let out = compile_with_this("'a' + this", CelType::Str { owned: false });
        assert!(matches!(out.ty, CelType::Str { .. }));
    }

    #[test]
    fn string_contains() {
        let out = compile_with_this("this.contains('foo')", CelType::Str { owned: false });
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("contains"), "expected contains: {s}");
    }

    #[test]
    fn string_ends_with() {
        let out = compile_with_this("this.endsWith('.txt')", CelType::Str { owned: false });
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("ends_with"), "expected ends_with: {s}");
    }

    #[test]
    fn string_matches_literal_pattern_compiles_to_oncelock_regex() {
        let out = compile_with_this(r"this.matches('^[a-z]+$')", CelType::Str { owned: false });
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains("OnceLock") && s.contains("Regex"),
            "expected cached Regex: {s}"
        );
    }

    #[test]
    fn string_matches_dynamic_pattern_compiles_per_call() {
        // A non-literal pattern can't be baked into a `OnceLock<Regex>`;
        // emit a per-call `Regex::new(pat).map(...)`. Slower than the
        // cached path but supports `this.matches(rule)`-style rules where
        // the pattern is a runtime value.
        let mut c = Compiler::new();
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { __this },
                ty: CelType::Str { owned: false },
                constant: None,
            },
        );
        c.bind(
            "pat",
            Binding {
                rust_expr: quote! { __pat },
                ty: CelType::Str { owned: false },
                constant: None,
            },
        );
        let out = c
            .compile("this.matches(pat)")
            .expect("dynamic pattern should compile");
        assert_eq!(out.ty, CelType::Bool);
        let s = out.tokens.to_string();
        assert!(
            s.contains("Regex :: new") || s.contains("Regex::new"),
            "expected per-call Regex::new: {s}"
        );
        assert!(
            !s.contains("OnceLock"),
            "dynamic path must not use OnceLock cache: {s}"
        );
    }

    #[test]
    fn string_lower_ascii() {
        let out = compile_with_this("this.lowerAscii() == 'abc'", CelType::Str { owned: false });
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn string_upper_ascii() {
        let out = compile_with_this("this.upperAscii() == 'ABC'", CelType::Str { owned: false });
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn string_index_of() {
        let out = compile_with_this("this.indexOf('x') >= 0", CelType::Str { owned: false });
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn string_substring() {
        let out = compile_with_this(
            "this.substring(0, 3) == 'abc'",
            CelType::Str { owned: false },
        );
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn string_starts_with_owned_target() {
        // Even when `this` is an owned String, startsWith should resolve.
        let out = compile_with_this("this.startsWith('hi')", CelType::Str { owned: true });
        assert_eq!(out.ty, CelType::Bool);
    }

    // ====================================================================
    // Bucket 6: map indexing
    //
    // Map<K, V> indexing must recover the original Rust scalar type
    // from MapTy. The Borrow workaround in op_index special-cases
    // Str/Bytes keys.
    // ====================================================================

    #[test]
    fn map_index_string_key() {
        let map_ty = CelType::Map(Box::new(MapTy {
            key_cel: CelType::Str { owned: false },
            value_cel: CelType::Int,
            key_rust: RustScalar::Str,
            value_rust: RustScalar::I64,
        }));
        let out = compile_with_this("this['k'] == 1", map_ty);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains(". get (") || s.contains(".get("),
            "expected map .get(): {s}"
        );
    }

    #[test]
    fn map_index_int_key() {
        let map_ty = CelType::Map(Box::new(MapTy {
            key_cel: CelType::Int,
            value_cel: CelType::Str { owned: false },
            key_rust: RustScalar::I64,
            value_rust: RustScalar::Str,
        }));
        let out = compile_with_this("this[1] == 'a'", map_ty);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn map_index_bool_key() {
        let map_ty = CelType::Map(Box::new(MapTy {
            key_cel: CelType::Bool,
            value_cel: CelType::Int,
            key_rust: RustScalar::Bool,
            value_rust: RustScalar::I64,
        }));
        let out = compile_with_this("this[true] == 1", map_ty);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn in_operator_on_map_string_key_emits_contains_key() {
        let map_ty = CelType::Map(Box::new(MapTy {
            key_cel: CelType::Str { owned: false },
            value_cel: CelType::Int,
            key_rust: RustScalar::Str,
            value_rust: RustScalar::I64,
        }));
        let out = compile_with_this("'k' in this", map_ty);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("contains_key"), "expected contains_key: {s}");
    }

    #[test]
    fn in_operator_on_map_int_key_emits_contains_key() {
        let map_ty = CelType::Map(Box::new(MapTy {
            key_cel: CelType::Int,
            value_cel: CelType::Str { owned: false },
            key_rust: RustScalar::I64,
            value_rust: RustScalar::Str,
        }));
        let out = compile_with_this("1 in this", map_ty);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("contains_key"), "expected contains_key: {s}");
    }

    #[test]
    fn size_on_map() {
        let map_ty = CelType::Map(Box::new(MapTy {
            key_cel: CelType::Str { owned: false },
            value_cel: CelType::Int,
            key_rust: RustScalar::Str,
            value_rust: RustScalar::I64,
        }));
        let out = compile_with_this("size(this) > 0", map_ty);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains(". len (") || s.contains(".len("),
            "expected .len() for map size: {s}"
        );
    }

    #[test]
    fn map_all_iterates_keys() {
        // `m.all(k, ...)` in CEL iterates *keys* of the map.
        let map_ty = CelType::Map(Box::new(MapTy {
            key_cel: CelType::Str { owned: false },
            value_cel: CelType::Int,
            key_rust: RustScalar::Str,
            value_rust: RustScalar::I64,
        }));
        let out = compile_with_this("this.all(k, size(k) > 0)", map_ty);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn map_index_then_compare_uses_widened_type() {
        // The map's value is Int (i64). After indexing, comparing
        // against 0 should use i64 semantics.
        let map_ty = CelType::Map(Box::new(MapTy {
            key_cel: CelType::Str { owned: false },
            value_cel: CelType::Int,
            key_rust: RustScalar::Str,
            value_rust: RustScalar::I64,
        }));
        let out = compile_with_this("this['k'] > 0", map_ty);
        let s = rendered(&out.tokens);
        assert!(s.contains("> "), "expected i64 comparison: {s}");
    }

    // ====================================================================
    // Bucket 7: Compiled.constant folding
    //
    // The transpiler tracks compile-time-known constants so that
    // predefined-rule `rule` references inline as Rust literals rather
    // than falling out to runtime expressions.
    // ====================================================================

    #[test]
    fn rule_const_int_inlines_as_i64_literal() {
        let mut c = Compiler::new();
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { __this },
                ty: CelType::Int,
                constant: None,
            },
        );
        c.bind_rule_const("rule", &crate::scan::RuleConst::Int(7));
        let out = c.compile("this == rule").expect("compile");
        let s = out.tokens.to_string();
        assert!(
            s.contains("7i64") || s.contains("7 "),
            "expected i64 literal 7: {s}"
        );
    }

    #[test]
    fn rule_const_uint_inlines_as_u64_literal() {
        let mut c = Compiler::new();
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { __this },
                ty: CelType::UInt,
                constant: None,
            },
        );
        c.bind_rule_const("rule", &crate::scan::RuleConst::UInt(42));
        let out = c.compile("this == rule").expect("compile");
        let s = out.tokens.to_string();
        assert!(
            s.contains("42u64") || s.contains("42 "),
            "expected u64 literal 42: {s}"
        );
    }

    #[test]
    fn rule_const_double_inlines() {
        let mut c = Compiler::new();
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { __this },
                ty: CelType::Double,
                constant: None,
            },
        );
        c.bind_rule_const("rule", &crate::scan::RuleConst::Double(2.5));
        let out = c.compile("this >= rule").expect("compile");
        let s = out.tokens.to_string();
        assert!(
            s.contains("2.5") || s.contains("2.5f64"),
            "expected double literal: {s}"
        );
    }

    #[test]
    fn rule_const_bool_inlines() {
        let mut c = Compiler::new();
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { __this },
                ty: CelType::Bool,
                constant: None,
            },
        );
        c.bind_rule_const("rule", &crate::scan::RuleConst::Bool(true));
        let out = c.compile("this == rule").expect("compile");
        let s = out.tokens.to_string();
        assert!(s.contains("true"), "expected bool literal: {s}");
    }

    #[test]
    fn rule_const_str_inlines_as_str_literal() {
        let mut c = Compiler::new();
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { __this },
                ty: CelType::Str { owned: false },
                constant: None,
            },
        );
        c.bind_rule_const("rule", &crate::scan::RuleConst::Str("hello".to_string()));
        let out = c.compile("this == rule").expect("compile");
        let s = out.tokens.to_string();
        assert!(s.contains("\"hello\""), "expected str literal: {s}");
    }

    #[test]
    fn rule_const_in_arithmetic_folds_into_expression() {
        let mut c = Compiler::new();
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { __this },
                ty: CelType::Int,
                constant: None,
            },
        );
        c.bind_rule_const("rule", &crate::scan::RuleConst::Int(10));
        let out = c.compile("this + rule > 20").expect("compile");
        let s = out.tokens.to_string();
        assert!(
            s.contains("10") && s.contains("20"),
            "expected both literals: {s}"
        );
    }

    #[test]
    fn rule_const_list_iteration() {
        let mut c = Compiler::new();
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { __this },
                ty: CelType::Int,
                constant: None,
            },
        );
        c.bind_rule_const(
            "rule",
            &crate::scan::RuleConst::List(vec![
                crate::scan::RuleConst::Int(1),
                crate::scan::RuleConst::Int(2),
                crate::scan::RuleConst::Int(3),
            ]),
        );
        let out = c.compile("this in rule").expect("compile");
        assert_eq!(out.ty, CelType::Bool);
        let s = out.tokens.to_string();
        assert!(
            s.contains("1i64") || s.contains("[1"),
            "expected list literal: {s}"
        );
    }

    // ====================================================================
    // Bucket 8: map literals + list indexing + dynamic regex +
    //           heterogeneous numeric lists + exists_one
    //
    // Initially documented as transpiler gaps; each one is now supported.
    // ====================================================================

    #[test]
    fn map_literal_string_keys_emits_hashmap_from() {
        let out = compile_with_this("size({'a': 1, 'b': 2}) == 2", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("HashMap"), "expected HashMap construction: {s}");
        assert!(s.contains("String"), "expected owned String keys: {s}");
    }

    #[test]
    fn map_literal_int_keys_lookup() {
        let out = compile_with_this("{1: 'a', 2: 'b'}[1] == 'a'", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("HashMap"), "expected HashMap: {s}");
        assert!(
            s.contains(". get (") || s.contains(".get("),
            "expected .get(): {s}"
        );
    }

    #[test]
    fn map_literal_in_operator() {
        let out = compile_with_this("'a' in {'a': 1, 'b': 2}", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("contains_key"), "expected contains_key: {s}");
    }

    #[test]
    fn empty_map_literal_size_zero() {
        let out = compile_with_this("size({}) == 0", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn map_literal_double_key_rejected_not_hashable() {
        // CEL map keys: bool / int / uint / string. Double is not allowed
        // because f64 has no Hash impl. Reject at codegen.
        let err = compile_fails("size({1.0: 'a'}) == 1", CelType::Int);
        assert_eq!(err.kind, FallbackKind::Unsupported);
        assert!(err.message.contains("hashable"), "{}", err.message);
    }

    #[test]
    fn list_index_int_element() {
        let out = compile_with_this("this[0] == 1", CelType::List(Box::new(CelType::Int)));
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("as usize"), "expected usize cast: {s}");
    }

    #[test]
    fn list_index_string_element_returns_borrowed() {
        let out = compile_with_this(
            "this[0] == 'foo'",
            CelType::List(Box::new(CelType::Str { owned: false })),
        );
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("AsRef"), "expected AsRef<str> for borrow: {s}");
    }

    #[test]
    fn list_index_through_list_literal() {
        let out = compile_with_this("[10, 20, 30][1] == 20", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn heterogeneous_int_double_list_promotes_to_double() {
        // `[1, 2.0]` — element type should widen to Double, not truncate
        // 2.0 down to Int. The list compares correctly against a Double
        // needle.
        let out = compile_with_this("2.0 in [1, 2.0, 3.0]", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn heterogeneous_uint_double_list_promotes_to_double() {
        let out = compile_with_this("2.0 in [1u, 2.0, 3u]", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn heterogeneous_int_uint_list_still_rejected() {
        // CEL doesn't have a single "integer" promotion target — int+uint
        // is intentionally not promoted by `promote_numeric`. List
        // literals inherit that restriction.
        let err = compile_fails("size([1, 2u])", CelType::Int);
        assert_eq!(err.kind, FallbackKind::Unsupported);
    }

    #[test]
    fn exists_one_on_list() {
        let out = compile_with_this(
            "this.exists_one(x, x == 5)",
            CelType::List(Box::new(CelType::Int)),
        );
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        // The emission shape uses a counter with an early break.
        assert!(s.contains("__cel_count"), "expected counter loop: {s}");
        assert!(s.contains("break"), "expected early break: {s}");
        assert!(s.contains("== 1"), "expected final == 1 check: {s}");
    }

    #[test]
    fn exists_one_on_empty_list_short_circuits_to_false() {
        // 0 matches → count == 1 is false. Falls into the same
        // statically-empty short-circuit as `exists`.
        let out = compile_with_this("[].exists_one(x, x == 5)", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert_eq!(s.trim(), "false");
    }

    #[test]
    fn exists_one_on_typed_short_list() {
        let out = compile_with_this("[1, 2, 3].exists_one(x, x > 1)", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
    }

    // ====================================================================
    // Bucket 11: timezone-arg timestamp accessors + optional types.
    // ====================================================================

    #[test]
    fn timestamp_get_full_year_with_tz_arg() {
        let out = compile_with_this(
            "this.getFullYear('America/New_York') >= 2020",
            CelType::Timestamp,
        );
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("chrono_tz"), "expected chrono_tz tz parse: {s}");
        assert!(s.contains("with_timezone"), "expected with_timezone: {s}");
    }

    #[test]
    fn timestamp_get_hours_with_tz_arg() {
        let out = compile_with_this("this.getHours('UTC') < 24", CelType::Timestamp);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn duration_accessor_rejects_tz_arg() {
        // Duration accessors take no args; tz is timestamp-only.
        let err = compile_fails("this.getHours('UTC') < 24", CelType::Duration);
        assert_eq!(err.kind, FallbackKind::Unsupported);
    }

    #[test]
    fn optional_of_int() {
        let out = compile_with_this("optional.of(this).hasValue()", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("Some"), "expected Some(): {s}");
        assert!(s.contains("is_some"), "expected is_some: {s}");
    }

    #[test]
    fn optional_none_in_ternary_with_some() {
        // `optional.none()` has Optional<Dyn> typing; unify_branches
        // adapts it to Optional<Int> via the other branch.
        let out = compile_with_this(
            "(this > 0 ? optional.of(this) : optional.none()).orValue(0) >= 0",
            CelType::Int,
        );
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn optional_or_value_default() {
        let out = compile_with_this("optional.of(this).orValue(-1) >= 0", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("unwrap_or"), "expected unwrap_or: {s}");
    }

    #[test]
    fn optional_value_unwrap() {
        let out = compile_with_this("optional.of(this).value() == 5", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("expect"), "expected expect: {s}");
    }

    #[test]
    fn optional_of_non_zero_int() {
        let out = compile_with_this("optional.ofNonZeroValue(this).hasValue()", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("!= 0i64"), "expected zero-check: {s}");
    }

    #[test]
    fn optional_of_non_zero_string() {
        let out = compile_with_this(
            "optional.ofNonZeroValue(this).hasValue()",
            CelType::Str { owned: false },
        );
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("is_empty"), "expected !is_empty: {s}");
    }

    #[test]
    fn opt_index_map_returns_optional() {
        let map_ty = CelType::Map(Box::new(MapTy {
            key_cel: CelType::Str { owned: false },
            value_cel: CelType::Int,
            key_rust: RustScalar::Str,
            value_rust: RustScalar::I64,
        }));
        let out = compile_with_this("this[?'k'].hasValue()", map_ty);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn opt_index_list_returns_optional() {
        let out = compile_with_this(
            "this[?0].orValue(0) >= 0",
            CelType::List(Box::new(CelType::Int)),
        );
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn opt_select_blocked_by_parser() {
        // UPSTREAM LIMITATION: cel-rs 0.13's parser does not recognize
        // the `?.` optional-select syntax even with
        // `enable_optional_syntax(true)`; the `?` is greedily parsed as
        // the start of a ternary operator. The transpiler has an
        // `op_opt_select` impl ready to handle `OPT_SELECT` AST nodes,
        // but they're unreachable until the parser is fixed upstream.
        // Pinned so we notice if cel-rs ships a fix.
        let err = compile_fails("optional.of(this)?.x", CelType::Int);
        assert_eq!(err.kind, FallbackKind::Unsupported);
        assert!(err.message.contains("parse"), "{}", err.message);
    }

    // ====================================================================
    // Bucket 10: timestamp accessors, math.*, reverse / distinct,
    //            isFinite.
    // ====================================================================

    #[test]
    fn timestamp_get_full_year() {
        let out = compile_with_this("this.getFullYear() >= 2020", CelType::Timestamp);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("year"), "expected year(): {s}");
    }

    #[test]
    fn timestamp_get_month_is_zero_based() {
        let out = compile_with_this("this.getMonth() == 0", CelType::Timestamp);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        // We subtract 1 from chrono's 1-based month.
        assert!(s.contains("- 1"), "expected - 1 adjustment: {s}");
    }

    #[test]
    fn timestamp_get_day_of_week() {
        let out = compile_with_this("this.getDayOfWeek() == 0", CelType::Timestamp);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn timestamp_get_hours_minutes_seconds() {
        let out = compile_with_this(
            "this.getHours() == 12 && this.getMinutes() == 0 && this.getSeconds() == 0",
            CelType::Timestamp,
        );
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn math_abs_int() {
        let out = compile_with_this("math.abs(this) > 5", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains("wrapping_abs") || s.contains("abs"),
            "expected abs(): {s}"
        );
    }

    #[test]
    fn math_greatest_three_args() {
        let out = compile_with_this("math.greatest(this, 5, 10) >= 10", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn math_least_two_args() {
        let out = compile_with_this("math.least(this, 0) <= 0", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn math_ceil_floor_round_trunc() {
        for fname in &["ceil", "floor", "round", "trunc"] {
            let out = compile_with_this(&format!("math.{fname}(this) >= 0.0"), CelType::Double);
            assert_eq!(out.ty, CelType::Bool);
        }
    }

    #[test]
    fn math_sign_int() {
        let out = compile_with_this("math.sign(this) > 0", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn math_bit_and_or_xor() {
        for fname in &["bitAnd", "bitOr", "bitXor"] {
            let out = compile_with_this(&format!("math.{fname}(this, 5u) >= 0u"), CelType::UInt);
            assert_eq!(out.ty, CelType::Bool);
        }
    }

    #[test]
    fn math_bit_not() {
        let out = compile_with_this("math.bitNot(this) > 0u", CelType::UInt);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn math_bit_shift() {
        let out = compile_with_this("math.bitShiftLeft(this, 2u) > 0u", CelType::UInt);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn float_is_finite() {
        let out = compile_with_this("this.isFinite()", CelType::Double);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("is_finite"), "expected is_finite: {s}");
    }

    #[test]
    fn string_reverse_unicode() {
        let out = compile_with_this("this.reverse() == 'olleh'", CelType::Str { owned: false });
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("chars"), "expected chars().rev(): {s}");
    }

    #[test]
    fn list_reverse() {
        let out = compile_with_this(
            "this.reverse().all(x, x > 0)",
            CelType::List(Box::new(CelType::Int)),
        );
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn list_distinct_int() {
        let out = compile_with_this(
            "size(this.distinct()) >= 0",
            CelType::List(Box::new(CelType::Int)),
        );
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn list_distinct_string() {
        let out = compile_with_this(
            "size(this.distinct()) >= 0",
            CelType::List(Box::new(CelType::Str { owned: false })),
        );
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn list_distinct_double_unsupported() {
        // f64 isn't Hash, so distinct on doubles falls back.
        let err = compile_fails(
            "size(this.distinct()) >= 0",
            CelType::List(Box::new(CelType::Double)),
        );
        assert_eq!(err.kind, FallbackKind::Unsupported);
    }

    // ====================================================================
    // Bucket 9: type() reflection, dynamic time constructors,
    //           two-var comprehensions, non-string join, extra format
    //           directives.
    // ====================================================================

    #[test]
    fn type_of_int_folds_to_int_marker() {
        let out = compile_with_this("type(this) == int", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("\"int\""), "expected int marker: {s}");
    }

    #[test]
    fn type_of_string_folds_to_string_marker() {
        let out = compile_with_this("type(this) == string", CelType::Str { owned: false });
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("\"string\""), "expected string marker: {s}");
    }

    #[test]
    fn type_of_list_folds_to_list_marker() {
        let out = compile_with_this(
            "type(this) == list_type",
            CelType::List(Box::new(CelType::Int)),
        );
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn type_of_int_not_equal_to_string_marker() {
        // `type(int_val) == string` is a compile-time-false comparison.
        let out = compile_with_this("type(this) == string", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        // Both sides are string constants; they compare unequal.
        assert!(
            s.contains("\"int\"") && s.contains("\"string\""),
            "expected both type markers: {s}"
        );
    }

    #[test]
    fn duration_dynamic_arg_uses_runtime_parser() {
        // `duration(this)` where `this` is a string — emits a call to
        // `parse_duration` rather than the literal-fold path.
        let out = compile_with_this(
            "duration(this) >= duration('1s')",
            CelType::Str { owned: false },
        );
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains("parse_duration"),
            "expected parse_duration call: {s}"
        );
    }

    #[test]
    fn timestamp_dynamic_arg_uses_runtime_parser() {
        let out = compile_with_this(
            "timestamp(this) > timestamp('2020-01-01T00:00:00Z')",
            CelType::Str { owned: false },
        );
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains("parse_timestamp"),
            "expected parse_timestamp call: {s}"
        );
    }

    #[test]
    fn two_var_map_all_binds_key_and_value() {
        // cel-rs's macro expander only matches the 2-arg form; the
        // 3-arg `.all(k, v, P)` form lands as a plain method call. The
        // transpiler intercepts it in `try_two_var_comprehension`,
        // bringing `k` and `v` into scope from `.iter()` pairs.
        let map_ty = CelType::Map(Box::new(MapTy {
            key_cel: CelType::Str { owned: false },
            value_cel: CelType::Int,
            key_rust: RustScalar::Str,
            value_rust: RustScalar::I64,
        }));
        let out = compile_with_this("this.all(k, v, size(k) > 0 && v > 0)", map_ty);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains(". iter (") || s.contains(".iter("),
            "expected .iter() over pairs: {s}"
        );
    }

    #[test]
    fn two_var_list_all_binds_index_and_value() {
        // `xs.all(i, v, …)` — `i` is the index (Int), `v` is the element.
        let out = compile_with_this(
            "this.all(i, v, i >= 0 && v > 0)",
            CelType::List(Box::new(CelType::Int)),
        );
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains("enumerate"),
            "expected .enumerate() for two-var list: {s}"
        );
    }

    #[test]
    fn two_var_map_exists() {
        let map_ty = CelType::Map(Box::new(MapTy {
            key_cel: CelType::Str { owned: false },
            value_cel: CelType::Int,
            key_rust: RustScalar::Str,
            value_rust: RustScalar::I64,
        }));
        let out = compile_with_this("this.exists(k, v, v == 1)", map_ty);
        assert_eq!(out.ty, CelType::Bool);
    }

    #[test]
    fn two_var_map_exists_one() {
        let map_ty = CelType::Map(Box::new(MapTy {
            key_cel: CelType::Str { owned: false },
            value_cel: CelType::Int,
            key_rust: RustScalar::Str,
            value_rust: RustScalar::I64,
        }));
        let out = compile_with_this("this.exists_one(k, v, v == 1)", map_ty);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains("__cel_count"), "expected counter loop: {s}");
    }

    #[test]
    fn two_var_map_filter() {
        let map_ty = CelType::Map(Box::new(MapTy {
            key_cel: CelType::Str { owned: false },
            value_cel: CelType::Int,
            key_rust: RustScalar::Str,
            value_rust: RustScalar::I64,
        }));
        let out = compile_with_this("this.filter(k, v, v > 0)", map_ty);
        assert!(matches!(out.ty, CelType::List(_)));
    }

    #[test]
    fn two_var_map_map_three_arg_taken_by_filter_form() {
        // KNOWN: cel-rs's `find_expander` macroizes 3-arg `.map` as the
        // single-var "filter-then-map" comprehension, so
        // `this.map(k, v, expr)` is parsed as `iter_var=k, filter=v,
        // mapped=expr` — `v` is an unbound ident, the transpiler fails.
        // Use the 4-arg form `.map(k, v, filter, mapped)` instead.
        let map_ty = CelType::Map(Box::new(MapTy {
            key_cel: CelType::Str { owned: false },
            value_cel: CelType::Int,
            key_rust: RustScalar::Str,
            value_rust: RustScalar::I64,
        }));
        let mut c = Compiler::new();
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { __this },
                ty: map_ty,
                constant: None,
            },
        );
        let err = c
            .compile("this.map(k, v, v + 1)")
            .expect_err("3-arg map is taken by the filter-form macro");
        assert_eq!(err.kind, FallbackKind::Unsupported);
        assert!(err.message.contains("unknown ident"), "{}", err.message);
    }

    #[test]
    fn two_var_map_map_four_arg_with_filter() {
        // `.map(k, v, filter, mapped)`.
        let map_ty = CelType::Map(Box::new(MapTy {
            key_cel: CelType::Str { owned: false },
            value_cel: CelType::Int,
            key_rust: RustScalar::Str,
            value_rust: RustScalar::I64,
        }));
        let out = compile_with_this("this.map(k, v, v > 0, v * 2)", map_ty);
        assert!(matches!(out.ty, CelType::List(_)));
    }

    #[test]
    fn join_on_int_list_uses_display_format() {
        let out = compile_with_this(
            "this.join(',') == '1,2,3'",
            CelType::List(Box::new(CelType::Int)),
        );
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains("format"),
            "expected format!() for non-string join: {s}"
        );
    }

    #[test]
    fn join_on_bool_list_uses_display_format() {
        let out = compile_with_this("this.join('|')", CelType::List(Box::new(CelType::Bool)));
        assert!(matches!(out.ty, CelType::Str { .. }));
    }

    #[test]
    fn join_on_double_list_uses_display_format() {
        let out = compile_with_this("this.join(' ')", CelType::List(Box::new(CelType::Double)));
        assert!(matches!(out.ty, CelType::Str { .. }));
    }

    /// Build the rendered-token needle for a Rust formatting directive.
    /// Avoids a literal `"{:x}"`-style string that clippy's
    /// `literal_string_with_formatting_args` flags as a misplaced format
    /// arg.
    fn fmt_needle(directive: &str) -> String {
        let mut s = String::from("{:");
        s.push_str(directive);
        s.push('}');
        s
    }

    #[test]
    fn format_directive_hex_lowercase() {
        let out = compile_with_this("'%x'.format([this]) == 'ff'", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(s.contains(&fmt_needle("x")), "expected hex format: {s}");
    }

    #[test]
    fn format_directive_hex_uppercase() {
        let out = compile_with_this("'%X'.format([this]) == 'FF'", CelType::Int);
        assert_eq!(out.ty, CelType::Bool);
        let s = rendered(&out.tokens);
        assert!(
            s.contains(&fmt_needle("X")),
            "expected upper-hex format: {s}"
        );
    }

    #[test]
    fn format_directive_octal() {
        let out = compile_with_this("'%o'.format([this])", CelType::Int);
        let s = rendered(&out.tokens);
        assert!(s.contains(&fmt_needle("o")), "expected octal format: {s}");
    }

    #[test]
    fn format_directive_binary() {
        let out = compile_with_this("'%b'.format([this])", CelType::UInt);
        let s = rendered(&out.tokens);
        assert!(s.contains(&fmt_needle("b")), "expected binary format: {s}");
    }

    #[test]
    fn format_directive_scientific() {
        let out = compile_with_this("'%e'.format([this])", CelType::Double);
        let s = rendered(&out.tokens);
        assert!(
            s.contains(&fmt_needle(".6e")),
            "expected scientific format: {s}"
        );
    }

    #[test]
    fn struct_literal_is_unsupported_with_clear_reason() {
        // Documenting that proto message literals inside CEL still fail.
        let err = compile_fails("MyMessage{x: 1}", CelType::Int);
        assert_eq!(err.kind, FallbackKind::Unsupported);
        assert!(err.message.contains("struct"), "{}", err.message);
    }

    #[test]
    fn schemalookup_btreemap_impl_resolves_message_ref() {
        // `BTreeMap<String, MessageSchema>` implements `SchemaLookup`,
        // so chained `this.e.a` selects through it natively.
        let inner = MessageSchema {
            fields: vec![MessageFieldEntry {
                proto_name: "a".to_string(),
                rust_ident: "a".to_string(),
                ty: CelType::Int,
                kind: SchemaFieldKind::Scalar,
            }],
        };
        let outer = MessageSchema {
            fields: vec![MessageFieldEntry {
                proto_name: "e".to_string(),
                rust_ident: "e".to_string(),
                ty: CelType::Dyn,
                kind: SchemaFieldKind::Message {
                    proto_fqn: Some("Inner".to_string()),
                },
            }],
        };
        let mut index: BTreeMap<String, MessageSchema> = BTreeMap::new();
        index.insert("Inner".to_string(), inner);
        let mut c = Compiler::new().with_schemas(&index);
        c.bind(
            "this",
            Binding {
                rust_expr: quote! { self },
                ty: CelType::Message(Box::new(outer)),
                constant: None,
            },
        );
        let out = c.compile("this.e.a > 0").expect("compile");
        assert_eq!(out.ty, CelType::Bool);
        let s = out.tokens.to_string();
        // The `?` short-circuit on the sub-message lookup must be emitted
        // so the validate body skips the rule when `e` is unset.
        assert!(
            s.contains("as_option ()"),
            "expected as_option() on sub-message: {s}"
        );
        assert!(
            s.contains("? )") || s.contains("? . a") || s.contains(". a"),
            "expected nested .a access: {s}"
        );
    }
}
