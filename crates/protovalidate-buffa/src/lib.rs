//! Runtime companion for `protoc-gen-protovalidate-buffa`.
//!
//! Provides the [`Validate`] trait, the [`ValidationError`] /
//! [`Violation`] / [`FieldPath`] types returned from generated
//! `validate()` methods, the [`cel`] module that backs message-level
//! and field-level CEL rules, and the [`rules`] module of pure-Rust
//! helpers used by generated code (UUID / ULID / IP / URI / hostname
//! checks and friends, mostly thin wrappers over `uuid`, `ulid`,
//! `ipnet`, and `fluent-uri`).
//!
//! [`ValidationError`] carries three orthogonal signals:
//!
//! - `violations`: list of per-field rule failures (the common case).
//! - `compile_error`: non-empty when the codegen plugin detected a
//!   schema-level mismatch (rule type / field type, duplicate / unknown
//!   fields in `message.oneof`, CEL referencing a non-existent field).
//! - `runtime_error`: non-empty when a rule's precondition could not be
//!   evaluated (e.g. `bytes.pattern` on non-UTF-8 input, CEL type
//!   mismatch).
//!
//! The full upstream `protovalidate-conformance` suite (2872 cases,
//! covering proto2, proto3, and editions 2023) passes against code
//! emitted by the paired plugin.

pub mod cel;
mod error;
pub mod rules;

#[cfg(feature = "connect")]
mod connect;

// Re-export external crates referenced by plugin-generated code so that
// downstream crates only need to depend on `protovalidate-buffa` and not on
// `regex` / `cel` / `buffa` directly.
pub use buffa;
pub use ::cel as cel_core;
pub use error::{FieldPath, FieldPathElement, FieldType, Subscript, ValidationError, Violation};
/// `#[connect_impl]` — attribute macro applied to a Connect service `impl`
/// block that inserts `req.validate()?` at the top of every handler method.
/// Guarantees protovalidate runs for every RPC without relying on per-handler
/// discipline.
pub use protovalidate_buffa_macros::connect_impl;
pub use regex;

pub trait Validate {
    /// Runs every rule attached to this message (and any nested messages),
    /// collecting violations rather than short-circuiting on the first.
    ///
    /// # Errors
    ///
    /// Returns a [`ValidationError`] containing one or more [`Violation`]s
    /// when any rule fails. Callers typically map this to
    /// `ConnectError::invalid_argument` via
    /// [`ValidationError::into_connect_error`] (requires the `connect` feature).
    fn validate(&self) -> Result<(), ValidationError>;
}

#[macro_export]
macro_rules! field_path {
    ( $( $part:expr ),* $(,)? ) => {{
        let mut elements = ::std::vec::Vec::new();
        $(
            elements.push($crate::FieldPathElement {
                field_number: None,
                field_name: Some(::std::borrow::Cow::Borrowed($part)),
                field_type: None,
                key_type: None,
                value_type: None,
                subscript: None,
            });
        )*
        $crate::FieldPath { elements }
    }};
}
