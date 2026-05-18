//! Runtime companion for `protoc-gen-protovalidate-buffa`.
//!
//! Provides the [`Validate`] trait, the [`ValidationError`] /
//! [`Violation`] / [`FieldPath`] types returned from generated
//! `validate()` methods, the [`cel`] module of thin helpers that
//! compile-time-expanded CEL rules call into (scalar widening,
//! Duration/Timestamp converters, `now`), and the [`rules`] module
//! of pure-Rust helpers used by generated code (UUID / ULID / IP /
//! URI / hostname checks and friends, mostly thin wrappers over
//! `uuid`, `ulid`, `ipnet`, and `fluent-uri`).
//!
//! There is **no CEL interpreter at runtime**: the paired
//! `protoc-gen-protovalidate-buffa` plugin transpiles every CEL rule
//! to native Rust at codegen time. Generated `validate()` methods are
//! direct field-access checks with zero per-call `Value` / `HashMap`
//! allocations.
//!
//! [`ValidationError`] carries three orthogonal signals:
//!
//! - `violations`: list of per-field rule failures (the common case).
//! - `compile_error`: non-empty when the codegen plugin detected a
//!   schema-level mismatch (rule type / field type, duplicate / unknown
//!   fields in `message.oneof`, CEL referencing a non-existent field).
//! - `runtime_error`: non-empty when a rule's precondition could not be
//!   evaluated (e.g. `bytes.pattern` on non-UTF-8 input, or a CEL rule
//!   that compiled-time analysis flagged as always-runtime-error such as
//!   `dyn(this).<unknown_field>`).
//!
//! The full upstream `protovalidate-conformance` suite (2872 cases,
//! covering proto2, proto3, and editions 2023) passes against code
//! emitted by the paired plugin.

pub mod cel;
mod error;
pub mod rules;

#[cfg(feature = "connect")]
mod connect;

// Re-export `regex` so generated patterns (`::protovalidate_buffa::regex::Regex`)
// resolve without each downstream crate having to add a direct `regex` dep.
// `buffa` is re-exported for convenience but generated code uses the
// `::buffa::` path directly; downstream crates already depend on buffa for
// their message types.
pub use buffa;
/// IANA timezone database, re-exported so generated code can reference
/// `::protovalidate_buffa::chrono_tz::Tz` when a CEL rule uses the
/// timezone-argument form of a timestamp accessor
/// (`t.getHours("America/New_York")`). Only exported when the `tz`
/// feature is enabled — rules without tz args don't need this dep.
#[cfg(feature = "tz")]
pub use chrono_tz;
pub use error::{FieldPath, FieldPathElement, FieldType, Subscript, ValidationError, Violation};
/// `#[connect_impl]` — attribute macro applied to a Connect service `impl`
/// block that inserts `req.validate()?` at the top of every handler method.
/// Guarantees protovalidate runs for every RPC without relying on per-handler
/// discipline.
///
/// Only exported when the `connect` feature is enabled (the default), since
/// the emitted code calls [`ValidationError::into_connect_error`].
#[cfg(feature = "connect")]
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
