//! Helpers used by compile-time-expanded CEL rules emitted by the plugin.
//!
//! CEL rules are transpiled to native Rust at codegen time, so this module
//! is a narrow support layer rather than an interpreter: scalar widening
//! (`CelScalar`), Duration/Timestamp conversion
//! (`duration_from_secs_nanos`, `timestamp_from_secs_nanos`), and the
//! per-evaluation `now` binding (`now_local`).

/// Current wall-clock time as a `chrono::DateTime<chrono::FixedOffset>`.
///
/// Used to seed the `now` binding inside compile-time-expanded CEL bodies.
/// Lives in this crate so generated code doesn't need to depend on `chrono`
/// directly.
#[must_use]
pub fn now_local() -> chrono::DateTime<chrono::FixedOffset> {
    chrono::Utc::now().fixed_offset()
}

/// Width-converts a proto scalar (or enum wrapper) into CEL's wide types
/// (`i64` / `u64` / `f64`).
///
/// Used by codegen-emitted native CEL bodies so a single emitted
/// comparison/arithmetic expression works regardless of the underlying Rust
/// representation (`i32`, `u32`, `i64`, `u64`, `f32`, `f64`, or
/// `buffa::EnumValue<E>`).
pub trait CelScalar: Copy {
    /// Coerce to CEL's `int` wide type. Numeric `as`-casts; for
    /// `EnumValue<E>` returns `i64::from(self.to_i32())`.
    fn cel_int(self) -> i64;
    /// Coerce to CEL's `uint` wide type. Numeric `as`-casts; for floats
    /// the cast truncates toward zero.
    fn cel_uint(self) -> u64;
    /// Coerce to CEL's `double` wide type.
    fn cel_double(self) -> f64;
}

macro_rules! impl_cel_scalar_int {
    ($($t:ty),*) => {
        $(
            impl CelScalar for $t {
                #[inline]
                #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss, clippy::cast_lossless, clippy::cast_precision_loss)]
                fn cel_int(self) -> i64 { self as i64 }
                #[inline]
                #[allow(clippy::cast_sign_loss, clippy::cast_lossless)]
                fn cel_uint(self) -> u64 { self as u64 }
                #[inline]
                #[allow(clippy::cast_lossless, clippy::cast_precision_loss)]
                fn cel_double(self) -> f64 { self as f64 }
            }
        )*
    };
}
impl_cel_scalar_int!(i32, i64, u32, u64);

impl CelScalar for f32 {
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    fn cel_int(self) -> i64 {
        self as i64
    }
    #[inline]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn cel_uint(self) -> u64 {
        self as u64
    }
    #[inline]
    fn cel_double(self) -> f64 {
        f64::from(self)
    }
}

impl CelScalar for f64 {
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    fn cel_int(self) -> i64 {
        self as i64
    }
    #[inline]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn cel_uint(self) -> u64 {
        self as u64
    }
    #[inline]
    fn cel_double(self) -> f64 {
        self
    }
}

impl<E: buffa::Enumeration + Copy> CelScalar for buffa::EnumValue<E> {
    #[inline]
    fn cel_int(self) -> i64 {
        i64::from(self.to_i32())
    }
    #[inline]
    #[allow(clippy::cast_sign_loss)]
    fn cel_uint(self) -> u64 {
        self.to_i32() as u64
    }
    #[inline]
    fn cel_double(self) -> f64 {
        f64::from(self.to_i32())
    }
}

/// Construct a `chrono::Duration` from a protobuf-shaped
/// `(seconds, nanos)` pair (the wire format of
/// `google.protobuf.Duration`).
///
/// Used by codegen-emitted CEL bodies when binding `this` to a
/// `MessageField<Duration>` value or when constructing a literal via
/// `duration("…")`.
#[must_use]
pub fn duration_from_secs_nanos(seconds: i64, nanos: i32) -> chrono::Duration {
    chrono::Duration::seconds(seconds) + chrono::Duration::nanoseconds(i64::from(nanos))
}

/// Construct a `chrono::DateTime<chrono::FixedOffset>` from a
/// protobuf-shaped `(seconds, nanos)` pair (the wire format of
/// `google.protobuf.Timestamp`).
///
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

/// Parse a CEL `duration("…")` string into a `chrono::Duration`.
///
/// Accepts the protobuf duration grammar: an optional sign, a decimal
/// number, and one of the suffixes `ns` / `us` / `µs` / `ms` / `s` / `m`
/// / `h`. Returns `None` on any parse error so the caller can decide
/// whether to map that to a CEL runtime error.
///
/// Used by codegen for `duration(this.field)` where `this.field` isn't
/// a compile-time-known string literal; literal-arg paths fold the parse
/// into `duration_from_secs_nanos(secs, nanos)` at codegen time and do
/// not call this.
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn parse_duration(s: &str) -> Option<chrono::Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Split into sign + magnitude + unit. We accept a leading `+` or `-`.
    let (sign, rest) = match s.as_bytes()[0] {
        b'-' => (-1i64, &s[1..]),
        b'+' => (1i64, &s[1..]),
        _ => (1i64, s),
    };
    // Find the unit suffix.
    let (num_str, unit) = if let Some(stripped) = rest.strip_suffix("ns") {
        (stripped, "ns")
    } else if let Some(stripped) = rest.strip_suffix("us") {
        (stripped, "us")
    } else if let Some(stripped) = rest.strip_suffix("µs") {
        (stripped, "us")
    } else if let Some(stripped) = rest.strip_suffix("ms") {
        (stripped, "ms")
    } else if let Some(stripped) = rest.strip_suffix('s') {
        (stripped, "s")
    } else if let Some(stripped) = rest.strip_suffix('m') {
        (stripped, "m")
    } else if let Some(stripped) = rest.strip_suffix('h') {
        (stripped, "h")
    } else {
        return None;
    };
    let value: f64 = num_str.parse().ok()?;
    let nanos_total: f64 = match unit {
        "ns" => value,
        "us" => value * 1_000.0,
        "ms" => value * 1_000_000.0,
        "s" => value * 1_000_000_000.0,
        "m" => value * 60.0 * 1_000_000_000.0,
        "h" => value * 3600.0 * 1_000_000_000.0,
        _ => return None,
    };
    if !nanos_total.is_finite() {
        return None;
    }
    let signed = (nanos_total as i64).checked_mul(sign)?;
    Some(chrono::Duration::nanoseconds(signed))
}

/// Parse a CEL `timestamp("…")` string (RFC3339).
///
/// Returns `None` on any parse error. Used by codegen for
/// `timestamp(this.field)` where the argument isn't a compile-time
/// literal — the literal-arg path bakes the result into a cached
/// `OnceLock<DateTime>` at codegen time and doesn't call this.
#[must_use]
pub fn parse_timestamp(s: &str) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    chrono::DateTime::parse_from_rfc3339(s).ok()
}
