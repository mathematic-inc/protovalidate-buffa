//! Helpers used by compile-time-expanded CEL rules emitted by the plugin.
//!
//! CEL rules are transpiled to native Rust at codegen time, so this module
//! is a narrow support layer rather than an interpreter: scalar widening
//! (`CelScalar`), Duration/Timestamp conversion
//! ([`duration_from_secs_nanos`], [`timestamp_from_secs_nanos`]), and the
//! per-evaluation `now` binding ([`now_local`]). Generated expressions use
//! [`Duration`] and [`Timestamp`] to keep the time backend private.
//!
//! ```
//! use protovalidate_buffa::cel::{duration_from_secs_nanos, timestamp_from_secs_nanos};
//! let epoch = timestamp_from_secs_nanos(0, 0);
//! let second = duration_from_secs_nanos(1, 0);
//! assert_eq!(epoch.checked_add_signed(second), Some(timestamp_from_secs_nanos(1, 0)));
//! ```

mod temporal;

#[cfg(feature = "tz")]
pub use temporal::in_time_zone;
pub use temporal::{
    Duration, Timestamp, duration_from_secs_nanos, now_local, parse_duration, parse_timestamp,
    timestamp_from_secs_nanos,
};

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
