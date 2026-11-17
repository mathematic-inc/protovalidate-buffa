//! Keep the time backend private and preserve protobuf conversion behavior.
//! Constructors retain the previous ranges; emitted arithmetic enforces CEL's
//! narrower bounds. IANA lookup selects an offset at the given UTC instant.

use time::{OffsetDateTime, SignedDuration, UtcOffset, format_description::well_known::Rfc3339};

// Preserve the previous backend's limits, including malformed protobuf inputs.
// https://docs.rs/chrono/0.4.45/chrono/struct.TimeDelta.html
const MIN_DURATION: SignedDuration = SignedDuration::milliseconds(-i64::MAX);
const MAX_DURATION: SignedDuration = SignedDuration::milliseconds(i64::MAX);
// https://docs.rs/chrono/0.4.45/chrono/struct.NaiveDate.html
const MIN_YEAR: i32 = -262_143;
const MAX_YEAR: i32 = 262_142;

/// A signed, nanosecond-precision value used by generated CEL expressions.
///
/// Construction saturates at ±`i64::MAX` milliseconds. Generated arithmetic
/// additionally checks CEL's narrower `i64` nanosecond range.
///
/// # Examples
/// ```
/// use protovalidate_buffa::cel::duration_from_secs_nanos;
/// assert_eq!(duration_from_secs_nanos(-1, -1).num_nanoseconds(), Some(-1_000_000_001));
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Duration(SignedDuration);

// ===== impl Duration =====

impl Duration {
    /// A duration of zero seconds.
    pub const ZERO: Self = Self(SignedDuration::ZERO);

    fn from_inner(value: SignedDuration) -> Option<Self> {
        (MIN_DURATION..=MAX_DURATION)
            .contains(&value)
            .then_some(Self(value))
    }

    /// Whole seconds, truncated toward zero.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::duration_from_secs_nanos;
    /// assert_eq!(duration_from_secs_nanos(-1, -1).num_seconds(), -1);
    /// ```
    #[must_use]
    pub const fn num_seconds(self) -> i64 {
        self.0.whole_seconds()
    }

    /// Whole milliseconds, truncated toward zero.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::duration_from_secs_nanos;
    /// assert_eq!(duration_from_secs_nanos(0, -1_999_999).num_milliseconds(), -1);
    /// ```
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Duration is bounded to i64 milliseconds"
    )]
    pub const fn num_milliseconds(self) -> i64 {
        self.0.whole_milliseconds() as i64
    }

    /// Whole minutes, truncated toward zero.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::duration_from_secs_nanos;
    /// assert_eq!(duration_from_secs_nanos(-61, 0).num_minutes(), -1);
    /// ```
    #[must_use]
    pub const fn num_minutes(self) -> i64 {
        self.0.whole_minutes()
    }

    /// Whole hours, truncated toward zero.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::duration_from_secs_nanos;
    /// assert_eq!(duration_from_secs_nanos(-3601, 0).num_hours(), -1);
    /// ```
    #[must_use]
    pub const fn num_hours(self) -> i64 {
        self.0.whole_hours()
    }

    /// Nanoseconds, or `None` outside CEL's duration range.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::duration_from_secs_nanos;
    /// assert_eq!(duration_from_secs_nanos(0, -1).num_nanoseconds(), Some(-1));
    /// ```
    #[must_use]
    pub fn num_nanoseconds(self) -> Option<i64> {
        i64::try_from(self.0.whole_nanoseconds()).ok()
    }

    /// Add a duration, returning `None` outside the construction range.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::duration_from_secs_nanos;
    /// let second = duration_from_secs_nanos(1, 0);
    /// assert_eq!(second.checked_add(second), Some(duration_from_secs_nanos(2, 0)));
    /// ```
    #[must_use]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).and_then(Self::from_inner)
    }

    /// Subtract a duration, returning `None` outside the construction range.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::{Duration, duration_from_secs_nanos};
    /// let second = duration_from_secs_nanos(1, 0);
    /// assert_eq!(second.checked_sub(second), Some(Duration::ZERO));
    /// ```
    #[must_use]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).and_then(Self::from_inner)
    }
}

/// An instant with a fixed offset used by generated CEL expressions.
///
/// Ordering and equality compare instants. Calendar accessors retain the parsed
/// offset, or the offset selected by `in_time_zone` when `tz` is enabled.
/// Construction accepts UTC years -262143 through 262142.
///
/// # Examples
/// ```
/// use protovalidate_buffa::cel::{parse_timestamp, timestamp_from_secs_nanos};
/// let t = parse_timestamp("1970-01-01T01:00:00+01:00").unwrap();
/// assert_eq!(t, timestamp_from_secs_nanos(0, 0));
/// assert_eq!(t.hour(), 1);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Timestamp(OffsetDateTime);

// ===== impl Timestamp =====

impl Timestamp {
    const UNIX_EPOCH: Self = Self(OffsetDateTime::UNIX_EPOCH);

    fn from_inner(value: OffsetDateTime) -> Option<Self> {
        let year = value.checked_to_offset(UtcOffset::UTC)?.year();
        (MIN_YEAR..=MAX_YEAR).contains(&year).then_some(Self(value))
    }

    /// Seconds since the Unix epoch, rounded down for negative instants.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::parse_timestamp;
    /// let t = parse_timestamp("2024-02-29T12:34:56.123456789Z").unwrap();
    /// assert_eq!(t.timestamp(), 1_709_210_096);
    /// ```
    #[must_use]
    pub const fn timestamp(self) -> i64 {
        self.0.unix_timestamp()
    }

    /// Calendar year in the selected offset.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::parse_timestamp;
    /// let t = parse_timestamp("2024-02-29T12:34:56.123456789Z").unwrap();
    /// assert_eq!(t.year(), 2024);
    /// ```
    #[must_use]
    pub const fn year(self) -> i32 {
        self.0.year()
    }

    /// Calendar month, from 1 to 12.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::parse_timestamp;
    /// let t = parse_timestamp("2024-02-29T12:34:56.123456789Z").unwrap();
    /// assert_eq!(t.month(), 2);
    /// ```
    #[must_use]
    pub const fn month(self) -> u8 {
        self.0.month() as u8
    }

    /// Day of the month, from 1 to 31.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::parse_timestamp;
    /// let t = parse_timestamp("2024-02-29T12:34:56.123456789Z").unwrap();
    /// assert_eq!(t.day(), 29);
    /// ```
    #[must_use]
    pub const fn day(self) -> u8 {
        self.0.day()
    }

    /// Day of the week, with Sunday equal to zero.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::parse_timestamp;
    /// let t = parse_timestamp("2024-02-29T12:34:56.123456789Z").unwrap();
    /// assert_eq!(t.weekday_from_sunday(), 4);
    /// ```
    #[must_use]
    pub const fn weekday_from_sunday(self) -> u8 {
        self.0.weekday().number_days_from_sunday()
    }

    /// Day of the year, from 1 to 366.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::parse_timestamp;
    /// let t = parse_timestamp("2024-02-29T12:34:56.123456789Z").unwrap();
    /// assert_eq!(t.ordinal(), 60);
    /// ```
    #[must_use]
    pub const fn ordinal(self) -> u16 {
        self.0.ordinal()
    }

    /// Hour in the selected offset, from 0 to 23.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::parse_timestamp;
    /// let t = parse_timestamp("2024-02-29T12:34:56.123456789Z").unwrap();
    /// assert_eq!(t.hour(), 12);
    /// ```
    #[must_use]
    pub const fn hour(self) -> u8 {
        self.0.hour()
    }

    /// Minute in the selected offset, from 0 to 59.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::parse_timestamp;
    /// let t = parse_timestamp("2024-02-29T12:34:56.123456789Z").unwrap();
    /// assert_eq!(t.minute(), 34);
    /// ```
    #[must_use]
    pub const fn minute(self) -> u8 {
        self.0.minute()
    }

    /// Second in the selected offset, from 0 to 59.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::parse_timestamp;
    /// let t = parse_timestamp("2024-02-29T12:34:56.123456789Z").unwrap();
    /// assert_eq!(t.second(), 56);
    /// ```
    #[must_use]
    pub const fn second(self) -> u8 {
        self.0.second()
    }

    /// Nonnegative fractional nanoseconds, from 0 to 999,999,999.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::parse_timestamp;
    /// let t = parse_timestamp("2024-02-29T12:34:56.123456789Z").unwrap();
    /// assert_eq!(t.nanosecond(), 123_456_789);
    /// ```
    #[must_use]
    pub const fn nanosecond(self) -> u32 {
        self.0.nanosecond()
    }

    /// Add elapsed time, returning `None` outside the timestamp range.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::{duration_from_secs_nanos, timestamp_from_secs_nanos};
    /// let epoch = timestamp_from_secs_nanos(0, 0);
    /// assert_eq!(epoch.checked_add_signed(duration_from_secs_nanos(1, 0)), Some(timestamp_from_secs_nanos(1, 0)));
    /// ```
    #[must_use]
    pub fn checked_add_signed(self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration.0).and_then(Self::from_inner)
    }

    /// Subtract elapsed time, returning `None` outside the timestamp range.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::{duration_from_secs_nanos, timestamp_from_secs_nanos};
    /// let epoch = timestamp_from_secs_nanos(0, 0);
    /// assert_eq!(epoch.checked_sub_signed(duration_from_secs_nanos(1, 0)), Some(timestamp_from_secs_nanos(-1, 0)));
    /// ```
    #[must_use]
    pub fn checked_sub_signed(self, duration: Duration) -> Option<Self> {
        self.0.checked_sub(duration.0).and_then(Self::from_inner)
    }

    /// Elapsed time since `earlier`, independent of either offset.
    ///
    /// # Examples
    /// ```
    /// use protovalidate_buffa::cel::timestamp_from_secs_nanos;
    /// let epoch = timestamp_from_secs_nanos(0, 0);
    /// assert_eq!(timestamp_from_secs_nanos(0, 1).signed_duration_since(epoch).num_nanoseconds(), Some(1));
    /// ```
    #[must_use]
    pub fn signed_duration_since(self, earlier: Self) -> Duration {
        // The timestamp range is narrower than Duration's construction range.
        Duration(self.0 - earlier.0)
    }
}

/// Current UTC wall-clock time for the generated `now` binding.
///
/// # Panics
/// Panics if the platform cannot read its wall clock or it exceeds `time`'s range.
///
/// # Examples
/// ```
/// use protovalidate_buffa::cel::now_local;
/// let now = now_local();
/// assert!(now.nanosecond() < 1_000_000_000);
/// ```
#[must_use]
#[track_caller]
pub fn now_local() -> Timestamp {
    Timestamp::from_inner(OffsetDateTime::now_utc()).unwrap_or(Timestamp::UNIX_EPOCH)
}

/// Convert protobuf duration fields, saturating at ±`i64::MAX` milliseconds.
///
/// # Examples
/// ```
/// use protovalidate_buffa::cel::duration_from_secs_nanos;
/// assert_eq!(duration_from_secs_nanos(-1, 1).num_nanoseconds(), Some(-999_999_999));
/// ```
#[must_use]
pub fn duration_from_secs_nanos(seconds: i64, nanos: i32) -> Duration {
    let fallback = Duration(if seconds < 0 {
        MIN_DURATION
    } else {
        MAX_DURATION
    });
    // Check whole seconds first to preserve the previous normalization order.
    Duration::from_inner(SignedDuration::seconds(seconds))
        .and_then(|duration| {
            duration.checked_add(Duration(SignedDuration::nanoseconds(i64::from(nanos))))
        })
        .unwrap_or(fallback)
}

/// Convert protobuf timestamp fields.
///
/// Negative nanos clamp to zero. Seconds outside UTC years -262143 through
/// 262142, or nanos above 999,999,999,
/// fall back to the Unix epoch. Leap seconds are unsupported.
///
/// # Examples
/// ```
/// use protovalidate_buffa::cel::timestamp_from_secs_nanos;
/// assert_eq!(timestamp_from_secs_nanos(-1, 999_999_999).timestamp(), -1);
/// ```
#[must_use]
pub fn timestamp_from_secs_nanos(seconds: i64, nanos: i32) -> Timestamp {
    let nanos = u32::try_from(nanos.max(0)).unwrap_or(0);
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()
        .and_then(|value| value.replace_nanosecond(nanos).ok())
        .and_then(Timestamp::from_inner)
        .unwrap_or(Timestamp::UNIX_EPOCH)
}

/// Parse one signed decimal and a suffix: `ns`, `us`, `µs`, `ms`, `s`, `m`, or `h`.
/// Returns `None` for invalid input; compound durations and bare `0` are unsupported.
///
/// # Examples
/// ```
/// use protovalidate_buffa::cel::parse_duration;
/// assert_eq!(parse_duration("-1.5s").unwrap().num_milliseconds(), -1500);
/// assert!(parse_duration("1h30m").is_none());
/// ```
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let (sign, rest) = match *s.as_bytes().first()? {
        b'-' => (-1i64, &s[1..]),
        b'+' => (1i64, &s[1..]),
        _ => (1i64, s),
    };
    let (num_str, unit) = split_unit(rest)?;
    let value: f64 = num_str.parse().ok()?;
    let nanos_total = match unit {
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
    Some(Duration(SignedDuration::nanoseconds(signed)))
}

fn split_unit(rest: &str) -> Option<(&str, &'static str)> {
    // Longest suffix first: `ms` must precede `s`.
    const SUFFIXES: [(&str, &str); 7] = [
        ("ns", "ns"),
        ("us", "us"),
        ("µs", "us"),
        ("ms", "ms"),
        ("s", "s"),
        ("m", "m"),
        ("h", "h"),
    ];
    SUFFIXES
        .into_iter()
        .find_map(|(suffix, unit)| rest.strip_suffix(suffix).map(|n| (n, unit)))
}

/// Parse an RFC 3339 timestamp, retaining its offset. Returns `None` on invalid
/// input, including leap-second spellings, which protobuf timestamps cannot store.
///
/// # Examples
/// ```
/// use protovalidate_buffa::cel::parse_timestamp;
/// assert_eq!(parse_timestamp("1970-01-01T01:00:00+01:00").unwrap().timestamp(), 0);
/// assert!(parse_timestamp("2016-12-31T23:59:60Z").is_none());
/// ```
#[must_use]
pub fn parse_timestamp(s: &str) -> Option<Timestamp> {
    // `time` permits arbitrary separators and clamps leap seconds; CEL does neither.
    // https://protobuf.dev/reference/protobuf/google.protobuf/#timestamp
    if !matches!(s.as_bytes().get(10).copied(), Some(b'T' | b't' | b' '))
        || s.get(17..19) == Some("60")
    {
        return None;
    }
    OffsetDateTime::parse(s, &Rfc3339)
        .ok()
        .and_then(Timestamp::from_inner)
}

/// Select an IANA name, numeric offset, or empty string for UTC.
/// Returns `None` for unknown names or invalid offsets.
///
/// # Examples
/// ```
/// use protovalidate_buffa::cel::{in_time_zone, timestamp_from_secs_nanos};
/// let t = in_time_zone(timestamp_from_secs_nanos(0, 0), "America/New_York").unwrap();
/// assert_eq!(t.hour(), 19);
/// ```
#[cfg(feature = "tz")]
#[cfg_attr(docsrs, doc(cfg(feature = "tz")))]
#[must_use]
pub fn in_time_zone(t: Timestamp, tz: &str) -> Option<Timestamp> {
    let seconds = if let Some((hours, minutes)) = tz.split_once(':') {
        let hours: i32 = hours.parse().ok()?;
        let minutes: i32 = minutes.parse().ok()?;
        if !(-23..=23).contains(&hours) || !(0..=59).contains(&minutes) {
            return None;
        }
        let minutes = if tz.starts_with('-') {
            -minutes
        } else {
            minutes
        };
        hours * 3600 + minutes * 60
    } else if tz.is_empty() {
        0
    } else {
        // tzdb lookup is case-insensitive; preserve CEL's exact IANA spelling.
        if !tzdb::TZ_NAMES.contains(&tz) {
            return None;
        }
        tzdb::tz_by_name(tz)?
            .find_local_time_type(t.timestamp())
            .ok()?
            .ut_offset()
    };
    let offset = UtcOffset::from_whole_seconds(seconds).ok()?;
    t.0.checked_to_offset(offset).map(Timestamp)
}
