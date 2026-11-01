//! Standard rules apply to repeated items, map keys, map values, explicit
//! presence fields, and wrappers as they do to singular fields, in owned
//! messages and views.

#![warn(rust_2018_idioms)]

use buffa::{HasMessageView, Message, encoding::encode_varint};
use buffa_descriptor::generated::descriptor::{
    DescriptorProto, FieldDescriptorProto, FileDescriptorSet, field_descriptor_proto::Type,
};
use protovalidate_buffa::{FieldPathElement, FieldType, Subscript, Validate, Violation};

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    elided_lifetimes_in_paths,
    non_camel_case_types,
    unused_imports,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_html_tags,
    reason = "buffa-build generated code"
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/_collection_include.rs"));
}

/// One scalar value with its wire encoding.
#[derive(Clone, Copy, Debug)]
enum Wire {
    Str(&'static str),
    Bytes(&'static [u8]),
    Int(i64),
    Uint(u64),
    Sint(i64),
    Fixed32(u32),
    Fixed64(u64),
    Sfixed32(i32),
    Sfixed64(i64),
    Float(f32),
    Double(f64),
    Bool(bool),
    Enum(i64),
    Time(i64, i32),
    Now(i64),
    Any(&'static str),
    Mask(&'static [&'static str]),
}

// ===== impl Wire =====

impl Wire {
    fn put(self, number: u32, bytes: &mut Vec<u8>) {
        let tag = u64::from(number) << 3;
        match self {
            Self::Str(value) => put_len(number, value.as_bytes(), bytes),
            Self::Bytes(value) => put_len(number, value, bytes),
            Self::Int(value) | Self::Enum(value) => {
                encode_varint(tag, bytes);
                encode_varint(value.cast_unsigned(), bytes);
            }
            Self::Time(seconds, nanos) => {
                let mut inner = Vec::new();
                Self::Int(seconds).put(1, &mut inner);
                Self::Int(i64::from(nanos)).put(2, &mut inner);
                put_len(number, &inner, bytes);
            }
            Self::Now(offset) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("test clock after epoch");
                Self::Time(
                    i64::try_from(now.as_secs()).expect("clock fits i64") + offset,
                    0,
                )
                .put(number, bytes);
            }
            Self::Any(url) => {
                let mut inner = Vec::new();
                Self::Str(url).put(1, &mut inner);
                put_len(number, &inner, bytes);
            }
            Self::Mask(paths) => {
                let mut inner = Vec::new();
                for path in paths {
                    Self::Str(path).put(1, &mut inner);
                }
                put_len(number, &inner, bytes);
            }
            Self::Uint(value) => {
                encode_varint(tag, bytes);
                encode_varint(value, bytes);
            }
            Self::Sint(value) => {
                encode_varint(tag, bytes);
                encode_varint(zigzag_i64(value), bytes);
            }
            Self::Bool(value) => {
                encode_varint(tag, bytes);
                encode_varint(u64::from(value), bytes);
            }
            Self::Fixed32(value) => put_fixed(tag | 5, &value.to_le_bytes(), bytes),
            Self::Sfixed32(value) => put_fixed(tag | 5, &value.to_le_bytes(), bytes),
            Self::Float(value) => put_fixed(tag | 5, &value.to_le_bytes(), bytes),
            Self::Fixed64(value) => put_fixed(tag | 1, &value.to_le_bytes(), bytes),
            Self::Sfixed64(value) => put_fixed(tag | 1, &value.to_le_bytes(), bytes),
            Self::Double(value) => put_fixed(tag | 1, &value.to_le_bytes(), bytes),
        }
    }

    /// Bytes, float, and double cannot be map keys.
    const fn is_key_type(self) -> bool {
        !matches!(
            self,
            Self::Bytes(_)
                | Self::Float(_)
                | Self::Double(_)
                | Self::Enum(_)
                | Self::Time(..)
                | Self::Now(_)
                | Self::Any(_)
                | Self::Mask(_)
        )
    }

    fn assert_key(self, subscript: Option<&Subscript>) {
        match (self, subscript) {
            (Self::Str(expected), Some(Subscript::StringKey(actual))) => {
                assert_eq!(actual, expected);
            }
            (
                Self::Int(expected) | Self::Sint(expected) | Self::Sfixed64(expected),
                Some(Subscript::IntKey(actual)),
            ) => assert_eq!(*actual, expected),
            (Self::Sfixed32(expected), Some(Subscript::IntKey(actual))) => {
                assert_eq!(*actual, i64::from(expected));
            }
            (Self::Uint(expected) | Self::Fixed64(expected), Some(Subscript::UintKey(actual))) => {
                assert_eq!(*actual, expected);
            }
            (Self::Fixed32(expected), Some(Subscript::UintKey(actual))) => {
                assert_eq!(*actual, u64::from(expected));
            }
            (Self::Bool(expected), Some(Subscript::BoolKey(actual))) => {
                assert_eq!(*actual, expected);
            }
            _ => panic!("unexpected subscript {subscript:?} for key {self:?}"),
        }
    }
}

const fn zigzag_i64(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)).cast_unsigned()
}

#[test]
fn zigzag_handles_integer_boundaries() {
    for (value, expected) in [
        (0, 0),
        (-1, 1),
        (1, 2),
        (i64::MIN, u64::MAX),
        (i64::MAX, u64::MAX - 1),
    ] {
        assert_eq!(zigzag_i64(value), expected);
    }
}

fn put_len(number: u32, value: &[u8], bytes: &mut Vec<u8>) {
    encode_varint((u64::from(number) << 3) | 2, bytes);
    encode_varint(value.len() as u64, bytes);
    bytes.extend_from_slice(value);
}

fn put_fixed(tag: u64, value: &[u8], bytes: &mut Vec<u8>) {
    encode_varint(tag, bytes);
    bytes.extend_from_slice(value);
}

/// A rule set on field `number` of `Items`, `Keys`, and `Values`, with a value
/// that satisfies it and one that breaks it.
struct Case {
    number: u32,
    /// Protobuf family and configured rule, independent of the emitter.
    rule: &'static str,
    /// Expected violation ID; combined rules can differ from the configured path.
    rule_id: &'static str,
    good: Wire,
    bad: Wire,
}

const fn case(
    number: u32,
    rule: &'static str,
    rule_id: &'static str,
    good: Wire,
    bad: Wire,
) -> Case {
    Case {
        number,
        rule,
        rule_id,
        good,
        bad,
    }
}

use Wire::{
    Any, Bool, Bytes, Double, Enum, Fixed32, Fixed64, Float, Int, Mask, Now, Sfixed32, Sfixed64,
    Sint, Str, Time, Uint,
};

/// 9999-12-31T23:59:59Z, the protobuf timestamp upper bound.
const YEAR_9999: i64 = 253_402_300_799;

// Co-update proto/validation/collection_rules/proto3/collections.proto.
// build/rule_matrix.rs expands that catalogue across positions and syntaxes.
const CASES: &[Case] = &[
    case(1, "string.const", "string.const", Str("abc"), Str("abx")),
    case(2, "string.len", "string.len", Str("abc"), Str("ab")),
    case(3, "string.min_len", "string.min_len", Str("ab"), Str("a")),
    case(
        4,
        "string.max_len",
        "string.max_len",
        Str("abc"),
        Str("abcd"),
    ),
    case(
        5,
        "string.len_bytes",
        "string.len_bytes",
        Str("abc"),
        Str("ab"),
    ),
    case(
        6,
        "string.min_bytes",
        "string.min_bytes",
        Str("ab"),
        Str("a"),
    ),
    case(
        7,
        "string.max_bytes",
        "string.max_bytes",
        Str("abc"),
        Str("\u{430}\u{431}\u{432}"),
    ),
    case(8, "string.pattern", "string.pattern", Str("aa"), Str("ab")),
    case(
        9,
        "string.prefix",
        "string.prefix",
        Str("prefix"),
        Str("fix"),
    ),
    case(
        10,
        "string.suffix",
        "string.suffix",
        Str("suffix"),
        Str("suffer"),
    ),
    case(
        11,
        "string.contains",
        "string.contains",
        Str("amidst"),
        Str("amist"),
    ),
    case(
        12,
        "string.not_contains",
        "string.not_contains",
        Str("good"),
        Str("badge"),
    ),
    case(13, "string.in", "string.in", Str("a"), Str("c")),
    case(14, "string.not_in", "string.not_in", Str("a"), Str("x")),
    case(
        15,
        "string.email",
        "string.email",
        Str("a@example.com"),
        Str("not-an-email"),
    ),
    case(
        16,
        "string.hostname",
        "string.hostname",
        Str("example.com"),
        Str("-bad-"),
    ),
    case(
        17,
        "string.ip",
        "string.ip",
        Str("127.0.0.1"),
        Str("300.0.0.1"),
    ),
    case(
        18,
        "string.ipv4",
        "string.ipv4",
        Str("127.0.0.1"),
        Str("::1"),
    ),
    case(
        19,
        "string.ipv6",
        "string.ipv6",
        Str("::1"),
        Str("127.0.0.1"),
    ),
    case(
        20,
        "string.uri",
        "string.uri",
        Str("https://example.com/x"),
        Str("not a uri"),
    ),
    case(
        21,
        "string.uri_ref",
        "string.uri_ref",
        Str("./path"),
        Str("\\"),
    ),
    case(
        22,
        "string.address",
        "string.address",
        Str("example.com"),
        Str("-bad-"),
    ),
    case(
        23,
        "string.uuid",
        "string.uuid",
        Str("8a6b7e2c-8c4c-4f7a-9d5e-1b2c3d4e5f60"),
        Str("not-a-uuid"),
    ),
    case(
        24,
        "string.tuuid",
        "string.tuuid",
        Str("8a6b7e2c8c4c4f7a9d5e1b2c3d4e5f60"),
        Str("not-a-uuid"),
    ),
    case(
        25,
        "string.ip_with_prefixlen",
        "string.ip_with_prefixlen",
        Str("10.0.0.1/8"),
        Str("10.0.0.1"),
    ),
    case(
        26,
        "string.ipv4_with_prefixlen",
        "string.ipv4_with_prefixlen",
        Str("10.0.0.1/8"),
        Str("::1/64"),
    ),
    case(
        27,
        "string.ipv6_with_prefixlen",
        "string.ipv6_with_prefixlen",
        Str("::1/64"),
        Str("10.0.0.1/8"),
    ),
    case(
        28,
        "string.ip_prefix",
        "string.ip_prefix",
        Str("10.0.0.0/8"),
        Str("10.0.0.1/8"),
    ),
    case(
        29,
        "string.ipv4_prefix",
        "string.ipv4_prefix",
        Str("10.0.0.0/8"),
        Str("10.0.0.1/8"),
    ),
    case(
        30,
        "string.ipv6_prefix",
        "string.ipv6_prefix",
        Str("2001:db8::/32"),
        Str("2001:db8::1/32"),
    ),
    case(
        31,
        "string.host_and_port",
        "string.host_and_port",
        Str("example.com:443"),
        Str("example.com"),
    ),
    case(
        32,
        "string.ulid",
        "string.ulid",
        Str("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        Str("not-a-ulid"),
    ),
    case(
        33,
        "string.protobuf_fqn",
        "string.protobuf_fqn",
        Str("foo.bar"),
        Str("foo..bar"),
    ),
    case(
        34,
        "string.protobuf_dot_fqn",
        "string.protobuf_dot_fqn",
        Str(".foo.bar"),
        Str(".foo..bar"),
    ),
    case(
        35,
        "string.well_known_regex",
        "string.well_known_regex.header_name",
        Str("content-type"),
        Str("bad name"),
    ),
    case(
        36,
        "bytes.const",
        "bytes.const",
        Bytes(b"abc"),
        Bytes(b"abx"),
    ),
    case(37, "bytes.len", "bytes.len", Bytes(b"abc"), Bytes(b"ab")),
    case(
        38,
        "bytes.min_len",
        "bytes.min_len",
        Bytes(b"ab"),
        Bytes(b"a"),
    ),
    case(
        39,
        "bytes.max_len",
        "bytes.max_len",
        Bytes(b"abc"),
        Bytes(b"abcd"),
    ),
    case(
        40,
        "bytes.pattern",
        "bytes.pattern",
        Bytes(b"aa"),
        Bytes(b"ab"),
    ),
    case(
        41,
        "bytes.prefix",
        "bytes.prefix",
        Bytes(b"prefix"),
        Bytes(b"fix"),
    ),
    case(
        42,
        "bytes.suffix",
        "bytes.suffix",
        Bytes(b"suffix"),
        Bytes(b"suffer"),
    ),
    case(
        43,
        "bytes.contains",
        "bytes.contains",
        Bytes(b"amidst"),
        Bytes(b"amist"),
    ),
    case(44, "bytes.in", "bytes.in", Bytes(b"a"), Bytes(b"c")),
    case(45, "bytes.not_in", "bytes.not_in", Bytes(b"a"), Bytes(b"x")),
    case(
        46,
        "bytes.ip",
        "bytes.ip",
        Bytes(b"\x7f\0\0\x01"),
        Bytes(b"\x7f\0\x01"),
    ),
    case(
        47,
        "bytes.ipv4",
        "bytes.ipv4",
        Bytes(b"\x7f\0\0\x01"),
        Bytes(b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"),
    ),
    case(
        48,
        "bytes.ipv6",
        "bytes.ipv6",
        Bytes(b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"),
        Bytes(b"\x7f\0\0\x01"),
    ),
    case(
        49,
        "bytes.uuid",
        "bytes.uuid",
        Bytes(b"0123456789abcdef"),
        Bytes(b"abc"),
    ),
    case(50, "int32.const", "int32.const", Int(5), Int(6)),
    case(51, "int32.lt", "int32.lt", Int(4), Int(5)),
    case(52, "int32.lte", "int32.lte", Int(5), Int(6)),
    case(53, "int32.gt", "int32.gt", Int(6), Int(5)),
    case(54, "int32.gte", "int32.gte", Int(5), Int(4)),
    case(55, "int32.in", "int32.in", Int(5), Int(7)),
    case(56, "int32.not_in", "int32.not_in", Int(5), Int(7)),
    case(57, "int64.const", "int64.const", Int(5), Int(6)),
    case(58, "int64.lt", "int64.lt", Int(4), Int(5)),
    case(59, "int64.lte", "int64.lte", Int(5), Int(6)),
    case(60, "int64.gt", "int64.gt", Int(6), Int(5)),
    case(61, "int64.gte", "int64.gte", Int(5), Int(4)),
    case(62, "int64.in", "int64.in", Int(5), Int(7)),
    case(63, "int64.not_in", "int64.not_in", Int(5), Int(7)),
    case(64, "uint32.const", "uint32.const", Uint(5), Uint(6)),
    case(65, "uint32.lt", "uint32.lt", Uint(4), Uint(5)),
    case(66, "uint32.lte", "uint32.lte", Uint(5), Uint(6)),
    case(67, "uint32.gt", "uint32.gt", Uint(6), Uint(5)),
    case(68, "uint32.gte", "uint32.gte", Uint(5), Uint(4)),
    case(69, "uint32.in", "uint32.in", Uint(5), Uint(7)),
    case(70, "uint32.not_in", "uint32.not_in", Uint(5), Uint(7)),
    case(71, "uint64.const", "uint64.const", Uint(5), Uint(6)),
    case(72, "uint64.lt", "uint64.lt", Uint(4), Uint(5)),
    case(73, "uint64.lte", "uint64.lte", Uint(5), Uint(6)),
    case(74, "uint64.gt", "uint64.gt", Uint(6), Uint(5)),
    case(75, "uint64.gte", "uint64.gte", Uint(5), Uint(4)),
    case(76, "uint64.in", "uint64.in", Uint(5), Uint(7)),
    case(77, "uint64.not_in", "uint64.not_in", Uint(5), Uint(7)),
    case(78, "sint32.const", "sint32.const", Sint(5), Sint(6)),
    case(79, "sint32.lt", "sint32.lt", Sint(4), Sint(5)),
    case(80, "sint32.lte", "sint32.lte", Sint(5), Sint(6)),
    case(81, "sint32.gt", "sint32.gt", Sint(6), Sint(5)),
    case(82, "sint32.gte", "sint32.gte", Sint(5), Sint(4)),
    case(83, "sint32.in", "sint32.in", Sint(5), Sint(7)),
    case(84, "sint32.not_in", "sint32.not_in", Sint(5), Sint(7)),
    case(85, "sint64.const", "sint64.const", Sint(5), Sint(6)),
    case(86, "sint64.lt", "sint64.lt", Sint(4), Sint(5)),
    case(87, "sint64.lte", "sint64.lte", Sint(5), Sint(6)),
    case(88, "sint64.gt", "sint64.gt", Sint(6), Sint(5)),
    case(89, "sint64.gte", "sint64.gte", Sint(5), Sint(4)),
    case(90, "sint64.in", "sint64.in", Sint(5), Sint(7)),
    case(91, "sint64.not_in", "sint64.not_in", Sint(5), Sint(7)),
    case(92, "fixed32.const", "fixed32.const", Fixed32(5), Fixed32(6)),
    case(93, "fixed32.lt", "fixed32.lt", Fixed32(4), Fixed32(5)),
    case(94, "fixed32.lte", "fixed32.lte", Fixed32(5), Fixed32(6)),
    case(95, "fixed32.gt", "fixed32.gt", Fixed32(6), Fixed32(5)),
    case(96, "fixed32.gte", "fixed32.gte", Fixed32(5), Fixed32(4)),
    case(97, "fixed32.in", "fixed32.in", Fixed32(5), Fixed32(7)),
    case(
        98,
        "fixed32.not_in",
        "fixed32.not_in",
        Fixed32(5),
        Fixed32(7),
    ),
    case(99, "fixed64.const", "fixed64.const", Fixed64(5), Fixed64(6)),
    case(100, "fixed64.lt", "fixed64.lt", Fixed64(4), Fixed64(5)),
    case(101, "fixed64.lte", "fixed64.lte", Fixed64(5), Fixed64(6)),
    case(102, "fixed64.gt", "fixed64.gt", Fixed64(6), Fixed64(5)),
    case(103, "fixed64.gte", "fixed64.gte", Fixed64(5), Fixed64(4)),
    case(104, "fixed64.in", "fixed64.in", Fixed64(5), Fixed64(7)),
    case(
        105,
        "fixed64.not_in",
        "fixed64.not_in",
        Fixed64(5),
        Fixed64(7),
    ),
    case(
        106,
        "sfixed32.const",
        "sfixed32.const",
        Sfixed32(5),
        Sfixed32(6),
    ),
    case(107, "sfixed32.lt", "sfixed32.lt", Sfixed32(4), Sfixed32(5)),
    case(
        108,
        "sfixed32.lte",
        "sfixed32.lte",
        Sfixed32(5),
        Sfixed32(6),
    ),
    case(109, "sfixed32.gt", "sfixed32.gt", Sfixed32(6), Sfixed32(5)),
    case(
        110,
        "sfixed32.gte",
        "sfixed32.gte",
        Sfixed32(5),
        Sfixed32(4),
    ),
    case(111, "sfixed32.in", "sfixed32.in", Sfixed32(5), Sfixed32(7)),
    case(
        112,
        "sfixed32.not_in",
        "sfixed32.not_in",
        Sfixed32(5),
        Sfixed32(7),
    ),
    case(
        113,
        "sfixed64.const",
        "sfixed64.const",
        Sfixed64(5),
        Sfixed64(6),
    ),
    case(114, "sfixed64.lt", "sfixed64.lt", Sfixed64(4), Sfixed64(5)),
    case(
        115,
        "sfixed64.lte",
        "sfixed64.lte",
        Sfixed64(5),
        Sfixed64(6),
    ),
    case(116, "sfixed64.gt", "sfixed64.gt", Sfixed64(6), Sfixed64(5)),
    case(
        117,
        "sfixed64.gte",
        "sfixed64.gte",
        Sfixed64(5),
        Sfixed64(4),
    ),
    case(118, "sfixed64.in", "sfixed64.in", Sfixed64(5), Sfixed64(7)),
    case(
        119,
        "sfixed64.not_in",
        "sfixed64.not_in",
        Sfixed64(5),
        Sfixed64(7),
    ),
    case(120, "float.const", "float.const", Float(5.0), Float(6.0)),
    case(121, "float.lt", "float.lt", Float(4.0), Float(5.0)),
    case(122, "float.lte", "float.lte", Float(5.0), Float(6.0)),
    case(123, "float.gt", "float.gt", Float(6.0), Float(5.0)),
    case(124, "float.gte", "float.gte", Float(5.0), Float(4.0)),
    case(125, "float.in", "float.in", Float(5.0), Float(7.0)),
    case(126, "float.not_in", "float.not_in", Float(5.0), Float(7.0)),
    case(
        127,
        "float.finite",
        "float.finite",
        Float(1.0),
        Float(f32::INFINITY),
    ),
    case(
        128,
        "double.const",
        "double.const",
        Double(5.0),
        Double(6.0),
    ),
    case(129, "double.lt", "double.lt", Double(4.0), Double(5.0)),
    case(130, "double.lte", "double.lte", Double(5.0), Double(6.0)),
    case(131, "double.gt", "double.gt", Double(6.0), Double(5.0)),
    case(132, "double.gte", "double.gte", Double(5.0), Double(4.0)),
    case(133, "double.in", "double.in", Double(5.0), Double(7.0)),
    case(
        134,
        "double.not_in",
        "double.not_in",
        Double(5.0),
        Double(7.0),
    ),
    case(
        135,
        "double.finite",
        "double.finite",
        Double(1.0),
        Double(f64::INFINITY),
    ),
    case(136, "bool.const", "bool.const", Bool(true), Bool(false)),
    case(137, "enum.const", "enum.const", Enum(1), Enum(2)),
    case(
        138,
        "enum.defined_only",
        "enum.defined_only",
        Enum(1),
        Enum(99),
    ),
    case(139, "enum.in", "enum.in", Enum(1), Enum(2)),
    case(140, "enum.not_in", "enum.not_in", Enum(1), Enum(2)),
    case(
        141,
        "duration.const",
        "duration.const",
        Time(1, 0),
        Time(2, 0),
    ),
    case(142, "duration.lt", "duration.lt", Time(1, 0), Time(2, 0)),
    case(143, "duration.lte", "duration.lte", Time(2, 0), Time(3, 0)),
    case(144, "duration.gt", "duration.gt", Time(3, 0), Time(2, 0)),
    case(145, "duration.gte", "duration.gte", Time(2, 0), Time(1, 0)),
    case(146, "duration.in", "duration.in", Time(1, 0), Time(2, 0)),
    case(
        147,
        "duration.not_in",
        "duration.not_in",
        Time(1, 0),
        Time(2, 0),
    ),
    case(
        148,
        "timestamp.const",
        "timestamp.const",
        Time(1, 0),
        Time(2, 0),
    ),
    case(149, "timestamp.lt", "timestamp.lt", Time(1, 0), Time(2, 0)),
    case(
        150,
        "timestamp.lte",
        "timestamp.lte",
        Time(2, 0),
        Time(3, 0),
    ),
    case(151, "timestamp.gt", "timestamp.gt", Time(3, 0), Time(2, 0)),
    case(
        152,
        "timestamp.gte",
        "timestamp.gte",
        Time(2, 0),
        Time(1, 0),
    ),
    case(
        153,
        "timestamp.lt_now",
        "timestamp.lt_now",
        Time(0, 0),
        Time(YEAR_9999, 0),
    ),
    case(
        154,
        "timestamp.gt_now",
        "timestamp.gt_now",
        Time(YEAR_9999, 0),
        Time(0, 0),
    ),
    case(
        155,
        "timestamp.within",
        "timestamp.within",
        Now(0),
        Time(0, 0),
    ),
    case(156, "any.in", "any.in", Any("allowed"), Any("denied")),
    case(
        157,
        "any.not_in",
        "any.not_in",
        Any("allowed"),
        Any("denied"),
    ),
    case(
        158,
        "field_mask.const",
        "field_mask.const",
        Mask(&["a"]),
        Mask(&["b"]),
    ),
    case(
        159,
        "field_mask.in",
        "field_mask.in",
        Mask(&["a.b"]),
        Mask(&["b"]),
    ),
    case(
        160,
        "field_mask.not_in",
        "field_mask.not_in",
        Mask(&["a"]),
        Mask(&["b.c"]),
    ),
    case(
        161,
        "duration.gte",
        "duration.gte_lt",
        Time(5, 0),
        Time(10, 0),
    ),
    case(
        162,
        "duration.gte",
        "duration.gte_lt_exclusive",
        Time(11, 0),
        Time(5, 0),
    ),
    case(
        163,
        "duration.const",
        "duration.const",
        Time(5, 0),
        Time(6, 0),
    ),
    case(164, "duration.in", "duration.in", Time(5, 0), Time(6, 0)),
    case(
        165,
        "timestamp.within",
        "timestamp.within",
        Now(30),
        Now(120),
    ),
    case(166, "float.gt", "float.gt", Float(1.0), Float(f32::NAN)),
    case(167, "double.in", "double.in", Double(5.0), Double(6.0)),
    case(
        168,
        "string.well_known_regex",
        "string.well_known_regex.header_name",
        Str("header with spaces"),
        Str("bad\rheader"),
    ),
    case(169, "int32.gte", "int32.gte_lt_exclusive", Int(11), Int(5)),
    case(170, "int64.gt", "int64.gt_lte", Int(10), Int(0)),
    case(171, "uint64.const", "uint64.const", Uint(5), Uint(6)),
    case(172, "uint32.not_in", "uint32.not_in", Uint(4), Uint(5)),
    case(
        173,
        "float.finite",
        "float.finite",
        Float(2.0),
        Float(f32::INFINITY),
    ),
    case(
        174,
        "double.lt",
        "double.lt",
        Double(f64::MAX),
        Double(f64::INFINITY),
    ),
    case(
        175,
        "float.gt",
        "float.gt",
        Float(f32::MIN),
        Float(f32::NEG_INFINITY),
    ),
    case(
        176,
        "sint64.const",
        "sint64.const",
        Sint(i64::MIN),
        Sint(i64::MAX),
    ),
    case(
        177,
        "fixed64.const",
        "fixed64.const",
        Fixed64(u64::MAX),
        Fixed64(0),
    ),
    case(178, "string.len", "string.len", Str("é🌍"), Str("a")),
    case(
        179,
        "string.max_bytes",
        "string.max_bytes",
        Str("é"),
        Str("🌍"),
    ),
    case(
        180,
        "double.gte",
        "double.gte_lt_exclusive",
        Double(11.0),
        Double(f64::NAN),
    ),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Position {
    Items,
    Keys,
    Values,
    Singular,
    Presence,
    Oneof,
    Wrappers,
    WrapperItems,
    WrapperValues,
}

// ===== impl Position =====

impl Position {
    fn encode(self, case: &Case, value: Wire) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Self::Items => {
                case.good.put(case.number, &mut bytes);
                value.put(case.number, &mut bytes);
            }
            Self::Presence | Self::Oneof => value.put(case.number, &mut bytes),
            Self::Singular | Self::Wrappers => {
                let mut inner = Vec::new();
                value.put(1, &mut inner);
                put_len(case.number, &inner, &mut bytes);
            }
            Self::WrapperItems => {
                for value in [case.good, value] {
                    let mut inner = Vec::new();
                    value.put(1, &mut inner);
                    put_len(case.number, &inner, &mut bytes);
                }
            }
            Self::Keys | Self::Values | Self::WrapperValues => {
                let mut entry = Vec::new();
                if self == Self::Keys {
                    value.put(1, &mut entry);
                    Str("v").put(2, &mut entry);
                } else {
                    Str("k").put(1, &mut entry);
                    if self == Self::WrapperValues {
                        let mut wrapper = Vec::new();
                        value.put(1, &mut wrapper);
                        put_len(2, &wrapper, &mut entry);
                    } else {
                        value.put(2, &mut entry);
                    }
                }
                put_len(case.number, &entry, &mut bytes);
            }
        }
        bytes
    }

    const fn rule_prefix(self) -> &'static str {
        match self {
            Self::Items | Self::WrapperItems => "repeated.items.",
            Self::Keys => "map.keys.",
            Self::Values | Self::WrapperValues => "map.values.",
            Self::Singular | Self::Presence | Self::Oneof | Self::Wrappers => "",
        }
    }

    fn supports(self, case: &Case) -> bool {
        match self {
            Self::Keys => case.bad.is_key_type(),
            Self::Wrappers | Self::WrapperItems | Self::WrapperValues => {
                matches!(
                    case.rule.split('.').next(),
                    Some(
                        "string"
                            | "bytes"
                            | "bool"
                            | "int32"
                            | "int64"
                            | "uint32"
                            | "uint64"
                            | "float"
                            | "double"
                    )
                )
            }
            _ => true,
        }
    }
}

fn validation_results<M>(
    bytes: &[u8],
) -> Result<[Result<(), protovalidate_buffa::ValidationError>; 2], buffa::DecodeError>
where
    M: HasMessageView + Validate,
    for<'a> M::View<'a>: Validate,
{
    Ok([
        M::decode_from_slice(bytes)?.validate(),
        M::decode_view(bytes)?.validate(),
    ])
}

fn violations<M>(bytes: &[u8]) -> Result<[Vec<Violation>; 2], buffa::DecodeError>
where
    M: HasMessageView + Validate,
    for<'a> M::View<'a>: Validate,
{
    Ok(validation_results::<M>(bytes)?.map(|result| {
        result.err().map_or_else(Vec::new, |error| {
            assert!(error.compile_error.is_none(), "{error:?}");
            assert!(error.runtime_error.is_none(), "{error:?}");
            error.violations
        })
    }))
}

fn nested_input(position: u32, child: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    if position == 3 {
        let mut entry = Vec::new();
        Str("k").put(1, &mut entry);
        put_len(2, child, &mut entry);
        put_len(position, &entry, &mut bytes);
    } else {
        put_len(position, child, &mut bytes);
    }
    bytes
}

fn composed_input(number: u32, value: &'static str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut scalar = Vec::new();
    Str(value).put(1, &mut scalar);
    match number {
        1 | 6 | 8 => Str(value).put(number, &mut bytes),
        4 | 7 => put_len(number, &scalar, &mut bytes),
        2 | 3 | 5 => {
            let mut entry = Vec::new();
            if number == 2 {
                Str(value).put(1, &mut entry);
                Str("v").put(2, &mut entry);
            } else {
                Str("k").put(1, &mut entry);
                if number == 5 {
                    put_len(2, &scalar, &mut entry);
                } else {
                    Str(value).put(2, &mut entry);
                }
            }
            put_len(number, &entry, &mut bytes);
        }
        _ => unreachable!("composed fixture field"),
    }
    bytes
}

fn rule_ids(violations: &[Violation]) -> Vec<&str> {
    violations.iter().map(|v| v.rule_id.as_ref()).collect()
}

/// Each case accepts its valid value and refuses its invalid one with one
/// violation that names the field, the element, and the rule.
fn assert_cases<M>(position: Position, syntax: &str) -> Result<(), buffa::DecodeError>
where
    M: HasMessageView + Validate,
    for<'a> M::View<'a>: Validate,
{
    // Monomorphization: the assertion loop is shared by every message type.
    assert_cases_with(position, syntax, violations::<M>)
}

type ValidateWire = fn(&[u8]) -> Result<[Vec<Violation>; 2], buffa::DecodeError>;

fn assert_cases_with(
    position: Position,
    syntax: &str,
    validate: ValidateWire,
) -> Result<(), buffa::DecodeError> {
    let cases = CASES.iter().filter(|case| {
        position.supports(case) && !(syntax == "proto2" && case.rule == "enum.defined_only")
    });
    // Rules that let an invalid value through, collected so one run names all.
    let mut missed = Vec::new();
    for case in cases {
        for violations in validate(&position.encode(case, case.good))? {
            assert!(
                violations.is_empty(),
                "{position:?} {}: {violations:?}",
                case.rule
            );
        }
        for violations in validate(&position.encode(case, case.bad))? {
            let [violation] = violations.as_slice() else {
                missed.push((case.rule, violations));
                continue;
            };
            assert_eq!(violation.rule_id, case.rule_id, "{position:?}");
            assert_metadata(violation, case, position, syntax);
            assert_eq!(
                violation.for_key,
                position == Position::Keys,
                "{}",
                case.rule
            );
            let rule = violation
                .rule
                .elements
                .iter()
                .filter_map(|element| element.field_name.as_deref())
                .collect::<Vec<_>>()
                .join(".");
            assert_eq!(rule, format!("{}{}", position.rule_prefix(), case.rule));
            let fields = &violation.field.elements;
            assert_eq!(
                fields.len(),
                if position == Position::Singular { 2 } else { 1 },
                "{violation:?}"
            );
            let field = &fields[0];
            if position == Position::Singular {
                assert_eq!(fields[1].field_name.as_deref(), Some("value"));
                assert_eq!(fields[1].field_number, Some(1));
                assert!(fields[1].subscript.is_none());
            }
            assert!(!violation.message.is_empty(), "{violation:?}");
            assert_eq!(field.field_number, i32::try_from(case.number).ok());
            match position {
                Position::Items | Position::WrapperItems => {
                    assert!(
                        matches!(field.subscript, Some(Subscript::Index(1))),
                        "{field:?}"
                    );
                }
                Position::Keys => case.bad.assert_key(field.subscript.as_ref()),
                Position::Values | Position::WrapperValues => {
                    Str("k").assert_key(field.subscript.as_ref());
                }
                _ => assert!(field.subscript.is_none(), "{field:?}"),
            }
        }
    }
    assert!(
        missed.is_empty(),
        "{position:?} rules not refused: {missed:#?}"
    );
    Ok(())
}

static DESCRIPTORS: std::sync::LazyLock<FileDescriptorSet> = std::sync::LazyLock::new(|| {
    FileDescriptorSet::decode_from_slice(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/conformance.fds"
    )))
    .expect("fixture descriptors")
});

const fn field_type(kind: Type) -> FieldType {
    match kind {
        Type::TYPE_DOUBLE => FieldType::Double,
        Type::TYPE_FLOAT => FieldType::Float,
        Type::TYPE_INT64 => FieldType::Int64,
        Type::TYPE_UINT64 => FieldType::Uint64,
        Type::TYPE_INT32 => FieldType::Int32,
        Type::TYPE_FIXED64 => FieldType::Fixed64,
        Type::TYPE_FIXED32 => FieldType::Fixed32,
        Type::TYPE_BOOL => FieldType::Bool,
        Type::TYPE_STRING => FieldType::String,
        Type::TYPE_GROUP => FieldType::Group,
        Type::TYPE_MESSAGE => FieldType::Message,
        Type::TYPE_BYTES => FieldType::Bytes,
        Type::TYPE_UINT32 => FieldType::Uint32,
        Type::TYPE_ENUM => FieldType::Enum,
        Type::TYPE_SFIXED32 => FieldType::Sfixed32,
        Type::TYPE_SFIXED64 => FieldType::Sfixed64,
        Type::TYPE_SINT32 => FieldType::Sint32,
        Type::TYPE_SINT64 => FieldType::Sint64,
    }
}

fn rule_message(name: &str) -> &'static DescriptorProto {
    DESCRIPTORS
        .file
        .iter()
        .find(|f| f.package.as_deref() == Some("buf.validate"))
        .and_then(|f| {
            f.message_type
                .iter()
                .find(|m| m.name.as_deref() == Some(name))
        })
        .expect("rule descriptor")
}

fn assert_field(actual: &FieldPathElement, expected: &FieldDescriptorProto) {
    assert_eq!(actual.field_name.as_deref(), expected.name.as_deref());
    assert_eq!(actual.field_number, expected.number);
    assert_eq!(actual.field_type, expected.r#type.map(field_type));
}

fn assert_metadata(violation: &Violation, case: &Case, position: Position, syntax: &str) {
    let mut descriptor = rule_message("FieldRules");
    for element in &violation.rule.elements {
        let field = descriptor
            .field
            .iter()
            .find(|f| f.name.as_deref() == element.field_name.as_deref())
            .expect("rule path exists in vendored descriptor");
        assert_field(element, field);
        assert!(element.subscript.is_none());
        assert!(element.key_type.is_none() && element.value_type.is_none());
        if let Some(name) = &field.type_name
            && field.r#type == Some(Type::TYPE_MESSAGE)
        {
            // Only descend when another path element follows. WKT leaf types
            // live outside buf.validate and have no further rule segments.
            if name.starts_with(".buf.validate.") {
                descriptor = rule_message(name.rsplit('.').next().expect("type name"));
            }
        }
    }
    let name = match position {
        Position::Items => "Items",
        Position::Keys => "Keys",
        Position::Values => "Values",
        Position::Singular => "Singular",
        Position::Presence => "PresenceAll",
        Position::Oneof => "Oneofs",
        Position::Wrappers => "WrappersAll",
        Position::WrapperItems => "WrapperItems",
        Position::WrapperValues => "WrapperValues",
    };
    let package = format!("validation.collection_rules.{syntax}");
    let message = DESCRIPTORS
        .file
        .iter()
        .find(|f| f.package.as_deref() == Some(&package))
        .and_then(|f| {
            f.message_type
                .iter()
                .find(|m| m.name.as_deref() == Some(name))
        })
        .expect("matrix message");
    let field = message
        .field
        .iter()
        .find(|f| f.number == i32::try_from(case.number).ok())
        .expect("matrix field");
    let actual = &violation.field.elements[0];
    assert_field(actual, field);
    if matches!(
        position,
        Position::Keys | Position::Values | Position::WrapperValues
    ) {
        let entry_name = field
            .type_name
            .as_deref()
            .expect("entry")
            .rsplit('.')
            .next()
            .expect("entry name");
        let entry = message
            .nested_type
            .iter()
            .find(|m| m.name.as_deref() == Some(entry_name))
            .expect("entry descriptor");
        assert_eq!(actual.key_type, entry.field[0].r#type.map(field_type));
        assert_eq!(actual.value_type, entry.field[1].r#type.map(field_type));
    } else {
        assert!(actual.key_type.is_none() && actual.value_type.is_none());
    }
    if position == Position::Singular {
        let nested = format!("Case{}", case.number);
        let message = message
            .nested_type
            .iter()
            .find(|m| m.name.as_deref() == Some(&nested))
            .expect("singular descriptor");
        assert_field(&violation.field.elements[1], &message.field[0]);
    }
}

// https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
#[test]
fn catalogue_covers_every_vendored_value_rule() {
    use std::collections::BTreeSet;
    let covered: BTreeSet<_> = CASES.iter().map(|c| c.rule.to_owned()).collect();
    let mut expected = BTreeSet::new();
    for family in &rule_message("FieldRules").field {
        let name = family.name.as_deref().expect("family name");
        if family.oneof_index.is_none() || matches!(name, "repeated" | "map") {
            continue;
        }
        let message = rule_message(
            family
                .type_name
                .as_deref()
                .expect("rule type")
                .rsplit('.')
                .next()
                .expect("type name"),
        );
        for rule in &message.field {
            let rule = rule.name.as_deref().expect("rule name");
            // Example annotations document values; they impose no constraint.
            if rule == "example" {
                continue;
            }
            // strict modifies well_known_regex; case 168 exercises its false branch.
            if (name, rule) == ("string", "strict") {
                assert!(CASES.iter().any(|case| case.number == 168));
                continue;
            }
            expected.insert(format!("{name}.{rule}"));
        }
    }
    assert_eq!(
        covered, expected,
        "new rule fields require independent good/bad cases"
    );
}

macro_rules! collection_tests {
    ($syntax:ident) => {
        mod $syntax {
            use super::{
                Double, Position, Str, Uint, Wire, assert_cases, composed_input,
                generated::validation::collection_rules::$syntax::{
                    Composed, EvaluationParents, IgnoreEnums, IgnoredChildren, IgnoredInvalidRules,
                    IgnoredItemsSize, InvalidEncodedRules, InvalidItemRules, InvalidKeyRules,
                    InvalidUnique, InvalidValueRules, ItemCel, ItemMessages, Items, Keys, Oneofs,
                    Presence, PresenceAll, SchemaParents, Singular, UniqueNumbers, Values,
                    WrapperItems, WrapperValues, Wrappers, WrappersAll,
                },
                nested_input, put_len, rule_ids, validation_results, violations,
            };

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
            #[test]
            fn custom_rules_compose_with_standard_rules_and_presence()
            -> Result<(), buffa::DecodeError> {
                for violations in violations::<Composed>(&[])? {
                    assert!(violations.is_empty());
                }
                for field in 1..=8 {
                    for (value, expected) in [
                        ("eng", &[][..]),
                        ("en", &["string.min_len"][..]),
                        ("bad", &["this != 'bad'"][..]),
                        ("a b", &["no_space", "string.language_tag"][..]),
                        (
                            "",
                            if field <= 3 {
                                &[][..]
                            } else {
                                &["string.min_len", "string.language_tag"][..]
                            },
                        ),
                    ] {
                        for found in violations::<Composed>(&composed_input(field, value))? {
                            assert_eq!(rule_ids(&found), expected, "field {field}={value:?}");
                            for violation in found {
                                assert_eq!(violation.for_key, field == 2);
                                let path = violation
                                    .rule
                                    .elements
                                    .iter()
                                    .filter_map(|e| e.field_name.as_deref())
                                    .collect::<Vec<_>>();
                                let prefix: &[&str] = match field {
                                    1 | 4 => &["repeated", "items"],
                                    2 => &["map", "keys"],
                                    3 | 5 => &["map", "values"],
                                    _ => &[],
                                };
                                assert_eq!(&path[..prefix.len()], prefix);
                                let leaf = violation.rule.elements.last().expect("rule leaf");
                                match violation.rule_id.as_ref() {
                                    "this != 'bad'" => {
                                        assert_eq!(
                                            leaf.field_name.as_deref(),
                                            Some("cel_expression")
                                        );
                                        assert_eq!(leaf.field_number, Some(29));
                                        assert!(matches!(
                                            leaf.subscript,
                                            Some(protovalidate_buffa::Subscript::Index(0))
                                        ));
                                    }
                                    "no_space" => {
                                        assert_eq!(leaf.field_name.as_deref(), Some("cel"));
                                        assert_eq!(leaf.field_number, Some(23));
                                        assert!(matches!(
                                            leaf.subscript,
                                            Some(protovalidate_buffa::Subscript::Index(0))
                                        ));
                                    }
                                    "string.language_tag" => {
                                        assert_eq!(
                                            leaf.field_name.as_deref(),
                                            Some("[acme.v1.language_tag]")
                                        );
                                        assert_eq!(leaf.field_number, Some(500001));
                                    }
                                    "string.min_len" => assert_eq!(leaf.field_number, Some(2)),
                                    _ => panic!("unexpected violation: {violation:?}"),
                                }
                            }
                        }
                    }
                }
                Ok(())
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
            #[test]
            fn nested_errors_survive_every_message_position() -> Result<(), buffa::DecodeError> {
                let mut child = Vec::new();
                Str("bad").put(1, &mut child);
                for position in 1..=4 {
                    let input = nested_input(position, &child);
                    for result in validation_results::<SchemaParents>(&input)? {
                        let error = result.expect_err("nested schema must fail");
                        assert!(error.compile_error.is_some(), "{error:?}");
                    }
                    for result in validation_results::<EvaluationParents>(&input)? {
                        let error = result.expect_err("nested evaluation must fail");
                        assert!(error.runtime_error.is_some(), "{error:?}");
                    }
                    for found in violations::<IgnoredChildren>(&input)? {
                        assert!(found.is_empty(), "{found:?}");
                    }
                }
                for found in violations::<IgnoredItemsSize>(&[])? {
                    assert_eq!(rule_ids(&found), ["repeated.min_items"]);
                }
                for found in violations::<IgnoredItemsSize>(&nested_input(1, &child))? {
                    assert!(found.is_empty());
                }
                Ok(())
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
            #[test]
            fn invalid_nested_rule_types_report_schema_errors() -> Result<(), buffa::DecodeError> {
                for results in [
                    validation_results::<InvalidItemRules>(&[])?,
                    validation_results::<InvalidKeyRules>(&[])?,
                    validation_results::<InvalidValueRules>(&[])?,
                    validation_results::<InvalidEncodedRules>(&[])?,
                    validation_results::<InvalidUnique>(&[])?,
                ] {
                    for result in results {
                        let error = result.expect_err("invalid nested rule type");
                        assert!(error.compile_error.is_some(), "{error:?}");
                    }
                }
                let mut ignored = Vec::new();
                Str("invalid").put(1, &mut ignored);
                for result in validation_results::<IgnoredInvalidRules>(&ignored)? {
                    assert!(result.is_ok(), "{result:?}");
                }
                Ok(())
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
            #[test]
            fn float_uniqueness_uses_numeric_equality() -> Result<(), buffa::DecodeError> {
                for (values, valid) in [
                    ([1.0, 2.0], true),
                    ([1.0, 1.0], false),
                    ([0.0, -0.0], false),
                    ([f32::NAN, f32::NAN], true),
                    ([f32::INFINITY, f32::INFINITY], false),
                ] {
                    for field in [1, 2] {
                        let mut input = Vec::new();
                        for value in values {
                            if field == 1 {
                                Wire::Float(value).put(field, &mut input);
                            } else {
                                Double(f64::from(value)).put(field, &mut input);
                            }
                        }
                        for found in violations::<UniqueNumbers>(&input)? {
                            assert_eq!(found.is_empty(), valid, "{values:?}: {found:?}");
                            if !valid {
                                assert_eq!(rule_ids(&found), ["repeated.unique"]);
                            }
                        }
                    }
                }
                Ok(())
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
            #[test]
            fn enum_ignore_uses_declared_default_and_explicit_presence()
            -> Result<(), buffa::DecodeError> {
                let default = if stringify!($syntax) == "proto2" {
                    1
                } else {
                    0
                };
                for field in 1..=4 {
                    for value in [default, 2] {
                        let mut input = Vec::new();
                        if field == 2 {
                            let mut entry = Vec::new();
                            Str("key").put(1, &mut entry);
                            Wire::Enum(value).put(2, &mut entry);
                            put_len(field, &entry, &mut input);
                        } else {
                            Wire::Enum(value).put(field, &mut input);
                        }
                        for found in violations::<IgnoreEnums>(&input)? {
                            let valid = value == 2 || field <= 2;
                            assert_eq!(
                                found.is_empty(),
                                valid,
                                "field {field}, value {value}: {found:?}"
                            );
                            if !valid {
                                assert_eq!(rule_ids(&found), ["enum.const"]);
                            }
                        }
                    }
                }
                Ok(())
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
            #[test]
            fn every_rule_in_singular() -> Result<(), buffa::DecodeError> {
                assert_cases::<Singular>(Position::Singular, stringify!($syntax))
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
            #[test]
            fn every_rule_in_presence() -> Result<(), buffa::DecodeError> {
                assert_cases::<PresenceAll>(Position::Presence, stringify!($syntax))
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
            #[test]
            fn every_rule_in_oneof() -> Result<(), buffa::DecodeError> {
                assert_cases::<Oneofs>(Position::Oneof, stringify!($syntax))
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
            #[test]
            fn every_rule_in_wrappers() -> Result<(), buffa::DecodeError> {
                assert_cases::<WrappersAll>(Position::Wrappers, stringify!($syntax))
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
            #[test]
            fn every_rule_in_wrapperitems() -> Result<(), buffa::DecodeError> {
                assert_cases::<WrapperItems>(Position::WrapperItems, stringify!($syntax))
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
            #[test]
            fn every_rule_in_wrappervalues() -> Result<(), buffa::DecodeError> {
                assert_cases::<WrapperValues>(Position::WrapperValues, stringify!($syntax))
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
            #[test]
            fn standard_rules_apply_to_items() -> Result<(), buffa::DecodeError> {
                assert_cases::<Items>(Position::Items, stringify!($syntax))
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
            #[test]
            fn standard_rules_apply_to_map_keys() -> Result<(), buffa::DecodeError> {
                assert_cases::<Keys>(Position::Keys, stringify!($syntax))
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
            #[test]
            fn standard_rules_apply_to_map_values() -> Result<(), buffa::DecodeError> {
                assert_cases::<Values>(Position::Values, stringify!($syntax))
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
            #[test]
            fn item_violations_match_singular_violations() -> Result<(), buffa::DecodeError> {
                let mut bytes = Vec::new();
                Double(f64::NEG_INFINITY).put(1, &mut bytes);
                Double(f64::NEG_INFINITY).put(2, &mut bytes);
                for violations in violations::<ItemMessages>(&bytes)? {
                    let (single, items): (Vec<_>, Vec<_>) = violations
                        .iter()
                        .partition(|v| v.field.elements[0].field_number == Some(1));
                    assert_eq!(
                        rule_ids(&violations),
                        ["double.gte", "double.finite", "double.gte", "double.finite"]
                    );
                    for (single, item) in single.iter().zip(&items) {
                        assert!(!item.message.is_empty(), "{item:?}");
                        assert_eq!(item.message, single.message);
                    }
                }
                Ok(())
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
            #[test]
            fn item_cel_rules_run_with_standard_item_rules() -> Result<(), buffa::DecodeError> {
                for (value, expected) in [
                    ("a", &[][..]),
                    ("", &["string.min_len"][..]),
                    ("a b", &["ids.no_space"][..]),
                ] {
                    let mut bytes = Vec::new();
                    Str(value).put(1, &mut bytes);
                    for violations in violations::<ItemCel>(&bytes)? {
                        assert_eq!(rule_ids(&violations), expected, "{value:?}");
                    }
                }
                Ok(())
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
            #[test]
            fn explicit_presence_fields_apply_every_rule() -> Result<(), buffa::DecodeError> {
                for (values, expected) in [
                    (
                        [Wire::Int(1), Uint(5), Wire::Float(1.0), Double(2.0)],
                        &[][..],
                    ),
                    (
                        [Wire::Int(3), Uint(7), Wire::Float(1.5), Double(2.5)],
                        &["int32.in", "uint64.not_in", "float.const", "double.const"][..],
                    ),
                ] {
                    let mut bytes = Vec::new();
                    for (number, value) in (1..).zip(values) {
                        value.put(number, &mut bytes);
                    }
                    for violations in violations::<Presence>(&bytes)? {
                        assert_eq!(rule_ids(&violations), expected, "{values:?}");
                    }
                }
                Ok(())
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/114
            #[test]
            fn wrapper_values_apply_every_rule() -> Result<(), buffa::DecodeError> {
                for (values, expected) in [
                    (
                        [
                            Str("abc"),
                            Wire::Bytes(b"pq"),
                            Wire::Int(1),
                            Double(1.0),
                            Uint(5),
                        ],
                        &[][..],
                    ),
                    (
                        [
                            Str("\u{430}\u{431}"),
                            Wire::Bytes(b"q"),
                            Wire::Int(3),
                            Double(f64::NAN),
                            Uint(7),
                        ],
                        &[
                            "string.max_bytes",
                            "bytes.prefix",
                            "int32.in",
                            "double.finite",
                            "uint64.not_in",
                        ][..],
                    ),
                ] {
                    let mut bytes = Vec::new();
                    for (number, value) in (1..).zip(values) {
                        let mut wrapper = Vec::new();
                        value.put(1, &mut wrapper);
                        put_len(number, &wrapper, &mut bytes);
                    }
                    for violations in violations::<Wrappers>(&bytes)? {
                        assert_eq!(rule_ids(&violations), expected, "{values:?}");
                        assert!(violations.iter().all(|v| !v.for_key));
                    }
                }
                Ok(())
            }
        }
    };
}

collection_tests!(proto3);
collection_tests!(editions2024);

collection_tests!(proto2);
collection_tests!(editions2023);
