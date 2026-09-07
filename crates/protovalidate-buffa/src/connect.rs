use std::fmt;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use buffa::{Message, MessageName};
use connectrpc::{ConnectError, ErrorDetail};

use crate::{
    ValidationError, Violation,
    error_proto::{Exposure, convert_violation},
    proto,
};

// Library policy, not a protocol limit. 4 KiB becomes at most 5464 base64
// bytes, leaving headroom for Status/Any and other metadata under the common
// 8-KiB limit: https://grpc.io/docs/guides/metadata/. Other headers/details
// still count; this cannot guarantee the whole metadata block fits.
const MAX_DETAIL_BYTES: usize = 4096;
const MAX_BASE64_BYTES: usize = MAX_DETAIL_BYTES.div_ceil(3) * 4;
// A separate allocation budget prevents tiny repeated messages from expanding
// without bound. 1 MiB accommodates the generated elements in a 4-KiB payload.
const MAX_ELEMENT_MEMORY: usize = 1024 * 1024;
const INVALID_MESSAGE: &str = "request validation failed";
const TRUNCATED_MESSAGE: &str = "request validation failed (violation details truncated)";

impl ValidationError {
    /// Converts an RPC **request** validation failure into a transport error.
    ///
    /// Requires `connect`. Violations produce `invalid_argument` with one
    /// canonical [`proto::Violations`] detail. Compilation/evaluation failures
    /// take precedence (including mixed states), producing `internal` with no
    /// details. An empty error is also `internal`.
    ///
    /// Public messages are fixed. Detail messages and all map keys are omitted;
    /// rule IDs, schema names/numbers/types, repeated indexes and `for_key` are
    /// retained. Without map selectors, paths identify schema locations but
    /// cannot identify a particular map entry. Schema names and rule IDs are
    /// assumed to be schema-authored, not populated with rejected values.
    ///
    /// Details contain a prefix of whole violations whose combined protobuf
    /// encoding is at most 4096 bytes. If the next violation cannot fit, it and
    /// all subsequent violations are omitted, and the public message indicates
    /// truncation. No detail is attached if none fit. This leaves gRPC envelope
    /// and base64 headroom, but is not a limit on the complete metadata block.
    /// Callers adding metadata/details must budget those separately.
    ///
    /// The original error is retained as `std::error::Error::source()` and is
    /// never serialized. It, and [`Self::to_proto`], may contain rejected data.
    /// Response validation is not performed by `connect_impl`; callers that
    /// validate server responses should use a generic `ConnectError::internal`
    /// with the diagnostic as its source instead of this request conversion.
    ///
    /// ```
    /// use protovalidate_buffa::ValidationError;
    /// use connectrpc::ErrorCode;
    /// let failure = ValidationError {
    ///     compile_error: Some("private diagnostic".into()),
    ///     ..Default::default()
    /// };
    /// let rpc_error = failure.into_connect_error();
    /// assert_eq!(rpc_error.code, ErrorCode::Internal);
    /// assert!(rpc_error.details.is_empty());
    /// ```
    #[must_use]
    pub fn into_connect_error(self) -> ConnectError {
        if self.compile_error.is_some()
            || self.runtime_error.is_some()
            || self.violations.is_empty()
        {
            return ConnectError::internal("validation failed").with_source(self);
        }

        let mut details = proto::Violations::default();
        for violation in &self.violations {
            // Reject large schema strings/path lists before copying. Messages
            // and keys are never copied into this public representation.
            if !fits_copy_budget(violation) {
                break;
            }
            details
                .violations
                .push(convert_violation(violation, &Exposure::Public));
            if details.encoded_len() as usize > MAX_DETAIL_BYTES {
                details.violations.pop();
                break;
            }
        }
        let message = if details.violations.len() == self.violations.len() {
            INVALID_MESSAGE
        } else {
            TRUNCATED_MESSAGE
        };
        let mut error = ConnectError::invalid_argument(message);
        if !details.violations.is_empty() {
            error = error.with_detail(ErrorDetail::from_message(
                proto::Violations::FULL_NAME,
                &details,
            ));
        }
        error.with_source(self)
    }
}

fn fits_copy_budget(violation: &Violation) -> bool {
    let Some(mut remaining) = MAX_DETAIL_BYTES.checked_sub(violation.rule_id.len()) else {
        return false;
    };
    for path in [&violation.field, &violation.rule] {
        // Each element requires at least its tag and length on the wire.
        if path.elements.len() > remaining / 2 {
            return false;
        }
        remaining -= path.elements.len() * 2;
        for element in &path.elements {
            let name_len = element.field_name.as_ref().map_or(0, |name| name.len());
            let Some(rest) = remaining.checked_sub(name_len) else {
                return false;
            };
            remaining = rest;
        }
    }
    true
}

/// A matching validation detail could not be decoded within receiver limits.
///
/// Returned by [`decode_violations`]. Its diagnostic contains no peer data.
///
/// ```
/// use protovalidate_buffa::decode_violations;
/// let detail = connectrpc::ErrorDetail {
///     type_url: "buf.validate.Violations".into(),
///     value: None,
///     debug: None,
/// };
/// let error = decode_violations(&detail).unwrap_err();
/// assert_eq!(error.to_string(), "validation detail has no value");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeViolationsError {
    reason: &'static str,
}

impl fmt::Display for DecodeViolationsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason)
    }
}

impl std::error::Error for DecodeViolationsError {}

/// Decodes a canonical validation detail from a Connect or gRPC error.
///
/// Requires `connect`. Accepts the bare protobuf name or a type URL whose last
/// segment is `buf.validate.Violations`, including `type.googleapis.com/`.
/// Returns `Ok(None)` for unrelated types; never uses the optional JSON debug
/// value. Padded and unpadded standard base64 are accepted.
///
/// Receiver limits are 4096 decoded bytes, 5464 base64 bytes (checked before
/// allocation), and 1 MiB of repeated/map element memory through buffa's decode
/// options. Its default recursion and unknown-field limits also apply. Unknown
/// protobuf fields are accepted. Peer messages and map keys are preserved;
/// decoding does not impose this library's sender redaction policy.
///
/// # Errors
///
/// Returns [`DecodeViolationsError`] for a matching detail with a missing value,
/// invalid base64/protobuf, exceeded limits, or no violations. A decoded detail
/// describes failures; it does not establish the enclosing RPC status. Callers
/// should inspect `ConnectError::code` as well.
///
/// ```
/// use protovalidate_buffa::{decode_violations, proto};
/// let message = proto::Violations {
///     violations: vec![proto::Violation {
///         rule_id: Some("string.min_len".into()),
///         ..Default::default()
///     }],
///     ..Default::default()
/// };
/// let detail = connectrpc::ErrorDetail::from_message("buf.validate.Violations", &message);
/// let decoded = decode_violations(&detail)?.unwrap();
/// assert_eq!(decoded.violations[0].rule_id.as_deref(), Some("string.min_len"));
/// # Ok::<(), protovalidate_buffa::DecodeViolationsError>(())
/// ```
pub fn decode_violations(
    detail: &ErrorDetail,
) -> Result<Option<proto::Violations>, DecodeViolationsError> {
    let name = detail.type_url.rsplit('/').next().unwrap_or_default();
    if name != proto::Violations::FULL_NAME {
        return Ok(None);
    }
    let value = detail.value.as_deref().ok_or(DecodeViolationsError {
        reason: "validation detail has no value",
    })?;
    if value.len() > MAX_BASE64_BYTES {
        return Err(DecodeViolationsError {
            reason: "validation detail exceeds size limit",
        });
    }
    let bytes = STANDARD_NO_PAD
        .decode(value)
        .or_else(|_| STANDARD.decode(value))
        .map_err(|_| DecodeViolationsError {
            reason: "validation detail has invalid base64",
        })?;
    let violations: proto::Violations = buffa::DecodeOptions::new()
        .with_max_message_size(MAX_DETAIL_BYTES)
        .with_element_memory_limit(MAX_ELEMENT_MEMORY)
        .decode_from_slice(&bytes)
        .map_err(|_| DecodeViolationsError {
            reason: "validation detail has invalid protobuf or exceeds decode limits",
        })?;
    if violations.violations.is_empty() {
        return Err(DecodeViolationsError {
            reason: "validation detail contains no violations",
        });
    }
    Ok(Some(violations))
}
