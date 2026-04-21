pub mod string {
    /// Canonical hyphenated UUID per RFC 4122 §3 — 36-char `8-4-4-4-12` hex form.
    #[expect(
        clippy::missing_const_for_fn,
        reason = "uuid::Uuid::try_parse is not const"
    )]
    #[must_use]
    pub fn is_uuid(s: &str) -> bool {
        s.len() == 36 && ::uuid::Uuid::try_parse(s).is_ok()
    }

    /// Trimmed UUID — same bytes without dashes (32 hex characters).
    #[must_use]
    pub fn is_tuuid(s: &str) -> bool {
        s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Canonical 26-char Crockford ULID.
    ///
    /// The `ulid` crate handles length +
    /// alphabet; protovalidate additionally rejects values above 7ZZ...ZZ
    /// (the first Crockford base32 character cannot exceed '7' since a
    /// ULID is at most 2^128 − 1).
    #[must_use]
    pub fn is_ulid(s: &str) -> bool {
        if ::ulid::Ulid::from_string(s).is_err() {
            return false;
        }
        let first = s.as_bytes()[0].to_ascii_uppercase();
        (b'0'..=b'7').contains(&first)
    }

    /// IPv4 in dotted-quad form.
    #[must_use]
    pub fn is_ipv4(s: &str) -> bool {
        s.parse::<::std::net::Ipv4Addr>().is_ok()
    }

    /// IPv6 — any valid RFC 4291 textual form. Also accepts RFC 6874 zone-id
    /// suffix `%<zone>` (any non-null characters).
    #[must_use]
    pub fn is_ipv6(s: &str) -> bool {
        let (addr, zone) = match s.split_once('%') {
            Some((a, z)) => (a, Some(z)),
            None => (s, None),
        };
        if addr.parse::<::std::net::Ipv6Addr>().is_err() {
            return false;
        }
        zone.is_none_or(|z| !z.is_empty() && !z.contains('\0'))
    }

    /// IPv4 OR IPv6.
    #[must_use]
    pub fn is_ip(s: &str) -> bool {
        // Accept IPv4 or IPv6 (including IPv6 with zone-id suffix).
        s.parse::<::std::net::IpAddr>().is_ok() || is_ipv6(s)
    }

    /// Reject prefix-length strings with a leading zero (e.g. `/04`).
    fn prefix_no_leading_zero(s: &str) -> bool {
        let Some((_, prefix)) = s.split_once('/') else {
            return true;
        };
        !(prefix.len() > 1 && prefix.starts_with('0'))
    }

    /// IPv4 with prefix length `/N` (0..=32).
    #[must_use]
    pub fn is_ipv4_with_prefixlen(s: &str) -> bool {
        prefix_no_leading_zero(s) && s.parse::<::ipnet::Ipv4Net>().is_ok()
    }

    /// IPv6 with prefix length `/N` (0..=128).
    #[must_use]
    pub fn is_ipv6_with_prefixlen(s: &str) -> bool {
        prefix_no_leading_zero(s) && s.parse::<::ipnet::Ipv6Net>().is_ok()
    }

    /// Either IPv4 or IPv6 with a prefix length.
    #[must_use]
    pub fn is_ip_with_prefixlen(s: &str) -> bool {
        prefix_no_leading_zero(s) && s.parse::<::ipnet::IpNet>().is_ok()
    }

    /// IPv4 canonical prefix — prefix length `/N` AND host bits zero.
    #[must_use]
    pub fn is_ipv4_prefix(s: &str) -> bool {
        if !prefix_no_leading_zero(s) {
            return false;
        }
        let Ok(net) = s.parse::<::ipnet::Ipv4Net>() else {
            return false;
        };
        net.network() == net.addr()
    }

    /// IPv6 canonical prefix — prefix length AND host bits zero.
    #[must_use]
    pub fn is_ipv6_prefix(s: &str) -> bool {
        if !prefix_no_leading_zero(s) {
            return false;
        }
        let Ok(net) = s.parse::<::ipnet::Ipv6Net>() else {
            return false;
        };
        net.network() == net.addr()
    }

    /// IPv4 or IPv6 canonical prefix.
    #[must_use]
    pub fn is_ip_prefix(s: &str) -> bool {
        is_ipv4_prefix(s) || is_ipv6_prefix(s)
    }

    /// RFC 1035 hostname — labels of 1..=63 LDH characters, total ≤253 chars,
    /// and the final label must not be all digits.
    #[must_use]
    pub fn is_hostname(s: &str) -> bool {
        if s.is_empty() || s.len() > 253 {
            return false;
        }
        let trimmed = s.strip_suffix('.').unwrap_or(s);
        let labels: Vec<&str> = trimmed.split('.').collect();
        if labels.is_empty() {
            return false;
        }
        for label in &labels {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return false;
            }
        }
        if let Some(last) = labels.last() {
            if last.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
        }
        true
    }

    /// Hostname plus `:port` (0..=65535).
    ///
    /// Port must be plain digits with no leading zeros (except the single "0")
    /// and no sign.
    /// Parses via [`http::uri::Authority`], then applies protovalidate's
    /// stricter checks (exact round-trip — rejects userinfo `@`, forces
    /// canonical port spelling, and requires the host to be a hostname,
    /// IPv4, or bracketed IPv6).
    #[must_use]
    pub fn is_host_and_port(s: &str) -> bool {
        fn is_valid_port(p: &str) -> bool {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
            if p.len() > 1 && p.starts_with('0') {
                return false;
            }
            p.parse::<u16>().is_ok()
        }
        let Ok(auth) = s.parse::<::http::uri::Authority>() else {
            return false;
        };
        // Reject anything `http` accepts that we don't: userinfo, unusual
        // whitespace, non-canonical port.
        if auth.as_str() != s {
            return false;
        }
        let host = auth.host();
        let Some(port) = auth.port() else {
            return false;
        };
        if !is_valid_port(port.as_str()) {
            return false;
        }
        if host.starts_with('[') {
            let Some(inner) = host.strip_prefix('[').and_then(|x| x.strip_suffix(']')) else {
                return false;
            };
            return is_ipv6(inner);
        }
        is_hostname(host) || is_ipv4(host)
    }

    /// Email — permissive RFC 5321 addr-spec. protovalidate's reference
    /// implementation allows leading/trailing and consecutive dots in the
    /// local part but rejects a trailing dot on the domain.
    #[must_use]
    pub fn is_email(s: &str) -> bool {
        if s.is_empty() || s.len() > 254 {
            return false;
        }
        let Some((local, domain)) = s.rsplit_once('@') else {
            return false;
        };
        if local.is_empty() {
            return false;
        }
        let local_ok = local.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'.' | b'_'
                        | b'-'
                        | b'+'
                        | b'%'
                        | b'!'
                        | b'#'
                        | b'$'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'/'
                        | b'='
                        | b'?'
                        | b'^'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                )
        });
        if !local_ok {
            return false;
        }
        // Domain must not have a trailing dot in email context.
        if domain.ends_with('.') {
            return false;
        }
        // Email accepts all-digit domain labels (unlike strict is_hostname).
        is_email_domain(domain)
    }

    fn is_email_domain(s: &str) -> bool {
        if s.is_empty() || s.len() > 253 {
            return false;
        }
        s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_alphanumeric())
                && label
                    .bytes()
                    .last()
                    .is_some_and(|b| b.is_ascii_alphanumeric())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    }

    /// Protobuf FQN: dot-separated identifiers (no leading digit per segment).
    #[must_use]
    pub fn is_protobuf_fqn(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }
        s.split('.').all(|seg| {
            !seg.is_empty()
                && seg
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && seg.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
    }

    /// Like `is_protobuf_fqn` but rejects leading/trailing dots and double dots.
    #[must_use]
    pub fn is_protobuf_dot_fqn(s: &str) -> bool {
        // `.foo.bar.Baz` — one leading dot, then FQN.
        let trimmed = s.strip_prefix('.').unwrap_or(s);
        if trimmed == s {
            return is_protobuf_fqn(s);
        }
        is_protobuf_fqn(trimmed)
    }

    /// address = hostname OR IP.
    #[must_use]
    pub fn is_address(s: &str) -> bool {
        is_hostname(s) || is_ip(s)
    }

    /// Well-known regex — HTTP header name.
    ///
    /// `strict=true` follows RFC 7230 token syntax (delegated to
    /// [`http::HeaderName::from_bytes`]) plus HTTP/2 pseudo-headers starting
    /// with `:` (which the `http` crate rejects); `strict=false` is looser
    /// (no CR/LF/NUL).
    #[must_use]
    pub fn is_header_name(s: &str, strict: bool) -> bool {
        if s.is_empty() {
            return false;
        }
        if strict {
            // HTTP/2 pseudo-header — not accepted by `http::HeaderName`.
            if let Some(rest) = s.strip_prefix(':') {
                return !rest.is_empty()
                    && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
            }
            ::http::HeaderName::from_bytes(s.as_bytes()).is_ok()
        } else {
            s.bytes().all(|b| !matches!(b, 0 | b'\r' | b'\n'))
        }
    }

    /// Well-known regex — HTTP header value. `strict=true` delegates to
    /// [`http::HeaderValue::from_bytes`] (visible ASCII + tab); `strict=false`
    /// is looser (no CR/LF/NUL).
    #[must_use]
    pub fn is_header_value(s: &str, strict: bool) -> bool {
        if strict {
            ::http::HeaderValue::from_bytes(s.as_bytes()).is_ok()
        } else {
            s.bytes().all(|b| !matches!(b, 0 | b'\r' | b'\n'))
        }
    }

    /// True when `path` is equal to `candidate` or is a sub-path of it
    /// (i.e. `candidate` is a prefix at a path-segment boundary).
    #[must_use]
    pub fn fieldmask_covers(candidate: &str, path: &str) -> bool {
        if path == candidate {
            return true;
        }
        if path.len() > candidate.len()
            && path.starts_with(candidate)
            && path.as_bytes()[candidate.len()] == b'.'
        {
            return true;
        }
        false
    }

    /// URI per RFC 3986 §3. Accepts absolute URIs (scheme required).
    #[must_use]
    pub fn is_uri(s: &str) -> bool {
        // fluent-uri is strict RFC 3986 and rejects IP-literal hosts with
        // RFC 6874 zone-id (`[::1%25eth0]`). Strip a syntactically-valid
        // zone-id before parsing, then re-validate it ourselves.
        let (candidate, host_ok) = prepare_for_uri_parse(s);
        if !host_ok {
            return false;
        }
        let Ok(u) = ::fluent_uri::Uri::<&str>::parse(candidate.as_ref()) else {
            return false;
        };
        if let Some(auth) = u.authority() {
            let host = auth.host();
            if !host.starts_with('[') {
                return pct_decode_valid_utf8(host);
            }
        }
        true
    }

    /// URI reference per RFC 3986 §4.1. Either a URI or a relative-ref.
    #[must_use]
    pub fn is_uri_ref(s: &str) -> bool {
        if s.is_empty() {
            return true;
        }
        let (candidate, host_ok) = prepare_for_uri_parse(s);
        if !host_ok {
            return false;
        }
        let Ok(u) = ::fluent_uri::UriRef::<&str>::parse(candidate.as_ref()) else {
            return false;
        };
        if let Some(auth) = u.authority() {
            let host = auth.host();
            if !host.starts_with('[') {
                return pct_decode_valid_utf8(host);
            }
        }
        true
    }

    /// If the input has an IP-literal host `[...]`, validate its contents
    /// against our stricter IPv6-zone-id / `IPFuture` rules (fluent-uri won't
    /// accept RFC 6874 hosts). Returns `(candidate_for_fluent, ok)`.
    /// When an IP-literal is present and valid, the returned candidate has
    /// the zone-id stripped so fluent-uri can parse the remaining URI.
    fn prepare_for_uri_parse(s: &str) -> (std::borrow::Cow<'_, str>, bool) {
        let Some(lb) = s.find('[') else {
            return (s.into(), true);
        };
        let Some(rb_rel) = s[lb..].find(']') else {
            return (s.into(), false);
        };
        let rb = lb + rb_rel;
        let inner = &s[lb + 1..rb];
        if !is_ip_literal_content(inner) {
            return (s.into(), false);
        }
        // Strip zone-id so fluent-uri sees a vanilla IPv6.
        if let Some(pos) = inner.find("%25") {
            let mut rewritten = String::with_capacity(s.len());
            rewritten.push_str(&s[..=lb]);
            rewritten.push_str(&inner[..pos]);
            rewritten.push_str(&s[rb..]);
            return (rewritten.into(), true);
        }
        (s.into(), true)
    }

    /// Validate the contents of an RFC 3986 IP-literal (between `[` and `]`).
    /// Accepts `IPFuture` `v<hex>.<reserved>` or `IPv6address` with optional
    /// RFC 6874 zone-id `%25<non-empty pct-encoded reg-name>`.
    fn is_ip_literal_content(inner: &str) -> bool {
        if let Some(rest) = inner.strip_prefix('v').or_else(|| inner.strip_prefix('V')) {
            let bs = rest.as_bytes();
            let mut j = 0;
            while bs.get(j).is_some_and(u8::is_ascii_hexdigit) {
                j += 1;
            }
            if j == 0 {
                return false;
            }
            if bs.get(j) != Some(&b'.') {
                return false;
            }
            j += 1;
            if j >= bs.len() {
                return false;
            }
            return bs[j..].iter().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(*b, b'-' | b'.' | b'_' | b'~')
                    || matches!(
                        *b,
                        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
                    )
                    || *b == b':'
            });
        }
        let (addr, zone_opt) = inner.find("%25").map_or((inner, None), |pos| {
            (&inner[..pos], Some(&inner[pos + 3..]))
        });
        if addr.parse::<::std::net::Ipv6Addr>().is_err() {
            return false;
        }
        if let Some(zone) = zone_opt {
            if zone.is_empty() {
                return false;
            }
            if !pct_decode_valid_utf8(zone) {
                return false;
            }
        }
        true
    }

    /// Check that a string is composed of unreserved chars or valid
    /// pct-encoded triplets, AND that pct-decoding yields valid UTF-8.
    /// Uses [`percent_encoding::percent_decode_str`] for the decode; only
    /// the hex-digit validation is done manually (the crate silently passes
    /// through malformed `%XY` rather than erroring).
    fn pct_decode_valid_utf8(input: &str) -> bool {
        // Reject any `%` not followed by two hex digits.
        let bytes = input.as_bytes();
        let mut idx = 0;
        while idx < bytes.len() {
            if bytes[idx] == b'%' {
                if idx + 2 >= bytes.len()
                    || !bytes[idx + 1].is_ascii_hexdigit()
                    || !bytes[idx + 2].is_ascii_hexdigit()
                {
                    return false;
                }
                idx += 3;
            } else {
                idx += 1;
            }
        }
        ::percent_encoding::percent_decode_str(input)
            .decode_utf8()
            .is_ok()
    }
}

pub mod float {
    #[must_use]
    pub const fn is_finite_f32(f: f32) -> bool {
        f.is_finite()
    }
    #[must_use]
    pub const fn is_finite_f64(f: f64) -> bool {
        f.is_finite()
    }
}
