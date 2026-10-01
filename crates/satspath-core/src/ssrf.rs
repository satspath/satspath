//! SSRF (Server-Side Request Forgery) protection for SatsPath resolvers.
//!
//! All outbound HTTP/HTTPS requests from resolvers MUST pass through
//! [`validate_url`] before being issued. This prevents a malicious alias
//! (e.g. `attacker@127.0.0.1`) from tricking the resolver into contacting
//! internal services.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{Result, SatsPathError};

/// Domains that are always blocked regardless of IP resolution.
const BLOCKED_HOSTS: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal", // GCP metadata
    "169.254.169.254",          // AWS/GCP/Azure metadata endpoint
    "metadata.google.internal.",
];

/// Validate that a URL is safe to request (no SSRF risk).
///
/// Checks performed:
/// 1. Scheme must be HTTPS (or HTTP only if `allow_http` is true — for tests).
/// 2. Host must not be a known internal/metadata hostname.
/// 3. If the host is an IP literal, it must not be in a private/reserved range.
/// 4. Port must be standard (443 for HTTPS, 80 for HTTP) or in 1024..=65535.
pub fn validate_url(url: &str, allow_http: bool) -> Result<()> {
    let parsed = url::Url::parse(url)
        .map_err(|e| SatsPathError::ValidationError(format!("Invalid URL: {e}")))?;

    // ── Scheme ────────────────────────────────────────────────────────────
    match parsed.scheme() {
        "https" => {}
        "http" if allow_http => {}
        other => {
            return Err(SatsPathError::ValidationError(format!(
                "Blocked scheme '{other}' — only HTTPS is allowed"
            )));
        }
    }

    // ── Host ──────────────────────────────────────────────────────────────
    let host = parsed
        .host_str()
        .ok_or_else(|| SatsPathError::ValidationError("URL has no host".to_string()))?;

    let host_lower = host.to_ascii_lowercase();
    let host_clean = host_lower.strip_suffix('.').unwrap_or(&host_lower);

    // Block known internal hostnames
    if BLOCKED_HOSTS.iter().any(|blocked| {
        let blocked_clean = blocked.strip_suffix('.').unwrap_or(blocked);
        host_clean == blocked_clean || host_clean.ends_with(&format!(".{blocked_clean}"))
    }) {
        return Err(SatsPathError::ValidationError(format!(
            "Blocked host: {host} (internal/metadata endpoint)"
        )));
    }

    // If the host is an IP literal, check the range
    let ip_str = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        if is_private_or_reserved(ip) {
            return Err(SatsPathError::ValidationError(format!(
                "Blocked IP: {ip} (private/reserved range)"
            )));
        }
    }

    // ── Port ──────────────────────────────────────────────────────────────
    if let Some(port) = parsed.port() {
        // Allowlist: a public profile endpoint only needs standard web ports.
        match port {
            80 | 443 | 8080 | 8443 => {}
            _ => {
                return Err(SatsPathError::ValidationError(format!(
                    "Blocked port {port} — only 80, 443, 8080 and 8443 are allowed"
                )));
            }
        }
    }

    Ok(())
}

/// Returns `true` if the IP address is in a private, loopback, link-local,
/// or otherwise reserved range that should never be contacted by a resolver.
fn is_private_or_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // Loopback: 127.0.0.0/8
    if octets[0] == 127 {
        return true;
    }
    // Private: 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // Private: 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // Private: 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // Link-local: 169.254.0.0/16 (includes AWS/GCP metadata 169.254.169.254)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // Broadcast / unspecified
    if ip.is_broadcast() || ip.is_unspecified() {
        return true;
    }
    // Documentation ranges (RFC 5737)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return true;
    }
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }
    // Carrier-grade NAT: 100.64.0.0/10
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return true;
    }
    false
}

fn is_private_v6(ip: Ipv6Addr) -> bool {
    // Loopback: ::1
    if ip.is_loopback() {
        return true;
    }
    // Unspecified: ::
    if ip.is_unspecified() {
        return true;
    }
    let segments = ip.segments();
    // Link-local: fe80::/10
    if segments[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // Unique local: fc00::/7 (RFC 4193)
    if segments[0] & 0xfe00 == 0xfc00 {
        return true;
    }
    // IPv4-mapped: ::ffff:0:0/96 — check the embedded v4
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_private_v4(v4);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_public_allowed() {
        assert!(validate_url("https://example.com/.well-known/satspath/alice", false).is_ok());
    }

    #[test]
    fn http_blocked_by_default() {
        assert!(validate_url("http://example.com/test", false).is_err());
    }

    #[test]
    fn http_allowed_when_flagged() {
        assert!(validate_url("http://example.com/test", true).is_ok());
    }

    #[test]
    fn localhost_blocked() {
        assert!(validate_url("https://localhost/profile", false).is_err());
        assert!(validate_url("https://localhost:8080/profile", false).is_err());
    }

    #[test]
    fn loopback_ip_blocked() {
        assert!(validate_url("https://127.0.0.1/profile", false).is_err());
        assert!(validate_url("https://[::1]/profile", false).is_err());
    }

    #[test]
    fn private_ip_blocked() {
        assert!(validate_url("https://10.0.0.1/profile", false).is_err());
        assert!(validate_url("https://192.168.1.1/profile", false).is_err());
        assert!(validate_url("https://172.16.0.1/profile", false).is_err());
    }

    #[test]
    fn aws_metadata_blocked() {
        assert!(validate_url("https://169.254.169.254/latest/meta-data/", false).is_err());
        assert!(validate_url("https://metadata.google.internal/", false).is_err());
    }

    #[test]
    fn low_and_internal_service_ports_blocked() {
        assert!(validate_url("https://example.com:22/profile", false).is_err());
        assert!(validate_url("https://example.com:25/profile", false).is_err());
        // High-risk internal database / caching / search service ports
        for port in [3306, 5432, 6379, 9200, 11211, 27017] {
            assert!(
                validate_url(&format!("https://example.com:{port}/profile"), false).is_err(),
                "port {port} must be blocked"
            );
        }
    }

    #[test]
    fn allowed_ports_pass() {
        assert!(validate_url("https://example.com:443/profile", false).is_ok());
        assert!(validate_url("https://example.com:8443/profile", false).is_ok());
        assert!(validate_url("http://example.com:80/profile", true).is_ok());
        assert!(validate_url("http://example.com:8080/profile", true).is_ok());
    }

    #[test]
    fn encoded_ips_canonicalized_and_blocked() {
        // WHATWG URL parser canonicalizes these to 127.0.0.1 which is caught by loopback IP check
        assert!(validate_url("https://0x7f000001/profile", false).is_err());
        assert!(validate_url("https://2130706433/profile", false).is_err());
        assert!(validate_url("https://127.1/profile", false).is_err());
        assert!(validate_url("https://localhost./profile", false).is_err());
    }

    #[test]
    fn ftp_scheme_blocked() {
        assert!(validate_url("ftp://example.com/profile", false).is_err());
    }

    #[test]
    fn carrier_grade_nat_blocked() {
        assert!(validate_url("https://100.100.100.100/profile", false).is_err());
    }
}
