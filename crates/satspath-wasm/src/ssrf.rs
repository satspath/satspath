//! Zero-dependency SSRF protection for WASM resolvers.

/// Validate that a URL is safe to request (no SSRF risk).
///
/// Enforces:
/// 1. Must start with `https://`.
/// 2. Must have a non-empty host without embedded userinfo (`@`).
/// 3. Host must not be `localhost`, metadata endpoints, or private/reserved IPv4/IPv6 literals.
pub fn validate_url(url: &str) -> Result<(), String> {
    let trimmed = url.trim();
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return Err("Invalid URL: missing scheme".to_string());
    };

    if !scheme.eq_ignore_ascii_case("https") {
        return Err(format!(
            "Blocked scheme '{}' — only HTTPS is allowed",
            scheme.to_ascii_lowercase()
        ));
    }

    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err("URL has no host".to_string());
    }
    if authority.contains('@') {
        return Err("Blocked URL: embedded credentials are not allowed".to_string());
    }

    let host = if authority.starts_with('[') {
        let Some(end_bracket) = authority.find(']') else {
            return Err("Invalid IPv6 host in URL".to_string());
        };
        &authority[..=end_bracket]
    } else {
        authority.split(':').next().unwrap_or(authority)
    };

    if host.is_empty() {
        return Err("URL has no host".to_string());
    }

    let host_lower = host.to_ascii_lowercase();
    let blocked_hosts = [
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata.google.internal",
        "169.254.169.254",
    ];

    if blocked_hosts
        .iter()
        .any(|blocked| host_lower == *blocked || host_lower.ends_with(&format!(".{blocked}")))
    {
        return Err(format!("Blocked host: {host} (internal/metadata endpoint)"));
    }

    // Block IPv4 loopback, private, link-local, carrier-grade NAT
    if let Some(first_octet) = extract_first_octet(&host_lower) {
        if matches!(
            first_octet,
            0 | 10 | 100 | 127 | 169 | 172 | 192 | 224..=255
        ) {
            return Err(format!("Blocked IP: {host} (private/reserved range)"));
        }
    }

    // Block IPv6 loopback and private/link-local ranges
    if host_lower == "[::1]"
        || host_lower.starts_with("[fe80:")
        || host_lower.starts_with("[fc00:")
        || host_lower.starts_with("[fd00:")
    {
        return Err(format!("Blocked IPv6: {host} (private/reserved range)"));
    }

    Ok(())
}

fn extract_first_octet(host: &str) -> Option<u8> {
    if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
        if let Some(first) = host.split('.').next() {
            return first.parse::<u8>().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_urls() {
        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("https://satspath.dev/profile.json").is_ok());
        assert!(validate_url("https://9.9.9.9").is_ok());
    }

    #[test]
    fn test_blocked_schemes() {
        assert!(validate_url("http://example.com").is_err());
        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_blocked_hosts() {
        assert!(validate_url("https://localhost").is_err());
        assert!(validate_url("https://127.0.0.1").is_err());
        assert!(validate_url("https://169.254.169.254/latest/meta-data").is_err());
        assert!(validate_url("https://metadata.google.internal").is_err());
        assert!(validate_url("https://192.168.1.1").is_err());
        assert!(validate_url("https://10.0.0.1").is_err());
        assert!(validate_url("https://[::1]").is_err());
    }
}
