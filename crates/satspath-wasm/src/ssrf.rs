//! SSRF protection for WASM resolvers.

/// Validate that a URL is safe to request (no SSRF risk).
/// In a WASM context, we can't easily resolve DNS to check IPs before fetching,
/// but we CAN block known bad hostnames and IP literals.
pub fn validate_url(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL: {e}"))?;

    // Must be HTTPS
    if parsed.scheme() != "https" {
        return Err(format!(
            "Blocked scheme '{}' — only HTTPS is allowed",
            parsed.scheme()
        ));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?;
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
        if first_octet == 127
            || first_octet == 10
            || first_octet == 172
            || first_octet == 192
            || first_octet == 169
            || first_octet == 100
        {
            return Err(format!("Blocked IP: {host} (private/reserved range)"));
        }
    }

    // Block IPv6 loopback
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
        assert!(validate_url("https://9.9.9.9").is_ok()); // Public IP
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
        assert!(validate_url("https://169.254.169.254/latest/meta-data").is_err()); // Cloud metadata
        assert!(validate_url("https://metadata.google.internal").is_err());
        assert!(validate_url("https://192.168.1.1").is_err()); // Private IPv4
        assert!(validate_url("https://10.0.0.1").is_err());
        assert!(validate_url("https://[::1]").is_err()); // Loopback IPv6
    }
}
