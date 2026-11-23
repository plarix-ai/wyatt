//! URL parsing for `url` arguments and address classes for egress checks.
//!
//! The parser is strict on purpose. It accepts http and https only, and it
//! rejects user info (`https://good.com@evil.com`), backslashes, control
//! characters and percent-encoded hosts, which are the usual ways to make two
//! parsers disagree about where a request goes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// Path plus query, always starting with `/`.
    pub target: String,
}

impl Url {
    pub fn parse(s: &str) -> Result<Url, String> {
        if s.chars().any(|c| c.is_control() || c.is_whitespace() || c == '\\') {
            return Err("url contains whitespace, control characters or a backslash".into());
        }
        let (scheme, rest) = s.split_once("://").ok_or("url has no scheme")?;
        let scheme = scheme.to_ascii_lowercase();
        let default_port = match scheme.as_str() {
            "http" => 80,
            "https" => 443,
            other => return Err(format!("scheme `{other}` is not allowed; use http or https")),
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.contains('@') {
            return Err("url carries user info (user@host)".into());
        }
        if authority.contains('%') {
            return Err("percent-encoding in the host is not allowed".into());
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or("unclosed IPv6 bracket")?;
            h.parse::<Ipv6Addr>().map_err(|_| format!("`{h}` is not an IPv6 address"))?;
            let port = match after {
                "" => None,
                p => Some(p.strip_prefix(':').ok_or("junk after IPv6 address")?),
            };
            (format!("[{}]", h.to_ascii_lowercase()), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_ascii_lowercase(), Some(p)),
                None => (authority.to_ascii_lowercase(), None),
            }
        };
        let host = host.trim_end_matches('.').to_string();
        if host.is_empty() {
            return Err("url has no host".into());
        }
        if !host.starts_with('[')
            && !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
        {
            return Err(format!("host `{host}` has characters outside [a-z0-9-._]"));
        }
        let port = match port {
            None => default_port,
            Some(p) => p.parse::<u16>().ok().filter(|p| *p != 0).ok_or(format!("bad port `{p}`"))?,
        };
        let tail = tail.split('#').next().unwrap_or("");
        let target = if tail.starts_with('/') { tail.to_string() } else { format!("/{tail}") };
        Ok(Url { scheme, host, port, target })
    }

    pub fn default_port(&self) -> bool {
        matches!((self.scheme.as_str(), self.port), ("http", 80) | ("https", 443))
    }

    /// Host without IPv6 brackets, as a resolver expects it.
    pub fn bare_host(&self) -> &str {
        self.host.trim_start_matches('[').trim_end_matches(']')
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}", self.scheme, self.host)?;
        if !self.default_port() {
            write!(f, ":{}", self.port)?;
        }
        f.write_str(&self.target)
    }
}

/// False for loopback, private, link-local (cloud metadata lives at
/// 169.254.169.254), CGNAT, multicast, documentation and other special ranges.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            let s = v6.segments();
            if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
                // NAT64 well-known prefix: judge the embedded IPv4 address.
                let o = v6.octets();
                return is_public_v4(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
            }
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || s[0] == 0x2002 // 6to4 can wrap private IPv4
                || (s[0] == 0x2001 && s[1] == 0)) // Teredo
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..128).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..32).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalises() {
        let u = Url::parse("HTTPS://API.Example.com./v1/x?q=1#frag").unwrap();
        assert_eq!(u.host, "api.example.com");
        assert_eq!(u.port, 443);
        assert_eq!(u.to_string(), "https://api.example.com/v1/x?q=1");
        let u = Url::parse("http://[::1]:8080").unwrap();
        assert_eq!((u.bare_host(), u.port, u.target.as_str()), ("::1", 8080, "/"));
    }

    #[test]
    fn rejects_parser_confusion() {
        for bad in [
            "https://good.com@evil.com/",
            "file:///etc/passwd",
            "gopher://x",
            "http://ev%69l.com",
            "http://a.com\\@b.com",
            "http://exa mple.com",
            "http://host:0/",
            "http://host:99999/",
            "//no-scheme",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn classifies_addresses() {
        for private in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a9fe:a9fe",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
        for public in ["1.1.1.1", "8.8.8.8", "2606:4700::1111", "172.32.0.1"] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
    }
}
