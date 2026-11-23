//! Human-friendly units used in policy files: `250ms`, `10s`, `5m`, `1MiB`, `60/min`.

use std::time::Duration;

fn split(s: &str) -> (&str, &str) {
    let s = s.trim();
    let at = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (n, unit) = s.split_at(at);
    (n, unit.trim())
}

pub fn duration(s: &str) -> Result<Duration, String> {
    let (n, unit) = split(s);
    let n: u64 = n.parse().map_err(|_| format!("`{s}` is not a duration like 500ms, 10s, 5m or 1h"))?;
    let scale = match unit {
        "ms" => 1,
        "s" => 1_000,
        "m" | "min" => 60_000,
        "h" => 3_600_000,
        _ => return Err(format!("`{s}` has no valid unit (ms, s, m, h)")),
    };
    n.checked_mul(scale).map(Duration::from_millis).ok_or_else(|| format!("`{s}` is too large"))
}

pub fn size(s: &str) -> Result<usize, String> {
    let (n, unit) = split(s);
    let n: usize = n.parse().map_err(|_| format!("`{s}` is not a size like 64KiB or 1MiB"))?;
    let scale: usize = match unit {
        "B" | "" => 1,
        "KB" => 1_000,
        "KiB" => 1 << 10,
        "MB" => 1_000_000,
        "MiB" => 1 << 20,
        "GB" => 1_000_000_000,
        "GiB" => 1 << 30,
        _ => return Err(format!("`{s}` has no valid unit (B, KiB, MiB, GiB)")),
    };
    n.checked_mul(scale).ok_or_else(|| format!("`{s}` is too large"))
}

/// `60/min` -> (60, 60_000 ms).
pub fn rate(s: &str) -> Result<(u32, u64), String> {
    let (count, per) = s.split_once('/').ok_or_else(|| format!("`{s}` is not a rate like 60/min"))?;
    let count: u32 = count.trim().parse().map_err(|_| format!("`{s}`: count must be a whole number"))?;
    let window = match per.trim() {
        "s" | "sec" => 1_000,
        "m" | "min" => 60_000,
        "h" | "hour" => 3_600_000,
        "d" | "day" => 86_400_000,
        _ => return Err(format!("`{s}`: window must be s, min, hour or day")),
    };
    if count == 0 {
        return Err(format!("`{s}`: a rate of zero blocks every call; use a deny rule instead"));
    }
    Ok((count, window))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units() {
        assert_eq!(duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(size("64KiB").unwrap(), 65_536);
        assert_eq!(size("1MiB").unwrap(), 1 << 20);
        assert_eq!(rate("60/min").unwrap(), (60, 60_000));
        assert!(duration("10").is_err());
        assert!(size("1TB").is_err());
        assert!(rate("0/s").is_err());
    }
}
