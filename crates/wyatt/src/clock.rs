//! Wall-clock time in milliseconds and RFC 3339 formatting, without a date crate.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's algorithm.
fn civil(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn days(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

pub fn rfc3339(ms: u64) -> String {
    let secs = ms / 1000;
    let (y, m, d) = civil((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", rem / 3600, rem % 3600 / 60, rem % 60, ms % 1000)
}

/// Parses `YYYY-MM-DDTHH:MM:SS[.mmm]Z`. Only UTC; enough for test files.
pub fn parse_rfc3339(s: &str) -> Option<u64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut dp = date.splitn(3, '-').map(str::parse::<i64>);
    let (y, mo, d) = (dp.next()?.ok()?, dp.next()?.ok()?, dp.next()?.ok()?);
    let (hms, frac) = time.split_once('.').unwrap_or((time, "0"));
    let mut tp = hms.splitn(3, ':').map(str::parse::<u64>);
    let (h, mi, se) = (tp.next()?.ok()?, tp.next()?.ok()?, tp.next()?.ok()?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let ms: u64 = format!("{frac:0<3}")[..3].parse().ok()?;
    let day = u64::try_from(days(y, mo as u32, d as u32)).ok()?;
    Some(day * 86_400_000 + (h * 3600 + mi * 60 + se) * 1000 + ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(951_782_400_123), "2000-02-29T00:00:00.123Z");
        for ms in [0, 951_782_400_123, 1_795_000_000_000, 4_102_444_800_000] {
            assert_eq!(parse_rfc3339(&rfc3339(ms)), Some(ms));
        }
        assert_eq!(parse_rfc3339("2026-11-23T03:00:00Z"), Some(1_795_402_800_000));
        assert_eq!(parse_rfc3339("2026-13-01T00:00:00Z"), None);
    }
}
