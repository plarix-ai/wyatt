//! Secret detection and redaction for tool output and audit records.
//!
//! Detectors target formats with a fixed shape (provider key prefixes, PEM
//! blocks, JWTs, card numbers that pass Luhn) plus `key = value` assignments
//! whose key names a secret. Where a detector has a capture group, only the
//! group is replaced, so `password: hunter2` becomes `password: [REDACTED:...]`
//! and the model still sees which field was there.

use std::borrow::Cow;
use std::collections::BTreeMap;

use regex::Regex;
use serde_json::Value;

use crate::error::PolicyError;

#[derive(Debug, Clone)]
struct Detector {
    name: String,
    re: Regex,
    group: usize,
    luhn: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Dlp {
    detectors: Vec<Detector>,
}

pub type Findings = BTreeMap<String, usize>;

const BUILTIN: &[(&str, &str, usize)] = &[
    (
        "private_key",
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
        0,
    ),
    ("aws_access_key", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b", 0),
    ("github_token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b", 0),
    ("gitlab_token", r"\bglpat-[A-Za-z0-9_-]{20,}\b", 0),
    ("slack_token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b", 0),
    ("anthropic_key", r"\bsk-ant-[A-Za-z0-9_-]{20,}", 0),
    (
        "openai_key",
        r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}|\bsk-proj-[A-Za-z0-9_-]{40,}",
        0,
    ),
    ("stripe_key", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b", 0),
    ("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}\b", 0),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", 0),
    ("connection_string", r"\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@]+:([^\s@/]+)@", 1),
    (
        "secret_assignment",
        r#"(?i)(?:\b|_)(?:password|passwd|pwd|secret(?:[_-][a-z0-9_-]*)?|api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?key)\b["']?\s*[:=]\s*("[^"\n]{3,}"|'[^'\n]{3,}'|[^\s"',;]{3,})"#,
        1,
    ),
    ("card_number", r"\b(?:\d[ -]?){12,18}\d\b", 0),
];

pub fn builtin_names() -> Vec<&'static str> {
    BUILTIN.iter().map(|(n, _, _)| *n).collect()
}

impl Dlp {
    /// `names: None` enables every built-in detector.
    pub fn new(names: Option<&[String]>, custom: &[(String, String)]) -> Result<Dlp, PolicyError> {
        let mut detectors = Vec::new();
        let wanted = |n: &str| names.is_none_or(|ns| ns.iter().any(|x| x == n));
        if let Some(ns) = names {
            for n in ns {
                if !BUILTIN.iter().any(|(b, _, _)| b == n) {
                    return Err(PolicyError {
                        at: "redact.detectors".into(),
                        msg: format!("unknown detector `{n}`; built-in: {}", builtin_names().join(", ")),
                    });
                }
            }
        }
        for (name, re, group) in BUILTIN {
            if wanted(name) {
                detectors.push(Detector {
                    name: name.to_string(),
                    re: Regex::new(re).expect("built-in detector regex"),
                    group: *group,
                    luhn: *name == "card_number",
                });
            }
        }
        for (i, (name, re)) in custom.iter().enumerate() {
            let re = Regex::new(re)
                .map_err(|e| PolicyError { at: format!("redact.patterns[{i}]"), msg: format!("bad regex: {e}") })?;
            let group = usize::from(re.captures_len() > 1);
            detectors.push(Detector { name: name.clone(), re, group, luhn: false });
        }
        Ok(Dlp { detectors })
    }

    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }

    pub fn redact_str<'a>(&self, input: &'a str, found: &mut Findings) -> Cow<'a, str> {
        let mut text = Cow::Borrowed(input);
        for d in &self.detectors {
            let mut out = String::new();
            let mut last = 0;
            let mut hits = 0;
            for caps in d.re.captures_iter(&text) {
                let Some(m) = caps.get(d.group) else { continue };
                if d.luhn && !luhn(m.as_str()) {
                    continue;
                }
                out.push_str(&text[last..m.start()]);
                out.push_str("[REDACTED:");
                out.push_str(&d.name);
                out.push(']');
                last = m.end();
                hits += 1;
            }
            if hits > 0 {
                out.push_str(&text[last..]);
                *found.entry(d.name.clone()).or_default() += hits;
                text = Cow::Owned(out);
            }
        }
        text
    }

    /// Redacts every string inside a JSON value, keys included.
    pub fn redact_value(&self, v: &mut Value, found: &mut Findings) {
        match v {
            Value::String(s) => {
                if let Cow::Owned(r) = self.redact_str(s, found) {
                    *s = r;
                }
            }
            Value::Array(items) => items.iter_mut().for_each(|i| self.redact_value(i, found)),
            Value::Object(map) => {
                let old = std::mem::take(map);
                for (k, mut val) in old {
                    self.redact_value(&mut val, found);
                    map.insert(self.redact_str(&k, found).into_owned(), val);
                }
            }
            _ => {}
        }
    }
}

fn luhn(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) || digits.iter().all(|d| *d == digits[0]) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 { x - 9 } else { x }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Dlp {
        Dlp::new(None, &[]).unwrap()
    }

    fn red(s: &str) -> (String, Findings) {
        let mut f = Findings::new();
        let out = all().redact_str(s, &mut f).into_owned();
        (out, f)
    }

    #[test]
    fn redacts_known_formats() {
        let (out, f) = red("key AKIAIOSFODNN7EXAMPLE and ghp_abcdefghijklmnopqrstuvwxyz0123456789");
        assert_eq!(out, "key [REDACTED:aws_access_key] and [REDACTED:github_token]");
        assert_eq!(f.len(), 2);
        let (out, _) = red("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\nok");
        assert_eq!(out, "[REDACTED:private_key]\nok");
    }

    #[test]
    fn keeps_field_names() {
        let (out, _) = red("DB_PASSWORD=hunter22\npassword: \"s3cr3t value\"");
        assert_eq!(out, "DB_PASSWORD=[REDACTED:secret_assignment]\npassword: [REDACTED:secret_assignment]");
        let (out, _) =
            red("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG\naws_secret_access_key = abc123\nsecretary: Bob");
        assert_eq!(
            out,
            "AWS_SECRET_ACCESS_KEY=[REDACTED:secret_assignment]\naws_secret_access_key = [REDACTED:secret_assignment]\nsecretary: Bob"
        );
        let (out, _) = red("max_tokens: 4096");
        assert_eq!(out, "max_tokens: 4096");
        let (out, _) = red("postgres://app:pa55word@db:5432/x");
        assert_eq!(out, "postgres://app:[REDACTED:connection_string]@db:5432/x");
    }

    #[test]
    fn card_numbers_need_luhn() {
        assert_eq!(red("card 4111 1111 1111 1111").0, "card [REDACTED:card_number]");
        assert_eq!(red("order 1234 5678 9012 3456").0, "order 1234 5678 9012 3456");
        assert_eq!(red("ts 1700000000000").0, "ts 1700000000000");
    }

    #[test]
    fn walks_json() {
        let mut v = serde_json::json!({"env": ["API_KEY=abcdef123"], "n": 1});
        let mut f = Findings::new();
        all().redact_value(&mut v, &mut f);
        assert_eq!(v["env"][0], "API_KEY=[REDACTED:secret_assignment]");
        assert_eq!(f["secret_assignment"], 1);
    }

    #[test]
    fn unknown_detector_is_an_error() {
        assert!(Dlp::new(Some(&["nope".to_string()]), &[]).is_err());
    }
}
