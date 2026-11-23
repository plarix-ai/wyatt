//! Rule conditions.
//!
//! A condition is a YAML map from a field to a test:
//!
//! ```yaml
//! when:
//!   args.path: { glob: "/srv/app/logs/**" }
//!   session.labels: { contains: secret }
//!   any:
//!     - args.mode: read
//!     - agent.labels: { contains: admin }
//! ```
//!
//! Keys in one map must all hold. `any`, `all` and `not` combine conditions.
//! A scalar is shorthand for `eq`, a list for `in`.
//!
//! On a list value, an operator that tests one value (glob, regex, prefix, in,
//! comparisons) holds if any element passes. `each` requires every element to
//! pass. `eq`, `ne`, `contains*`, `max_len` and `exists` look at the list as a
//! whole. A missing field fails every test except `exists: false`.

use std::borrow::Cow;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde_json::Value;

use crate::error::PolicyError;

pub trait Facts {
    fn get(&self, path: &str) -> Option<Cow<'_, Value>>;
}

#[derive(Debug, Clone)]
pub enum Cond {
    True,
    All(Vec<Cond>),
    Any(Vec<Cond>),
    Not(Box<Cond>),
    Field { path: String, ops: Vec<Op> },
}

#[derive(Debug, Clone)]
pub enum Op {
    Eq(Value),
    Ne(Value),
    In(Vec<Value>),
    NotIn(Vec<Value>),
    Glob(GlobSet, Vec<String>),
    Regex(Regex),
    Prefix(Vec<String>),
    Suffix(Vec<String>),
    Contains(Value),
    ContainsAny(Vec<Value>),
    ContainsAll(Vec<Value>),
    Lt(f64),
    Le(f64),
    Gt(f64),
    Ge(f64),
    Exists(bool),
    MaxLen(usize),
    Each(Vec<Op>),
}

impl Op {
    pub fn name(&self) -> &'static str {
        match self {
            Op::Eq(_) => "eq",
            Op::Ne(_) => "ne",
            Op::In(_) => "in",
            Op::NotIn(_) => "not_in",
            Op::Glob(..) => "glob",
            Op::Regex(_) => "regex",
            Op::Prefix(_) => "prefix",
            Op::Suffix(_) => "suffix",
            Op::Contains(_) => "contains",
            Op::ContainsAny(_) => "contains_any",
            Op::ContainsAll(_) => "contains_all",
            Op::Lt(_) => "lt",
            Op::Le(_) => "le",
            Op::Gt(_) => "gt",
            Op::Ge(_) => "ge",
            Op::Exists(_) => "exists",
            Op::MaxLen(_) => "max_len",
            Op::Each(_) => "each",
        }
    }

    /// Ops that test a single value and so apply per element on lists.
    pub fn is_scalar(&self) -> bool {
        matches!(
            self,
            Op::In(_)
                | Op::NotIn(_)
                | Op::Glob(..)
                | Op::Regex(_)
                | Op::Prefix(_)
                | Op::Suffix(_)
                | Op::Lt(_)
                | Op::Le(_)
                | Op::Gt(_)
                | Op::Ge(_)
        )
    }
}

const OPS: &[&str] = &[
    "eq",
    "ne",
    "in",
    "not_in",
    "glob",
    "regex",
    "prefix",
    "suffix",
    "contains",
    "contains_any",
    "contains_all",
    "lt",
    "le",
    "gt",
    "ge",
    "exists",
    "max_len",
    "each",
];

fn err(at: &str, msg: impl Into<String>) -> PolicyError {
    PolicyError { at: at.to_string(), msg: msg.into() }
}

pub fn compile(v: &Value, at: &str) -> Result<Cond, PolicyError> {
    let Value::Object(map) = v else {
        return Err(err(at, "a condition must be a map of field: test"));
    };
    let mut all = Vec::with_capacity(map.len());
    for (key, val) in map {
        let here = format!("{at}.{key}");
        let c = match key.as_str() {
            "all" | "any" => {
                let Value::Array(items) = val else {
                    return Err(err(&here, format!("`{key}` takes a list of conditions")));
                };
                if items.is_empty() {
                    return Err(err(&here, format!("`{key}` needs at least one condition")));
                }
                let items = items
                    .iter()
                    .enumerate()
                    .map(|(i, c)| compile(c, &format!("{here}[{i}]")))
                    .collect::<Result<Vec<_>, _>>()?;
                if key == "all" { Cond::All(items) } else { Cond::Any(items) }
            }
            "not" => Cond::Not(Box::new(compile(val, &here)?)),
            field => {
                check_field(field, &here)?;
                Cond::Field { path: field.to_string(), ops: compile_ops(val, &here)? }
            }
        };
        all.push(c);
    }
    Ok(match all.len() {
        0 => Cond::True,
        1 => all.pop().unwrap(),
        _ => Cond::All(all),
    })
}

fn check_field(f: &str, at: &str) -> Result<(), PolicyError> {
    const ROOTS: &[&str] = &[
        "tool",
        "agent",
        "agent.labels",
        "session.labels",
        "session.calls",
        "session.tools",
        "time.hour",
        "time.weekday",
        "args",
    ];
    if ROOTS.contains(&f) || f.strip_prefix("args.").is_some_and(|r| !r.is_empty()) {
        return Ok(());
    }
    Err(err(
        at,
        format!(
            "unknown field `{f}`; use args.<name>, tool, agent, agent.labels, session.labels, session.calls, session.tools, time.hour or time.weekday"
        ),
    ))
}

fn compile_ops(v: &Value, at: &str) -> Result<Vec<Op>, PolicyError> {
    match v {
        Value::Object(m) => {
            if m.is_empty() {
                return Err(err(at, "empty test"));
            }
            m.iter().map(|(k, v)| compile_op(k, v, &format!("{at}.{k}"))).collect()
        }
        Value::Array(items) => Ok(vec![Op::In(items.clone())]),
        scalar => Ok(vec![Op::Eq(scalar.clone())]),
    }
}

fn strings(v: &Value, at: &str) -> Result<Vec<String>, PolicyError> {
    match v {
        Value::String(s) => Ok(vec![s.clone()]),
        Value::Array(items) => {
            items.iter().map(|i| i.as_str().map(str::to_string).ok_or_else(|| err(at, "expected strings"))).collect()
        }
        _ => Err(err(at, "expected a string or a list of strings")),
    }
}

fn list(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(items) => items.clone(),
        other => vec![other.clone()],
    }
}

fn number(v: &Value, at: &str) -> Result<f64, PolicyError> {
    v.as_f64().ok_or_else(|| err(at, "expected a number"))
}

pub fn glob_set(patterns: &[String], separator: bool, at: &str) -> Result<GlobSet, PolicyError> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        let g = GlobBuilder::new(p)
            .literal_separator(separator)
            .backslash_escape(true)
            .build()
            .map_err(|e| err(at, format!("bad glob `{p}`: {e}")))?;
        b.add(g);
    }
    b.build().map_err(|e| err(at, e.to_string()))
}

fn compile_op(name: &str, v: &Value, at: &str) -> Result<Op, PolicyError> {
    Ok(match name {
        "eq" => Op::Eq(v.clone()),
        "ne" => Op::Ne(v.clone()),
        "in" => Op::In(list(v)),
        "not_in" => Op::NotIn(list(v)),
        "glob" => {
            let pats = strings(v, at)?;
            Op::Glob(glob_set(&pats, true, at)?, pats)
        }
        "regex" => {
            let s = v.as_str().ok_or_else(|| err(at, "regex takes one string"))?;
            Op::Regex(Regex::new(s).map_err(|e| err(at, format!("bad regex: {e}")))?)
        }
        "prefix" => Op::Prefix(strings(v, at)?),
        "suffix" => Op::Suffix(strings(v, at)?),
        "contains" => Op::Contains(v.clone()),
        "contains_any" => Op::ContainsAny(list(v)),
        "contains_all" => Op::ContainsAll(list(v)),
        "lt" => Op::Lt(number(v, at)?),
        "le" => Op::Le(number(v, at)?),
        "gt" => Op::Gt(number(v, at)?),
        "ge" => Op::Ge(number(v, at)?),
        "exists" => Op::Exists(v.as_bool().ok_or_else(|| err(at, "exists takes true or false"))?),
        "max_len" => Op::MaxLen(v.as_u64().ok_or_else(|| err(at, "max_len takes a whole number"))? as usize),
        "each" => {
            let ops = compile_ops(v, at)?;
            if ops.iter().any(|o| matches!(o, Op::Each(_) | Op::Exists(_))) {
                return Err(err(at, "each cannot hold each or exists"));
            }
            Op::Each(ops)
        }
        other => {
            return Err(err(at, format!("unknown operator `{other}`; known: {}", OPS.join(", "))));
        }
    })
}

fn same(a: &Value, b: &Value) -> bool {
    match (a.as_f64(), b.as_f64()) {
        (Some(x), Some(y)) => x == y,
        _ => a == b,
    }
}

fn scalar_match(op: &Op, v: &Value) -> bool {
    let s = v.as_str();
    match op {
        Op::In(set) => set.iter().any(|x| same(x, v)),
        Op::NotIn(set) => !set.iter().any(|x| same(x, v)),
        Op::Glob(g, _) => s.is_some_and(|s| g.is_match(s)),
        Op::Regex(r) => s.is_some_and(|s| r.is_match(s)),
        Op::Prefix(ps) => s.is_some_and(|s| ps.iter().any(|p| s.starts_with(p.as_str()))),
        Op::Suffix(ps) => s.is_some_and(|s| ps.iter().any(|p| s.ends_with(p.as_str()))),
        Op::Lt(n) => v.as_f64().is_some_and(|x| x < *n),
        Op::Le(n) => v.as_f64().is_some_and(|x| x <= *n),
        Op::Gt(n) => v.as_f64().is_some_and(|x| x > *n),
        Op::Ge(n) => v.as_f64().is_some_and(|x| x >= *n),
        _ => false,
    }
}

fn contains(hay: &Value, needle: &Value) -> bool {
    match hay {
        Value::Array(items) => items.iter().any(|i| same(i, needle)),
        Value::String(s) => needle.as_str().is_some_and(|n| s.contains(n)),
        _ => false,
    }
}

pub fn op_matches(op: &Op, v: &Value) -> bool {
    match op {
        Op::Exists(want) => *want,
        Op::Eq(x) => same(v, x),
        Op::Ne(x) => !same(v, x),
        Op::Contains(n) => contains(v, n),
        Op::ContainsAny(ns) => ns.iter().any(|n| contains(v, n)),
        Op::ContainsAll(ns) => ns.iter().all(|n| contains(v, n)),
        Op::MaxLen(n) => match v {
            Value::Array(a) => a.len() <= *n,
            Value::String(s) => s.chars().count() <= *n,
            Value::Object(o) => o.len() <= *n,
            _ => false,
        },
        Op::Each(ops) => match v {
            Value::Array(items) => items.iter().all(|i| ops.iter().all(|o| op_matches(o, i))),
            other => ops.iter().all(|o| op_matches(o, other)),
        },
        scalar => match v {
            Value::Array(items) => items.iter().any(|i| scalar_match(scalar, i)),
            other => scalar_match(scalar, other),
        },
    }
}

impl Cond {
    pub fn eval(&self, f: &dyn Facts) -> bool {
        match self {
            Cond::True => true,
            Cond::All(cs) => cs.iter().all(|c| c.eval(f)),
            Cond::Any(cs) => cs.iter().any(|c| c.eval(f)),
            Cond::Not(c) => !c.eval(f),
            Cond::Field { path, ops } => match f.get(path) {
                Some(v) => ops.iter().all(|o| op_matches(o, &v)),
                None => ops.iter().all(|o| matches!(o, Op::Exists(false))),
            },
        }
    }

    /// A short note on why the condition failed, for `wyatt eval`.
    pub fn why_not(&self, f: &dyn Facts) -> Option<String> {
        match self {
            Cond::True => None,
            Cond::All(cs) => cs.iter().find_map(|c| c.why_not(f)),
            Cond::Any(cs) => {
                if cs.iter().any(|c| c.eval(f)) {
                    None
                } else {
                    Some(format!("none of {} alternatives held", cs.len()))
                }
            }
            Cond::Not(c) => c.eval(f).then(|| "a `not` condition held".to_string()),
            Cond::Field { path, ops } => {
                let v = f.get(path);
                ops.iter().find_map(|o| {
                    let ok = match &v {
                        Some(v) => op_matches(o, v),
                        None => matches!(o, Op::Exists(false)),
                    };
                    (!ok).then(|| match &v {
                        Some(v) => format!("{path} = {} fails {}", short(v), o.name()),
                        None => format!("{path} is missing"),
                    })
                })
            }
        }
    }

    /// Every field path the condition reads, with the ops applied to it.
    pub fn fields(&self) -> Vec<(&str, &[Op])> {
        let mut out = Vec::new();
        self.walk(&mut out);
        out
    }

    fn walk<'a>(&'a self, out: &mut Vec<(&'a str, &'a [Op])>) {
        match self {
            Cond::True => {}
            Cond::All(cs) | Cond::Any(cs) => cs.iter().for_each(|c| c.walk(out)),
            Cond::Not(c) => c.walk(out),
            Cond::Field { path, ops } => out.push((path, ops)),
        }
    }

    pub fn is_true(&self) -> bool {
        matches!(self, Cond::True)
    }
}

fn short(v: &Value) -> String {
    let s = v.to_string();
    if s.chars().count() > 60 { format!("{}…", s.chars().take(60).collect::<String>()) } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    struct Map(BTreeMap<String, Value>);
    impl Facts for Map {
        fn get(&self, p: &str) -> Option<Cow<'_, Value>> {
            self.0.get(p).map(Cow::Borrowed)
        }
    }

    fn facts(v: Value) -> Map {
        Map(serde_json::from_value(v).unwrap())
    }

    fn c(v: Value) -> Cond {
        compile(&v, "when").unwrap()
    }

    #[test]
    fn shorthand_and_combinators() {
        let f = facts(json!({"args.mode": "read", "args.n": 3, "session.labels": ["secret"]}));
        assert!(c(json!({"args.mode": "read"})).eval(&f));
        assert!(c(json!({"args.mode": ["read", "list"]})).eval(&f));
        assert!(c(json!({"any": [{"args.mode": "write"}, {"args.n": {"lt": 5}}]})).eval(&f));
        assert!(!c(json!({"not": {"session.labels": {"contains": "secret"}}})).eval(&f));
        assert!(c(json!({"args.n": {"ge": 3, "le": 3.0}})).eval(&f));
    }

    #[test]
    fn globs_respect_separators() {
        let g = c(json!({"args.path": {"glob": "/srv/*.log"}}));
        assert!(g.eval(&facts(json!({"args.path": "/srv/a.log"}))));
        assert!(!g.eval(&facts(json!({"args.path": "/srv/x/a.log"}))));
        let g = c(json!({"args.path": {"glob": "/srv/**"}}));
        assert!(g.eval(&facts(json!({"args.path": "/srv/x/y/a.log"}))));
    }

    #[test]
    fn list_semantics() {
        let f = facts(json!({"args.argv": ["status", "--force"]}));
        assert!(c(json!({"args.argv": {"regex": "^--force"}})).eval(&f));
        assert!(!c(json!({"args.argv": {"each": {"regex": "^[a-z]+$"}}})).eval(&f));
        assert!(c(json!({"args.argv": {"contains": "status", "max_len": 2}})).eval(&f));
    }

    #[test]
    fn missing_fields() {
        let f = facts(json!({}));
        assert!(!c(json!({"args.x": {"ne": 1}})).eval(&f));
        assert!(c(json!({"args.x": {"exists": false}})).eval(&f));
        assert_eq!(c(json!({"args.x": 1})).why_not(&f).unwrap(), "args.x is missing");
    }

    #[test]
    fn rejects_bad_conditions() {
        for bad in [
            json!({"args.x": {"glob_": "*"}}),
            json!({"argz.x": 1}),
            json!({"args.x": {"regex": "("}}),
            json!({"any": []}),
            json!({"args.x": {"each": {"exists": true}}}),
            json!("nope"),
        ] {
            assert!(compile(&bad, "when").is_err(), "{bad}");
        }
    }
}
