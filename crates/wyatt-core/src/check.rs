//! Static checks for `wyatt check`. These find policies that load fine but do
//! not mean what their author thinks: typos in names, conditions on arguments
//! that no tool has, allow rules that a deny always overrides, and tests on
//! lists or URLs that are easy to get wrong.

use serde::Serialize;

use crate::cond::Op;
use crate::policy::{ArgType, Args, Driver, Effect, Mode, Names, Policy, Rule, Tool};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Note,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct Diag {
    pub level: Level,
    pub at: String,
    pub msg: String,
}

struct Out(Vec<Diag>);

impl Out {
    fn push(&mut self, level: Level, at: impl Into<String>, msg: impl Into<String>) {
        self.0.push(Diag { level, at: at.into(), msg: msg.into() });
    }
}

/// True when every name `inner` can match is also matched by `outer`.
/// Conservative: a glob in `inner` only counts as covered by a wildcard.
fn covers(outer: Option<&Names>, inner: Option<&Names>) -> bool {
    match (outer, inner) {
        (None, _) => true,
        (Some(o), _) if o.is_wildcard() => true,
        (Some(_), None) => false,
        (Some(o), Some(i)) => i.literals().count() == i.patterns.len() && i.literals().all(|n| o.matches(n)),
    }
}

/// Whether a rule's tool names can reach this tool entry.
fn reaches(names: &crate::policy::Names, t: &Tool) -> bool {
    names.matches(&t.name) || t.pattern.as_ref().is_some_and(|m| names.literals().any(|l| m.is_match(l)))
}

fn targeted<'a>(p: &'a Policy, r: &Rule) -> Vec<&'a Tool> {
    p.tools.values().filter(|t| reaches(&r.tools, t)).collect()
}

pub fn lint(p: &Policy) -> Vec<Diag> {
    let mut out = Out(Vec::new());

    if p.mode == Mode::Monitor {
        out.push(Level::Warning, "mode", "monitor mode: decisions are logged but nothing is blocked");
    }
    for a in p.agents.values() {
        if !a.has_binding() {
            out.push(
                Level::Warning,
                format!("agents.{}", a.name),
                "no uid, gid, exe or token: the daemon will refuse this agent (the hook and MCP gateway do not need a binding)",
            );
        }
    }

    for (i, r) in p.rules.iter().enumerate() {
        let at = format!("rules[{i}] `{}`", r.id);
        let tools = targeted(p, r);
        for lit in r.tools.literals() {
            if p.tool(lit).is_none() {
                out.push(Level::Error, &at, format!("unknown tool `{lit}`"));
            }
        }
        if tools.is_empty() && r.tools.literals().count() == 0 {
            out.push(Level::Warning, &at, "tool pattern matches no tool");
        }
        if let Some(agents) = &r.agents {
            for lit in agents.literals() {
                if !p.agents.contains_key(lit) {
                    out.push(Level::Error, &at, format!("unknown agent `{lit}`"));
                }
            }
        }
        if r.effect == Effect::Allow && r.tools.is_wildcard() && r.agents.is_none() && r.when.is_true() {
            out.push(Level::Warning, &at, "allows every tool for every agent with no condition");
        }
        if r.effect == Effect::Approve && r.approvers.is_empty() {
            out.push(Level::Note, &at, "no approvers listed: anyone with access to the control socket can approve");
        }
        for (field, ops) in r.when.fields() {
            check_field(&mut out, &at, r, &tools, field, ops);
        }
    }

    for (i, r) in p.rules.iter().enumerate().filter(|(_, r)| r.effect != Effect::Deny) {
        let shadow = p.rules.iter().find(|d| {
            d.effect == Effect::Deny
                && d.when.is_true()
                && covers(Some(&d.tools), Some(&r.tools))
                && covers(d.agents.as_ref(), r.agents.as_ref())
        });
        if let Some(d) = shadow {
            out.push(
                Level::Warning,
                format!("rules[{i}] `{}`", r.id),
                format!("never takes effect: rule `{}` denies every call it covers", d.id),
            );
        }
    }

    for t in p.tools.values() {
        let at = format!("tools.{}", t.name);
        if !p.rules.iter().any(|r| r.effect != Effect::Deny && reaches(&r.tools, t)) {
            out.push(Level::Note, &at, "no allow or approve rule covers this tool, so every call to it is denied");
        }
        if matches!(t.args, Args::Any) {
            out.push(Level::Warning, &at, "`args: any` skips argument checks");
        }
        if t.driver == Driver::Proc && !t.sandbox.enabled {
            out.push(Level::Warning, &at, "sandbox disabled: the process can read and write anything the daemon can");
        }
        if t.driver == Driver::Http && t.hosts.iter().any(|h| h == "*") {
            out.push(Level::Note, &at, "may reach any public host");
        }
        if t.driver == Driver::Http && t.allow_private {
            out.push(
                Level::Warning,
                &at,
                "allow_private lets this tool reach loopback, private networks and cloud metadata",
            );
        }
    }

    out.0.sort_by_key(|d| std::cmp::Reverse(d.level));
    out.0
}

fn check_field(out: &mut Out, at: &str, r: &Rule, tools: &[&Tool], field: &str, ops: &[Op]) {
    let Some(rest) = field.strip_prefix("args.") else { return };
    let mut parts = rest.splitn(2, '.');
    let name = parts.next().unwrap_or_default();
    let sub = parts.next();
    if tools.is_empty() || tools.iter().any(|t| matches!(t.args, Args::Any)) {
        return;
    }
    let specs: Vec<_> = tools
        .iter()
        .filter_map(|t| match &t.args {
            Args::Schema(s) => s.get(name),
            Args::Any => None,
        })
        .collect();
    if specs.is_empty() {
        out.push(Level::Error, at, format!("`{field}`: no tool this rule targets takes an argument `{name}`"));
        return;
    }
    for spec in specs {
        match (spec.ty, sub) {
            (ArgType::Url, Some(s)) if !["host", "scheme", "port", "path"].contains(&s) => {
                out.push(Level::Error, at, format!("`{field}`: url arguments expose host, scheme, port and path"));
            }
            (ArgType::Url, None) => {
                for op in ops {
                    if let Op::Prefix(ps) = op
                        && let Some(p) = ps.iter().find(|p| p.split_once("://").is_some_and(|(_, h)| !h.contains('/')))
                    {
                        out.push(
                            Level::Warning,
                            at,
                            format!(
                                "prefix `{p}` also matches `{p}.evil.example`; end it with `/` or test `{field}.host`"
                            ),
                        );
                    }
                }
            }
            (ArgType::List, None) if r.effect != Effect::Deny => {
                if let Some(op) = ops.iter().find(|o| o.is_scalar()) {
                    out.push(
                        Level::Warning,
                        at,
                        format!("`{}` on the list `{field}` holds if any element passes; use `each` to require every element", op.name()),
                    );
                }
            }
            (ty, Some(_)) if !matches!(ty, ArgType::Url | ArgType::Object | ArgType::Any | ArgType::List) => {
                out.push(Level::Error, at, format!("`{field}`: `{name}` is a {}, it has no fields", ty.name()));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lint_src(src: &str) -> Vec<String> {
        lint(&Policy::from_yaml(src).unwrap())
            .into_iter()
            .map(|d| format!("{:?} {}: {}", d.level, d.at, d.msg))
            .collect()
    }

    fn has(ds: &[String], needle: &str) -> bool {
        ds.iter().any(|d| d.contains(needle))
    }

    #[test]
    fn finds_mistakes() {
        let ds = lint_src(
            r#"
version: 1
agents: { ops: { uid: 1 }, ghost: {} }
tools:
  read: { driver: fs.read, root: /srv }
  get: { driver: http, hosts: ["*"] }
  run: { driver: proc, command: [/usr/bin/git], sandbox: { enabled: false } }
  orphan: { driver: delegate }
rules:
  - { id: typo-tool, allow: raed }
  - { id: typo-arg, allow: read, when: { args.pth: { glob: "/srv/**" } } }
  - { id: lax-url, allow: get, when: { args.url: { prefix: "https://api.github.com" } } }
  - { id: lax-list, allow: run, when: { args.args: { regex: "^status$" } } }
  - { id: everything, allow: "*" }
  - { id: lockdown, deny: run }
  - { id: typo-agent, allow: read, agents: opz }
"#,
        );
        for want in [
            "Error rules[0] `typo-tool`: unknown tool `raed`",
            "no tool this rule targets takes an argument `pth`",
            "prefix `https://api.github.com` also matches",
            "use `each` to require every element",
            "allows every tool for every agent",
            "never takes effect: rule `lockdown`",
            "unknown agent `opz`",
            "agents.ghost: no uid",
            "tools.run: sandbox disabled",
        ] {
            assert!(has(&ds, want), "missing {want:?} in {ds:#?}");
        }
        assert!(ds[0].starts_with("Error"));
    }

    #[test]
    fn clean_policy_is_quiet() {
        let ds = lint_src(
            r#"
version: 1
agents: { ops: { uid: 1 } }
tools:
  read: { driver: fs.read, root: /srv }
  get: { driver: http, hosts: ["*.github.com"] }
rules:
  - { id: logs, allow: read, when: { args.path: { glob: "/srv/logs/**" } } }
  - { id: gh, allow: get, agents: ops, when: { args.url.host: { suffix: ".github.com" }, args.url.scheme: https } }
  - { id: keys, deny: read, when: { args.path: { glob: "**/*.key" } } }
"#,
        );
        assert!(ds.is_empty(), "{ds:#?}");
    }
}
