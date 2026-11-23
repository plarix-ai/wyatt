mod audit;
mod client;
mod clock;
mod cmd;
mod drivers;
mod paths;
mod peer;
mod proto;
mod server;
mod term;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Runtime policy enforcement for AI agents.
///
/// Wyatt sits between an agent and its tools. It decides every call from a
/// policy file, runs the allowed ones itself (sandboxed), and keeps a signed
/// audit log of what was asked, what was decided and what happened.
#[derive(Parser)]
#[command(name = "wyatt", version, max_term_width = 100)]
struct Cli {
    /// Control socket of the daemon [env: WYATT_CONTROL]
    #[arg(long, global = true, value_name = "PATH")]
    control: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Validate and lint a policy file.
    Check {
        /// Policy file [default: $WYATT_POLICY or ./wyatt.yaml]
        policy: Option<PathBuf>,
        /// Fail on warnings too.
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        json: bool,
    },
    /// Run policy test cases from YAML files.
    Test {
        /// Test files.
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Policy to test, overriding the `policy:` key in each file.
        #[arg(short, long)]
        policy: Option<PathBuf>,
        /// Only run cases whose name contains this text.
        #[arg(long)]
        only: Option<String>,
    },
    /// Decide one call and show which rules matched and why. Exits 2 if denied.
    Eval {
        tool: String,
        /// Arguments as JSON, or @file.
        #[arg(default_value = "{}")]
        args: String,
        #[arg(short, long)]
        agent: String,
        #[arg(short, long)]
        policy: Option<PathBuf>,
        /// Labels the session already has.
        #[arg(long = "label", value_name = "LABEL")]
        labels: Vec<String>,
        /// Calls the session already made.
        #[arg(long, default_value_t = 0)]
        calls: u64,
        /// Decide as if at this time (RFC 3339, UTC).
        #[arg(long)]
        now: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Measure decision speed of the engine on one call.
    Bench {
        tool: String,
        #[arg(default_value = "{}")]
        args: String,
        #[arg(short, long)]
        agent: String,
        #[arg(short, long)]
        policy: Option<PathBuf>,
        #[arg(short, default_value_t = 200_000)]
        n: usize,
    },
    /// Make a random agent token and the hash to put in the policy.
    Token,
    /// Hook into an agent runtime that has a hook system.
    Hook {
        #[command(subcommand)]
        cmd: HookCmd,
    },
    /// Read and verify the audit log.
    Audit {
        /// State directory holding audit.jsonl [env: WYATT_STATE]
        #[arg(long, global = true)]
        state: Option<PathBuf>,
        #[command(subcommand)]
        cmd: AuditCmd,
    },
    /// Run the daemon.
    Serve {
        /// Policy file [env: WYATT_POLICY, default: ./wyatt.yaml]
        #[arg(short, long)]
        policy: Option<PathBuf>,
        /// Agent socket [env: WYATT_SOCKET]
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Control socket, owner only [env: WYATT_CONTROL]
        #[arg(long)]
        control: Option<PathBuf>,
        /// Directory for the audit log and its key [env: WYATT_STATE]
        #[arg(long)]
        state: Option<PathBuf>,
        /// Permissions of the agent socket, in octal. Peers are still checked
        /// against the policy's identity bindings.
        #[arg(long, default_value = "660", value_parser = octal)]
        socket_mode: u32,
    },
    /// Show what the running daemon is doing.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// List sessions with their labels and call counts.
    Sessions {
        #[arg(long)]
        json: bool,
    },
    /// List calls waiting for a human.
    Approvals {
        #[arg(long)]
        json: bool,
    },
    /// Let a waiting call run.
    Approve { id: u64 },
    /// Refuse a waiting call.
    Deny {
        id: u64,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Kill switch: deny every call and kill running tools until unfrozen.
    Freeze {
        #[arg(long)]
        reason: Option<String>,
    },
    /// Lift the kill switch.
    Unfreeze,
    /// Load the policy file again. A file with errors is refused and the
    /// current policy stays.
    Reload,
}

#[derive(Subcommand)]
enum HookCmd {
    /// PreToolUse and PostToolUse hook for Claude Code.
    ClaudeCode {
        /// Agent name in the policy.
        #[arg(long, default_value = "claude-code")]
        agent: String,
        /// Agent socket [env: WYATT_SOCKET]
        #[arg(long)]
        socket: Option<PathBuf>,
        /// When the policy allows a call, skip Claude Code's own prompt.
        #[arg(long)]
        auto_allow: bool,
        /// Print the settings.json block that installs this hook, then exit.
        #[arg(long)]
        print_settings: bool,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Check every hash link and signature. Exits 1 if anything was changed.
    Verify {
        /// Public key as hex or @file, if not the one next to the log.
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Print the last records, optionally following new ones.
    Tail {
        #[arg(short, default_value_t = 20)]
        n: usize,
        #[arg(short, long)]
        follow: bool,
        /// Raw JSON lines.
        #[arg(long)]
        json: bool,
    },
    /// Print one record and every record that refers to it.
    Show { seq: u64 },
}

fn json_arg(s: &str) -> anyhow::Result<serde_json::Value> {
    use anyhow::Context;
    let text = match s.strip_prefix('@') {
        Some(file) => std::fs::read_to_string(file).with_context(|| format!("reading {file}"))?,
        None => s.to_string(),
    };
    serde_json::from_str(&text).with_context(|| format!("arguments are not valid JSON: {s}"))
}

fn done(ok: bool, fail: u8) -> anyhow::Result<ExitCode> {
    Ok(if ok { ExitCode::SUCCESS } else { ExitCode::from(fail) })
}

fn octal(s: &str) -> Result<u32, String> {
    u32::from_str_radix(s.trim_start_matches("0o"), 8).map_err(|_| format!("`{s}` is not an octal mode like 660"))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let control = cli.control.unwrap_or_else(paths::control_socket);
    let ok = |r: anyhow::Result<()>| r.map(|()| ExitCode::SUCCESS);
    let res = match cli.cmd {
        Cmd::Check { policy, strict, json } => {
            cmd::policy::lint(&policy.unwrap_or_else(paths::policy), json, strict).and_then(|ok| done(ok, 1))
        }
        Cmd::Test { files, policy, only } => {
            cmd::policy::test(policy.as_deref(), &files, only.as_deref()).and_then(|ok| done(ok, 1))
        }
        Cmd::Eval { tool, args, agent, policy, labels, calls, now, json } => json_arg(&args)
            .and_then(|args| {
                cmd::policy::eval(cmd::policy::EvalArgs {
                    policy: &policy.unwrap_or_else(paths::policy),
                    agent: &agent,
                    tool: &tool,
                    args,
                    labels,
                    calls,
                    now,
                    json,
                })
            })
            .and_then(|ok| done(ok, 2)),
        Cmd::Bench { tool, args, agent, policy, n } => ok(json_arg(&args)
            .and_then(|args| cmd::policy::bench(&policy.unwrap_or_else(paths::policy), &agent, &tool, args, n.max(1)))),
        Cmd::Token => ok(cmd::policy::token()),
        Cmd::Hook { cmd: HookCmd::ClaudeCode { agent, socket, auto_allow, print_settings } } => {
            if print_settings {
                println!("{}", cmd::hook::settings());
                Ok(ExitCode::SUCCESS)
            } else {
                let socket = socket.unwrap_or_else(paths::agent_socket);
                let token = std::env::var("WYATT_TOKEN").ok().filter(|t| !t.is_empty());
                let o = cmd::hook::Opts { socket: &socket, agent: &agent, token, auto_allow };
                Ok(ExitCode::from(cmd::hook::claude_code(&o)))
            }
        }
        Cmd::Audit { state, cmd } => {
            let state = state.unwrap_or_else(paths::state_dir);
            match cmd {
                AuditCmd::Verify { key, json } => {
                    cmd::audit::verify(&state, key.as_deref(), json).and_then(|ok| done(ok, 1))
                }
                AuditCmd::Tail { n, follow, json } => ok(cmd::audit::tail(&state, n, follow, json)),
                AuditCmd::Show { seq } => ok(cmd::audit::show(&state, seq)),
            }
        }
        Cmd::Serve { policy, socket, control, state, socket_mode } => server::serve(server::Config {
            policy: policy.unwrap_or_else(paths::policy),
            socket: socket.unwrap_or_else(paths::agent_socket),
            control: control.unwrap_or_else(paths::control_socket),
            state_dir: state.unwrap_or_else(paths::state_dir),
            socket_mode,
        })
        .map(|()| ExitCode::SUCCESS),
        Cmd::Status { json } => ok(cmd::ops::status(&control, json)),
        Cmd::Sessions { json } => ok(cmd::ops::sessions(&control, json)),
        Cmd::Approvals { json } => ok(cmd::ops::approvals(&control, json)),
        Cmd::Approve { id } => ok(cmd::ops::answer(&control, id, true, None)),
        Cmd::Deny { id, reason } => ok(cmd::ops::answer(&control, id, false, reason)),
        Cmd::Freeze { reason } => ok(cmd::ops::freeze(&control, reason)),
        Cmd::Unfreeze => ok(cmd::ops::unfreeze(&control)),
        Cmd::Reload => ok(cmd::ops::reload(&control)),
    };
    match res {
        Ok(code) => code,
        Err(e) => {
            eprintln!("wyatt: {e:#}");
            ExitCode::from(1)
        }
    }
}
