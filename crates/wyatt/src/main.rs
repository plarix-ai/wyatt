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

fn octal(s: &str) -> Result<u32, String> {
    u32::from_str_radix(s.trim_start_matches("0o"), 8).map_err(|_| format!("`{s}` is not an octal mode like 660"))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let control = cli.control.unwrap_or_else(paths::control_socket);
    let res = match cli.cmd {
        Cmd::Serve { policy, socket, control, state, socket_mode } => server::serve(server::Config {
            policy: policy.unwrap_or_else(paths::policy),
            socket: socket.unwrap_or_else(paths::agent_socket),
            control: control.unwrap_or_else(paths::control_socket),
            state_dir: state.unwrap_or_else(paths::state_dir),
            socket_mode,
        }),
        Cmd::Status { json } => cmd::ops::status(&control, json),
        Cmd::Sessions { json } => cmd::ops::sessions(&control, json),
        Cmd::Approvals { json } => cmd::ops::approvals(&control, json),
        Cmd::Approve { id } => cmd::ops::answer(&control, id, true, None),
        Cmd::Deny { id, reason } => cmd::ops::answer(&control, id, false, reason),
        Cmd::Freeze { reason } => cmd::ops::freeze(&control, reason),
        Cmd::Unfreeze => cmd::ops::unfreeze(&control),
        Cmd::Reload => cmd::ops::reload(&control),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wyatt: {e:#}");
            ExitCode::from(1)
        }
    }
}
