mod audit;
mod clock;
mod drivers;
mod paths;
mod peer;
mod proto;
mod server;

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
}

fn octal(s: &str) -> Result<u32, String> {
    u32::from_str_radix(s.trim_start_matches("0o"), 8).map_err(|_| format!("`{s}` is not an octal mode like 660"))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let res = match cli.cmd {
        Cmd::Serve { policy, socket, control, state, socket_mode } => server::serve(server::Config {
            policy: policy.unwrap_or_else(paths::policy),
            socket: socket.unwrap_or_else(paths::agent_socket),
            control: control.unwrap_or_else(paths::control_socket),
            state_dir: state.unwrap_or_else(paths::state_dir),
            socket_mode,
        }),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wyatt: {e:#}");
            ExitCode::from(1)
        }
    }
}
