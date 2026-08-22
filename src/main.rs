mod cli;
mod events;
mod interceptor;
mod isolation;
mod logger;
mod policy;
mod report;
mod tui;

use anyhow::{Context, Result};
use clap::Parser;

use crate::events::types::ShieldEvent;

fn main() -> Result<()> {
    let args = cli::Cli::parse();
    logger::init(args.verbose);

    match &args.command {
        Some(command) => command.run(),
        None => supervise(&args),
    }
}

fn supervise(args: &cli::Cli) -> Result<()> {
    if args.agent.is_empty() {
        anyhow::bail!("no agent command provided; usage: leash [OPTIONS] -- <command> [args...]");
    }

    let policy = policy::load(&args.profile)
        .with_context(|| format!("failed to load profile '{}'", args.profile))?;

    if args.dry_run {
        println!(
            "dry-run: '{}' would run under profile '{}' (nothing enforced)",
            args.agent.join(" "),
            args.profile
        );
    }

    tracing::info!(profile = %args.profile, pid = std::process::id(), "agent supervision started");

    let mut events = vec![ShieldEvent::AgentStarted {
        pid: std::process::id(),
        profile: args.profile.clone(),
    }];

    println!("leash v0.1.0 initialized");
    println!("{}", policy.summary());

    events.push(ShieldEvent::AgentStopped {
        pid: std::process::id(),
        code: 0,
    });

    if args.ci {
        report::emit_json(&events)?;
    }

    Ok(())
}
