//! Command-line packager and release tool; the composition root that wires traits to adapters.
//!
//! Exit status: 0 on success, 1 on any failure (`error: <message and causes>` on stderr), 2 on a
//! usage error (clap). No command prints private-key material, an environment variable's value or
//! a config value.

mod cmd_keys;
mod config;
mod place;
mod release_dir;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "lunepack",
    version,
    about = "Package, sign and publish app releases"
)]
struct Cli {
    /// The config file.
    #[arg(long, global = true, default_value = config::DEFAULT_CONFIG)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a config naming the app and its compiled-in root keys.
    Init(cmd_keys::InitArgs),
    /// Manage signing keys, `keys.json` and root rotation.
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
}

#[derive(Subcommand)]
enum KeysCommand {
    /// Generate a signing key file; prints its public key and id.
    Gen(cmd_keys::GenArgs),
    /// Print a signer's public key and id.
    Show(cmd_keys::ShowArgs),
    /// Write `keys.json` with the release keys, signed by the root.
    Set(cmd_keys::SetArgs),
    /// Rotate the root: write the next `root-<k>.json` and re-sign `keys.json`.
    RotateRoot(cmd_keys::RotateArgs),
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Init(args) => cmd_keys::init(&cli.config, &args),
        Command::Keys { command } => match command {
            KeysCommand::Gen(args) => cmd_keys::gen_key(&args),
            KeysCommand::Show(args) => cmd_keys::show_key(&cli.config, &args),
            KeysCommand::Set(args) => cmd_keys::set_keys(&cli.config, &args),
            KeysCommand::RotateRoot(args) => cmd_keys::rotate_root_cmd(&cli.config, &args),
        },
    }
}

fn main() -> ExitCode {
    // Usage errors and --help are handled (and exit) here; 2 is clap's status for a usage error.
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
