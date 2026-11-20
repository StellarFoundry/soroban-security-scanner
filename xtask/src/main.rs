//! Repository automation entry point.
//!
//! Run through the Cargo alias:
//!
//! ```text
//! cargo xtask --help
//! ```

mod backlog;
mod cli;
mod docs;
mod fixtures;
mod rule;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

use cli::{Cli, Command};

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Docs(args) => {
            let root = args.root.unwrap_or_else(workspace_root);
            let count = docs::check(&root)?;
            println!("OK: checked {count} Markdown files, no broken relative links.");
        }
        Command::Fixtures(args) => {
            let root = args.root.unwrap_or_else(workspace_root);
            let directory = fixtures::scaffold(&root, &args.name, args.force)?;
            println!("Scaffolded fixture at {}", directory.display());
        }
        Command::Backlog(args) => {
            let root = args.root.unwrap_or_else(workspace_root);
            if args.check {
                let issues = backlog::load(&root)?;
                println!("OK: parsed {} backlog issues.", issues.len());
            } else {
                let output = args
                    .output
                    .unwrap_or_else(|| backlog::default_output(&root));
                let count = backlog::write_all(&root, &output)?;
                println!("Wrote {count} issue bodies to {}", output.display());
            }
        }
        Command::Rule(args) => {
            let root = args.root.unwrap_or_else(workspace_root);
            let module = rule::scaffold(&root, &args.id, &args.title)?;
            println!("Scaffolded {} at {}", args.id, module.display());
        }
    }
    Ok(())
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}
