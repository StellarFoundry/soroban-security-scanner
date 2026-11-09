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
mod rules;

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
        Command::Rule(args) => {
            let root = args.root.unwrap_or_else(workspace_root);
            let created = rules::scaffold(
                &root,
                &rules::RuleScaffoldOptions {
                    id: args.id,
                    title: args.title,
                    module: args.module,
                    category: args.category,
                    severity: args.severity,
                    confidence: args.confidence,
                    force: args.force,
                },
            )?;
            println!(
                "Scaffolded rule module {}, docs {}, and corpus fixtures at {}",
                created.module_file.display(),
                created.doc_file.display(),
                created.corpus_dir.display()
            );
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
    }
    Ok(())
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}
