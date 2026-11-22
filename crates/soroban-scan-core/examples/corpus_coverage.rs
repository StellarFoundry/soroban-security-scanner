//! Print corpus coverage as text or Markdown (#140).
//!
//! ```text
//! cargo run -p soroban-scan-core --example corpus_coverage -- --format markdown
//! ```

use std::path::PathBuf;

use soroban_scan_core::corpus::{coverage, render_markdown, render_terminal};
use soroban_scan_core::registry::RuleRegistry;

fn main() {
    let mut format = "terminal".to_string();
    let mut root = PathBuf::from(".");
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--format" => {
                if let Some(value) = arguments.next() {
                    format = value;
                }
            }
            "--root" => {
                if let Some(value) = arguments.next() {
                    root = PathBuf::from(value);
                }
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let registry = RuleRegistry::with_default_rules();
    let rows = coverage(&root, &registry);
    let rendered = match format.as_str() {
        "markdown" | "md" => render_markdown(&rows),
        "terminal" | "text" => render_terminal(&rows),
        other => {
            eprintln!("unknown format: {other}; use terminal or markdown");
            std::process::exit(2);
        }
    };
    print!("{rendered}");
    if rows.iter().any(|row| !row.complete()) {
        std::process::exit(1);
    }
}
