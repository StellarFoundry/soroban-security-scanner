#[path = "../lsp.rs"]
mod lsp;

use std::process::ExitCode;

use soroban_scan_core::registry::RuleRegistry;

fn main() -> ExitCode {
    match lsp::run(RuleRegistry::with_default_rules()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("soroban-scan-lsp: {error}");
            ExitCode::from(3)
        }
    }
}
