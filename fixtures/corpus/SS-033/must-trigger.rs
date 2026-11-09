// Must-trigger recall fixture (SS-033)
// Rationale: True positive because `use soroban_sdk::*;` imports the entire SDK
// namespace via a wildcard, obscuring symbol provenance across SDK upgrades.

#![no_std]
use soroban_sdk::*;

#[contract]
pub struct GlobImportContract;

#[contractimpl]
impl GlobImportContract {
    pub fn status(_env: Env) -> Symbol {
        symbol_short!("ok")
    }
}
