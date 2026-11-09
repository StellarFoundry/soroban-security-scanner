// Must-trigger recall fixture (SS-007)
// Rationale: True positive because `hardcoded_guardian` embeds a 56-character
// Stellar StrKey account literal directly in source code, preventing key rotation
// and coupling the contract to a single network deployment.

#![no_std]
use soroban_sdk::{contractimpl, Env};

pub struct GuardianRegistry;

#[contractimpl]
impl GuardianRegistry {
    pub fn hardcoded_guardian(env: Env) -> &'static str {
        let _ = env;
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    }
}
