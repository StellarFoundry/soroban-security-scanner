// SS-007 positive: hardcoded Stellar address literal.
// This file is a security fixture, not production code.

use soroban_sdk::{contractimpl, Env};

#[contractimpl]
impl Config {
    pub fn admin_address(env: Env) -> &'static str {
        let _ = env;
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    }
}
