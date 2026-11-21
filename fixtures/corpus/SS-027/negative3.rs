// SS-027 negative: a private helper is not an entry point.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    fn guarded(env: Env) {
        env.current_contract_address().require_auth();
    }
}
