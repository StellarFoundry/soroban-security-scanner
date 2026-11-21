// SS-027 positive: the contract incorrectly authenticates itself as the caller.
#![no_std]
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn guarded(env: Env) {
        env.current_contract_address().require_auth();
    }
}
