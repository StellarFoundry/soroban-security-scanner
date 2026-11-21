// SS-027 positive: the contract authorizes its own address.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn guarded(env: Env) {
        env.current_contract_address().require_auth();
    }
}
