// SS-027 adversarial: a spaced self-authorization chain still authorizes the
// contract's own address.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn guarded(env: Env) {
        env . current_contract_address () . require_auth ();
    }
}
