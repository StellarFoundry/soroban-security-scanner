// SS-027 negative: the contract address is used for identity, not auth.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn id(env: Env) -> Address {
        env.current_contract_address()
    }
}
