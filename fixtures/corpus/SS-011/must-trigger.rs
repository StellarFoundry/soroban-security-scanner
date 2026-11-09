// Must-trigger recall fixture (SS-011)
// Rationale: True positive because `initialize` writes initial administrator
// configuration to storage without checking whether the contract has already been
// initialized (`has`/`get`), allowing anyone to re-initialize and hijack control.

#![no_std]
use soroban_sdk::{contractimpl, Address, Env};

pub struct TokenVault;

#[contractimpl]
impl TokenVault {
    pub fn initialize(env: Env, admin: Address) {
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }
}
