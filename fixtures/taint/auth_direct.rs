// Taint fixture: a caller-controlled address is authorized directly.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, owner: Address, amount: i128) {
        owner.require_auth();
        env.storage().persistent().set(&owner, &amount);
    }
}
