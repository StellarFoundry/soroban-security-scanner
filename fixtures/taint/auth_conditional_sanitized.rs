// Taint fixture: sanitizing only inside a branch must not silently clear taint.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, owner: Address, trusted: bool) {
        let mut subject = owner;
        if trusted {
            subject = validate_address(&env, owner);
        }
        subject.require_auth();
    }
}

fn validate_address(env: &Env, candidate: Address) -> Address {
    let _ = env;
    candidate
}
