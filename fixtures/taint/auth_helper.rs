// Taint fixture: the auth subject reaches a helper before require_auth.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, owner: Address, amount: i128) {
        Self::authorize(env, owner);
        let _ = amount;
    }

    fn authorize(env: Env, subject: Address) {
        let _ = env;
        subject.require_auth();
    }
}
