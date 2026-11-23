// SS-047 negative: a variable named `window` documents the intended tolerance.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn close(env: Env, admin: Address, deadline: u64, window: u64) {
        admin.require_auth();
        let now = env.ledger().timestamp();
        if now >= deadline - window {
            env.storage().temporary().set(&DataKey::Closed, &true);
        }
    }
}
