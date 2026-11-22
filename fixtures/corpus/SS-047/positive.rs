// SS-047 positive: an alias of the ledger timestamp is compared with no slack.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn close(env: Env, admin: Address, deadline: u64) {
        admin.require_auth();
        let now = env.ledger().timestamp();
        if now >= deadline {
            env.storage().temporary().set(&DataKey::Closed, &true);
        }
    }
}
