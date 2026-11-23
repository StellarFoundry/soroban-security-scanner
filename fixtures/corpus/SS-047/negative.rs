// SS-047 negative: an explicit tolerance constant bounds the comparison.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

const TOLERANCE: u64 = 5;

#[contractimpl]
impl Contract {
    pub fn close(env: Env, admin: Address, deadline: u64) {
        admin.require_auth();
        let now = env.ledger().timestamp();
        if now + TOLERANCE >= deadline {
            env.storage().temporary().set(&DataKey::Closed, &true);
        }
    }
}
