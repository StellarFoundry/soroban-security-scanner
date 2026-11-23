// SS-047 negative: checked arithmetic makes the comparison bounded.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn close(env: Env, admin: Address, deadline: u64) {
        admin.require_auth();
        let now = env.ledger().timestamp();
        if now.checked_add(5).unwrap() >= deadline {
            env.storage().temporary().set(&DataKey::Closed, &true);
        }
    }
}
