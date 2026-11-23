// SS-047 must trigger: the ledger timestamp is compared with a deadline with no
// tolerance or bounded window.

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
