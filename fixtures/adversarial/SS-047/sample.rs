// SS-047 adversarial: an alias of an alias still reaches the timestamp, and the
// comparison split across lines must still be reported.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn close(env: Env, admin: Address, deadline: u64) {
        admin.require_auth();
        let first = env.ledger().timestamp();
        let now = first;
        if now
            >= deadline
        {
            env.storage().temporary().set(&DataKey::Closed, &true);
        }
    }
}
