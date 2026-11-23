// SS-047 negative: equality is not an ordered deadline comparison, so the
// detector does not guess that it needs a tolerance window.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn exactly_now(env: Env, admin: Address, deadline: u64) -> bool {
        admin.require_auth();
        env.ledger().timestamp() == deadline
    }
}
