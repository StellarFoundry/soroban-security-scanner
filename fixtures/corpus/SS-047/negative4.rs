// SS-047 negative: the timestamp is read but not compared with a deadline.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn stamp(env: Env, admin: Address) -> u64 {
        admin.require_auth();
        env.ledger().timestamp()
    }
}
