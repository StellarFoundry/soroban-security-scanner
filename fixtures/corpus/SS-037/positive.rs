// SS-037 positive: one entry point authorizes two distinct actors.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn move_funds(env: Env, from: Address, to: Address) {
        from.require_auth();
        to.require_auth();
        let _ = &env;
    }
}
