// SS-041 negative: conditional authorization is outside any loop.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set(env: Env, admin: Address, enabled: bool) {
        if enabled {
            admin.require_auth();
        }
        env.storage().persistent().set(&admin, &1);
    }
}
