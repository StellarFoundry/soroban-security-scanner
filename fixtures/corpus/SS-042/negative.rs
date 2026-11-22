// SS-042 negative: the check runs before the early return.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set(env: Env, admin: Address, stop: bool) {
        admin.require_auth();
        if stop {
            return;
        }
        env.storage().persistent().set(&admin, &1);
    }
}
