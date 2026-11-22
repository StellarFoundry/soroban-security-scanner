// SS-042 negative: no early return, so every check is reachable.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set(env: Env, admin: Address, enabled: bool) {
        if enabled {
            admin.require_auth();
        }
        validate_amount(&env, 1);
        env.storage().persistent().set(&admin, &1);
    }
}

fn validate_amount(env: &Env, amount: i32) -> i32 {
    let _ = env;
    amount
}
