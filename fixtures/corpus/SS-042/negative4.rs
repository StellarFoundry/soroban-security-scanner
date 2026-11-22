// SS-042 negative: a conditional check followed by a return is still reachable.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set(env: Env, admin: Address, stop: bool) {
        validate_amount(&env, 1);
        if stop {
            admin.require_auth();
            return;
        }
        env.storage().persistent().set(&admin, &1);
    }
}

fn validate_amount(env: &Env, amount: i32) -> i32 {
    let _ = env;
    amount
}
