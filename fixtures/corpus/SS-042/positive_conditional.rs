// SS-042 positive: the check is unreachable inside a branch that returns first.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set(env: Env, admin: Address, stop: bool) {
        if stop {
            return;
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
