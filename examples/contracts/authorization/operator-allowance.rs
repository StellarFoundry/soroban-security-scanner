// SPDX-License-Identifier: MIT
//! Category: authorization
//! Focus: Bind an operator to an allowance that the owner authorizes once.

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_operator(env: Env, owner: Address, operator: Address, limit: i128) {
        owner.require_auth();
        env.storage().persistent().set(&0, &operator);
        env.storage().persistent().set(&1, &limit);
    }

    pub fn spend(env: Env, operator: Address, amount: i128) {
        operator.require_auth();
        let limit: i128 = env.storage().persistent().get(&1).unwrap();
        if amount > limit {
            panic!("allowance exceeded");
        }
    }
}
