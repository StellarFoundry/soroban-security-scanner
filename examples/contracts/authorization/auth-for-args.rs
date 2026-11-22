// SPDX-License-Identifier: MIT
//! Category: authorization
//! Focus: Authorize an operation and bind approval to its exact arguments.

use soroban_sdk::{contractimpl, Address, Env, IntoVal};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn withdraw(env: Env, owner: Address, amount: i128) {
        owner.require_auth_for_args((amount,).into_val(&env));
        let balance: i128 = env.storage().persistent().get(&owner).unwrap_or(0);
        if amount > balance {
            panic!("insufficient balance");
        }
        env.storage().persistent().set(&owner, &(balance - amount));
    }
}
