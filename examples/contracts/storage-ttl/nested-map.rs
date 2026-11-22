// SPDX-License-Identifier: MIT
//! Category: storage-ttl
//! Focus: Key persistent balances by address in a bounded map.

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn credit(env: Env, owner: Address, amount: i128) {
        owner.require_auth();
        let balance: i128 = env.storage().persistent().get(&owner).unwrap_or(0);
        env.storage().persistent().set(&owner, &(balance + amount));
        env.storage().persistent().extend_ttl(&owner, 100, 1000);
    }
}
