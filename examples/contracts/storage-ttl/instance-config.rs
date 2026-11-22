// SPDX-License-Identifier: MIT
//! Category: storage-ttl
//! Focus: Store bounded configuration in instance storage for cheap access.

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn configure(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().instance().set(&0, &admin);
        env.storage().instance().set(&1, &1_000i128);
    }
}
