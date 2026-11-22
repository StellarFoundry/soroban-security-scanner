// SPDX-License-Identifier: MIT
//! Category: authorization
//! Focus: Move authorization into an intra-file helper without dropping it.

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer_admin(env: Env, new_admin: Address) {
        Self::authorize_admin(&env);
        env.storage().instance().set(&0, &new_admin);
    }

    fn authorize_admin(env: &Env) {
        let admin: Address = env.storage().instance().get(&0).unwrap();
        admin.require_auth();
    }
}
