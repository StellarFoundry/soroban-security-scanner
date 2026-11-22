// SPDX-License-Identifier: MIT
//! Category: token
//! Focus: Allow a controlled clawback only for the configured administrator.

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn clawback(env: Env, token_id: Address, admin: Address, from: Address, amount: i128) {
        admin.require_auth();
        let expected: Address = env.storage().instance().get(&0).unwrap();
        if admin != expected {
            panic!("not allowed");
        }
        let client = token::Client::new(&env, &token_id);
        client.clawback(&from, &amount);
    }
}
