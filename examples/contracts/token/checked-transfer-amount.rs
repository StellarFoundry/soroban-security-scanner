// SPDX-License-Identifier: MIT
//! Category: token
//! Focus: Reject non-positive transfer amounts before calling a token.

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn pay(env: Env, token_id: Address, from: Address, to: Address, amount: i128) {
        if amount <= 0 {
            panic!("amount must be positive");
        }
        from.require_auth();
        let client = token::Client::new(&env, &token_id);
        client.transfer(&from, &to, &amount);
    }
}
