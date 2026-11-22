// SPDX-License-Identifier: MIT
//! Category: token
//! Focus: Move tokens only after the sender authorizes the transfer.

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn pay(env: Env, token_id: Address, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let client = token::Client::new(&env, &token_id);
        client.transfer(&from, &to, &amount);
    }
}
