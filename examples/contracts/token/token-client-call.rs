// SPDX-License-Identifier: MIT
//! Category: token
//! Focus: Query an external token's balance through a typed client.

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn reported_balance(env: Env, token_id: Address, owner: Address) -> i128 {
        let client = token::Client::new(&env, &token_id);
        client.balance(&owner)
    }
}
