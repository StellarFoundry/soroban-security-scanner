// SPDX-License-Identifier: MIT
//! Category: cross-contract
//! Focus: Call a configured contract through a typed client.

use soroban_sdk::{contractimpl, Address, Env};
use soroban_sdk::token::Client;

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn query(env: Env, token_id: Address, owner: Address) -> i128 {
        let configured: Address = env.storage().instance().get(&0).unwrap();
        if token_id != configured {
            panic!("unexpected token");
        }
        Client::new(&env, &token_id).balance(&owner)
    }
}
