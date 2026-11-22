// SPDX-License-Identifier: MIT
//! Category: cross-contract
//! Focus: Dispatch to one of two configured contracts based on a route key.

use soroban_sdk::{contractimpl, Address, Env};
use soroban_sdk::token::Client;

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn balance_of(env: Env, route: u32, owner: Address) -> i128 {
        let target: Address = env.storage().instance().get(&route).unwrap();
        Client::new(&env, &target).balance(&owner)
    }
}
