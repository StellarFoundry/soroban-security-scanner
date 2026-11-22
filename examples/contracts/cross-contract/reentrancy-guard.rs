// SPDX-License-Identifier: MIT
//! Category: cross-contract
//! Focus: Set a reentrancy lock before making an external call.

use soroban_sdk::{contractimpl, Address, Env};
use soroban_sdk::token::Client;

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn withdraw(env: Env, token_id: Address, to: Address, amount: i128) {
        let locked: bool = env.storage().instance().get(&7).unwrap_or(false);
        if locked {
            panic!("reentrant");
        }
        env.storage().instance().set(&7, &true);
        Client::new(&env, &token_id).transfer(&env.current_contract_address(), &to, &amount);
        env.storage().instance().set(&7, &false);
    }
}
