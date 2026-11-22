// SPDX-License-Identifier: MIT
//! Category: events
//! Focus: Publish a structured deposit event after a successful transfer.

use soroban_sdk::{contractimpl, contractevent, token, Address, Env};

#[contractevent]
pub struct Deposit {
    #[topic]
    pub from: Address,
    pub amount: i128,
}

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn deposit(env: Env, token_id: Address, from: Address, amount: i128) {
        from.require_auth();
        token::Client::new(&env, &token_id).transfer(&from, &env.current_contract_address(), &amount);
        Deposit { from, amount }.publish(&env);
    }
}
