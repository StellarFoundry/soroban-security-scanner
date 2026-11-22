// SPDX-License-Identifier: MIT
//! Category: token
//! Focus: Spend a pre-approved allowance through transfer_from.

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn pull(env: Env, token_id: Address, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        let client = token::Client::new(&env, &token_id);
        client.transfer_from(&spender, &from, &to, &amount);
    }
}
