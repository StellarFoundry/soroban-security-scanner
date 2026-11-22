// SPDX-License-Identifier: MIT
//! Category: token
//! Focus: Burn from the holder's own balance after their authorization.

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn burn(env: Env, token_id: Address, holder: Address, amount: i128) {
        holder.require_auth();
        let client = token::Client::new(&env, &token_id);
        client.burn(&holder, &amount);
    }
}
