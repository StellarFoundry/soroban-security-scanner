// SPDX-License-Identifier: MIT
//! Category: token
//! Focus: Restrict minting to the administrator and extend the balance TTL.

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn mint(env: Env, token_id: Address, admin: Address, to: Address, amount: i128) {
        admin.require_auth();
        let configured: Address = env.storage().instance().get(&0).unwrap();
        if admin != configured {
            panic!("not the token admin");
        }
        let client = token::Client::new(&env, &token_id);
        client.mint(&to, &amount);
        env.storage().persistent().extend_ttl(&to, 100, 1000);
    }
}
