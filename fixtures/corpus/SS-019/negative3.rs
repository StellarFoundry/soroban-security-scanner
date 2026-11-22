// SS-019 negative: the result is returned as the tail expression.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn probe(env: Env, from: Address, who: Address) -> i128 {
        from.require_auth();
        let token: Address = env
            .storage()
            .persistent()
            .get(&Key::Token)
            .unwrap_or(env.current_contract_address());
        let client = token::Client::new(&env, &token);
        client.balance(&who)
    }
}
