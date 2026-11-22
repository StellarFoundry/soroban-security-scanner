// SS-030 negative: the token address comes from storage, not the caller.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn payout(env: Env, to: Address, amount: i128) {
        let token_id: Address = env.storage().persistent().get(&Key::Token).unwrap();
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
