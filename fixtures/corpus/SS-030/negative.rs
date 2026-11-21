// SS-030 negative: the parameter is compared with stored configuration first.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn payout(env: Env, token_id: Address, to: Address, amount: i128) {
        let configured: Address = env.storage().persistent().get(&Key::Token).unwrap();
        if token_id != configured {
            panic!("unexpected token");
        }
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
