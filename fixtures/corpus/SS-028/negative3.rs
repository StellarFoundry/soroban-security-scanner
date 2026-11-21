// SS-028 negative: a private helper is not an entry point.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    fn withdraw(env: Env, token: Address, amount: i128) {
        let client = TokenClient::new(&env, &token);
        client.transfer(&env.current_contract_address(), &token, &amount);
        env.storage().persistent().set(&Key::Balance, &amount);
    }
}
