// SS-028 negative: state is updated before the cross-contract call.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, token: Address, amount: i128) {
        env.storage().persistent().set(&Key::Balance, &amount);
        let client = TokenClient::new(&env, &token);
        client.transfer(&env.current_contract_address(), &token, &amount);
    }
}
