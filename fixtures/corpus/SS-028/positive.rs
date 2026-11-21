// SS-028 positive: a cross-contract call precedes a state update with no guard.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, token: Address, amount: i128) {
        let client = TokenClient::new(&env, &token);
        client.transfer(&env.current_contract_address(), &token, &amount);
        env.storage().persistent().set(&Key::Balance, &amount);
    }
}
