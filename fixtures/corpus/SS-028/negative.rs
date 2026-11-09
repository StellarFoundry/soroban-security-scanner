#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, user: Address, token: Address, amount: i128) {
        user.require_auth();
        let key = symbol_short!("BAL");
        env.storage().persistent().set(&key, &0_i128);
        env.storage().persistent().extend_ttl(&key, 100, 1000);
        let client = TokenClient::new(&env, &token);
        client.transfer(&env.current_contract_address(), &user, &amount);
    }
}
