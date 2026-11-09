#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, token, Address, Env};

#[contract]
pub struct LendingPool;

#[contractimpl]
impl LendingPool {
    pub fn deposit_stored_token(env: Env, depositor: Address, amount: i128) {
        depositor.require_auth();
        if amount <= 0 {
            return;
        }
        let asset: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("ASSET"))
            .unwrap();
        let key = symbol_short!("DEP");
        env.storage().persistent().set(&key, &amount);
        env.storage().persistent().extend_ttl(&key, 100, 1000);
        let client = token::Client::new(&env, &asset);
        client.transfer(&depositor, &env.current_contract_address(), &amount);
    }
}
