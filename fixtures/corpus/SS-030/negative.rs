#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, token, Address, Env};

#[contract]
pub struct LendingPool;

#[contractimpl]
impl LendingPool {
    pub fn deposit(env: Env, depositor: Address, asset: Address, amount: i128) {
        depositor.require_auth();
        let accepted: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("ASSET"))
            .unwrap();
        if asset != accepted || amount <= 0 {
            return;
        }
        let key = symbol_short!("DEP");
        env.storage().persistent().set(&key, &amount);
        env.storage().persistent().extend_ttl(&key, 100, 1000);
        let client = token::Client::new(&env, &asset);
        client.transfer(&depositor, &env.current_contract_address(), &amount);
    }
}
