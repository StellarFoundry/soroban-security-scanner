use soroban_sdk::{contract, contractevent, contractimpl, contracttype, Env};

#[contract]
pub struct Vault;

#[contracttype]
pub struct Config {
    pub limit: u32,
}

#[contractevent]
pub struct Deposited {
    pub amount: u32,
}

#[contractimpl]
impl Vault {
    pub fn deposit(env: Env, amount: u32) {
        env.storage().persistent().set(&1u32, &amount);
    }
}

pub fn helper() {}
