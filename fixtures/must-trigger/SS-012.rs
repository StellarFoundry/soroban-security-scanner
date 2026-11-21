// SS-012 positive: unbounded collection growth after a storage read.

#![no_std]

use soroban_sdk::{contractimpl, Env, Vec};

pub struct Registry;

#[contractimpl]
impl Registry {
    pub fn add(env: Env, item: u32) {
        let mut items: Vec<u32> = env
            .storage()
            .persistent()
            .get(&DataKey::Items)
            .unwrap_or(Vec::new(&env));
        items.push_back(item);
        env.storage().persistent().set(&DataKey::Items, &items);
    }
}
