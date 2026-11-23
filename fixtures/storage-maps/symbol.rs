// Map storage fixture: symbol key.

#![no_std]

use soroban_sdk::{contractimpl, Env, Map, Symbol};

pub struct Store;

#[contractimpl]
impl Store {
    pub fn read_symbol(env: Env) -> u32 {
        let map: Map<Symbol, u32> =
            env.storage().persistent().get(&Key::BySymbol).unwrap();
        map.len()
    }
}
