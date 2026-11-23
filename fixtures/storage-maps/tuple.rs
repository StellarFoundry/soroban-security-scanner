// Map storage fixture: tuple key.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env, Map, Symbol};

pub struct Store;

#[contractimpl]
impl Store {
    pub fn read_tuple(env: Env) -> u64 {
        let map: Map<(Symbol, Address), u64> =
            env.storage().instance().get(&Key::ByTuple).unwrap();
        map.len()
    }
}
