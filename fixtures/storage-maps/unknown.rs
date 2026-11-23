// Map storage fixture: a key type the analysis cannot classify.

#![no_std]

use soroban_sdk::{contractimpl, Env, Map};

pub struct Store;

#[contractimpl]
impl Store {
    pub fn read_custom(env: Env) -> u32 {
        let map: Map<CustomKey, u32> =
            env.storage().persistent().get(&Key::ByCustom).unwrap();
        map.len()
    }
}
