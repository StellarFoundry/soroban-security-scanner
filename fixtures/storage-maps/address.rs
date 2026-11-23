// Map storage fixture: address key.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env, Map};

pub struct Store;

#[contractimpl]
impl Store {
    pub fn read_address(env: Env) -> i128 {
        let map: Map<Address, i128> =
            env.storage().persistent().get(&Key::ByAddress).unwrap();
        map.len() as i128
    }
}
