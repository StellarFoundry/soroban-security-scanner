// SS-020 negative: the fallible decode result is matched explicitly.

#![no_std]

use soroban_sdk::{contractimpl, Bytes, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn decode(_env: Env, payload: Bytes) -> u32 {
        match u32::try_from(&payload) {
            Ok(value) => value,
            Err(_) => 0,
        }
    }
}
