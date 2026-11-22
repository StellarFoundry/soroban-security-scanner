// SS-020 negative: the payload length is checked before decoding.

#![no_std]

use soroban_sdk::{contractimpl, Bytes, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn decode(env: Env, payload: Bytes) -> u32 {
        if payload.len() != 4 {
            return 0;
        }
        u32::from_xdr(&env, &payload)
    }
}
