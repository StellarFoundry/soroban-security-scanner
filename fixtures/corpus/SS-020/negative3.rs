// SS-020 negative: the bytes come from storage, not from the caller.

#![no_std]

use soroban_sdk::{contractimpl, Bytes, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn decode(env: Env) -> u32 {
        let payload: Bytes = env.storage().instance().get(&Key::Data).unwrap();
        u32::from_xdr(&env, &payload)
    }
}
