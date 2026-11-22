// SS-020 adversarial: spaces around the deserialization path do not hide it.

#![no_std]

use soroban_sdk::{contractimpl, Bytes, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn decode(env: Env, payload: Bytes) -> u32 {
        let value = u32 :: from_xdr ( & env , & payload ) ;
        value
    }
}
