#![no_std]
use soroban_sdk::{contract, contractimpl, xdr::FromXdr, Bytes, Env};

#[contract]
pub struct Bridge;

#[contractimpl]
impl Bridge {
    pub fn decode_constant(env: Env) -> u64 {
        let local_bytes = Bytes::from_slice(&env, &[0, 0, 0, 0, 0, 0, 0, 1]);
        u64::from_xdr(&env, &local_bytes).unwrap_or(0)
    }
}
