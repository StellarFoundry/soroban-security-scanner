#![no_std]
use soroban_sdk::{contract, contractimpl, xdr::FromXdr, Address, Bytes, Env};

#[contract]
pub struct Bridge;

#[contractimpl]
impl Bridge {
    pub fn ingest(env: Env, relayer: Address, raw_payload: Bytes) -> u64 {
        relayer.require_auth();
        if raw_payload.len() > 128 {
            return 0;
        }
        u64::from_xdr(&env, &raw_payload).unwrap_or(0)
    }
}
