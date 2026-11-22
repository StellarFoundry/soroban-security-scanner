// SS-034 positive: a deployer chain with no authorization.

#![no_std]

use soroban_sdk::{contractimpl, Address, BytesN, Env};

pub struct Factory;

#[contractimpl]
impl Factory {
    pub fn create(env: Env, wasm: BytesN<32>, salt: BytesN<32>) -> Address {
        env.deployer().with_current_contract(salt).deploy(wasm)
    }
}
