#![no_std]
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env};

#[contract]
pub struct Factory;

#[contractimpl]
impl Factory {
    pub fn deploy_child(env: Env, salt: BytesN<32>, wasm_hash: BytesN<32>) -> Address {
        env.deployer().with_current_contract(salt).deploy(wasm_hash)
    }
}
