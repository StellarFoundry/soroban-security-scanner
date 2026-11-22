// SS-034 negative: the administrator authorizes before deploying.

#![no_std]

use soroban_sdk::{contractimpl, Address, BytesN, Env};

pub struct Factory;

#[contractimpl]
impl Factory {
    pub fn create(
        env: Env,
        admin: Address,
        wasm: BytesN<32>,
        salt: BytesN<32>,
    ) -> Address {
        admin.require_auth();
        env.deployer().with_current_contract(salt).deploy(wasm)
    }
}
