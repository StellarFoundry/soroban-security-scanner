#![no_std]
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env};

#[contract]
pub struct Factory;

#[contractimpl]
impl Factory {
    pub fn deploy_child(
        env: Env,
        admin: Address,
        salt: BytesN<32>,
        wasm_hash: BytesN<32>,
    ) -> Address {
        Self::authorize(&admin);
        env.deployer()
            .with_current_contract(salt)
            .deploy_v2(wasm_hash, ())
    }

    fn authorize(admin: &Address) {
        admin.require_auth();
    }
}
