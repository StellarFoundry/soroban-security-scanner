#![no_std]
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env};

#[contract]
pub struct ModernFactory;

#[contractimpl]
impl ModernFactory {
    pub fn deploy_child(
        env: Env,
        admin: Address,
        salt: BytesN<32>,
        wasm_hash: BytesN<32>,
    ) -> Address {
        admin.require_auth();
        env.deployer()
            .with_address(admin, salt)
            .deploy_v2(wasm_hash, ())
    }
}
