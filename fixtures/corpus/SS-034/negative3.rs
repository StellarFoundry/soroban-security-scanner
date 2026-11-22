// SS-034 negative: deployment goes through a client, not `env.deployer()`.

#![no_std]

use soroban_sdk::{contractimpl, Address, BytesN, Env};

pub struct Factory;

#[contractimpl]
impl Factory {
    pub fn create(env: Env, admin: Address, wasm: BytesN<32>) {
        admin.require_auth();
        let factory = FactoryClient::new(&env, &id);
        let _result = factory.deploy(&wasm);
    }
}
