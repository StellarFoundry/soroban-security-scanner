// SS-034 negative: the deployer accessor is used without deploying anything.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Factory;

#[contractimpl]
impl Factory {
    pub fn address(env: Env) -> Address {
        let deployer = env.deployer();
        deployer.current_contract_address()
    }
}
