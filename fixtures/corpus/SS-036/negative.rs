#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct ModernVault;

#[contractimpl]
impl ModernVault {
    pub fn touch(env: Env) -> Address {
        let key = symbol_short!("CONF");
        env.storage().persistent().extend_ttl(&key, 100, 1000);
        env.current_contract_address()
    }
}
