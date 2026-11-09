#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct LegacyVault;

#[contractimpl]
impl LegacyVault {
    pub fn touch(env: Env) -> Address {
        let key = symbol_short!("CONF");
        env.storage().persistent().bump(&key, 100, 1000);
        env.current_contract_id()
    }
}
