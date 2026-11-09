#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Treasury;

#[contractimpl]
impl Treasury {
    pub fn contract_id(env: Env) -> Address {
        env.current_contract_address()
    }
}
