#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Treasury;

#[contractimpl]
impl Treasury {
    pub fn verify_caller(env: Env, caller: Address) -> bool {
        caller.require_auth();
        caller != env.current_contract_address()
    }
}
