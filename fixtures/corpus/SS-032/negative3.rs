#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct CounterContract;

#[contractimpl]
impl CounterContract {
    pub fn reset_and_count(env: Env, admin: Address, steps: u32) -> u32 {
        admin.require_auth();
        let mut i = 0;
        while i < steps {
            i += 1;
        }
        env.storage().instance().set(&admin, &i);
        i
    }
}
