#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

const VERSION_KEY: Symbol = symbol_short!("VER_1");

#[contract]
pub struct Pool;

#[contractimpl]
impl Pool {
    pub fn version(env: Env) -> u32 {
        env.storage().instance().get(&VERSION_KEY).unwrap_or(1)
    }
}
