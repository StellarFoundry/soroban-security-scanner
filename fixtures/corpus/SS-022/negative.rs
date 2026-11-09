#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, Symbol};

const REWARD_KEY: Symbol = symbol_short!("REWARD");
const PENALTY_KEY: Symbol = symbol_short!("PENALTY");

#[contract]
pub struct Pool;

#[contractimpl]
impl Pool {
    pub fn configure(env: Env, user: Address, reward: i128, penalty: i128) {
        user.require_auth();
        env.storage().persistent().set(&REWARD_KEY, &reward);
        env.storage().persistent().set(&PENALTY_KEY, &penalty);
        env.storage().persistent().extend_ttl(&REWARD_KEY, 100, 1000);
        env.storage().persistent().extend_ttl(&PENALTY_KEY, 100, 1000);
    }
}
