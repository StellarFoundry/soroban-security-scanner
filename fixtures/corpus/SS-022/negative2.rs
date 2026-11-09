#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Reward,
    Penalty,
}

#[contract]
pub struct Pool;

#[contractimpl]
impl Pool {
    pub fn configure(env: Env, user: Address, reward: i128) {
        user.require_auth();
        env.storage().persistent().set(&DataKey::Reward, &reward);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Reward, 100, 1000);
    }
}
