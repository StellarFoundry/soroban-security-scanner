#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Router;

#[contractimpl]
impl Router {
    pub fn preview(env: Env, amount: i128) -> i128 {
        let _ = env.ledger().sequence();
        amount
    }
}
