#![no_std]
use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct LendingPool;

#[contractimpl]
impl LendingPool {
    pub fn view_balance(env: Env, user: Address, asset: Address) -> i128 {
        user.require_auth();
        let client = token::Client::new(&env, &asset);
        client.balance(&user)
    }
}
