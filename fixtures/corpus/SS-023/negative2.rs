#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct AuthVault;

#[contractimpl]
impl AuthVault {
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        env.events()
            .publish((symbol_short!("deposit"), &user), amount);
    }
}
