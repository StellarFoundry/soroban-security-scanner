#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Bytes, Env};

#[contract]
pub struct AuthVault;

#[contractimpl]
impl AuthVault {
    pub fn register_secret(env: Env, user: Address, user_secret_key: Bytes) {
        user.require_auth();
        env.events()
            .publish((symbol_short!("reg"), &user), user_secret_key);
    }
}
