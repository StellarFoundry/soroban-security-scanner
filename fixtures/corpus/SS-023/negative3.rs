#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct AuthVault;

#[contractimpl]
impl AuthVault {
    pub fn rotate_key_id(env: Env, admin: Address, key_id: u32) {
        admin.require_auth();
        env.events()
            .publish((symbol_short!("rotate"), &admin), key_id);
    }
}
