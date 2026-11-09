#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, BytesN, Env};

#[contract]
pub struct AuthVault;

#[contractimpl]
impl AuthVault {
    pub fn register_commitment(env: Env, user: Address, commitment_hash: BytesN<32>) {
        user.require_auth();
        env.events()
            .publish((symbol_short!("reg"), &user), commitment_hash);
    }
}
