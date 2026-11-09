#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, IntoVal};

#[contract]
pub struct ScopedAccount;

#[contractimpl]
impl ScopedAccount {
    pub fn update_profile(env: Env, owner: Address, nonce: u64) {
        owner.require_auth();
        owner.require_auth_for_args((nonce,).into_val(&env));
        env.storage().persistent().set(&owner, &nonce);
    }
}
