#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct ConfusedVault;

#[contractimpl]
impl ConfusedVault {
    pub fn withdraw(env: Env, admin: Address, caller: Address, amount: i128) {
        admin.require_auth();
        caller.require_auth();
        env.storage().persistent().set(&caller, &amount);
    }
}
