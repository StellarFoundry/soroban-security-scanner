#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct CleanVault;

#[contractimpl]
impl CleanVault {
    pub fn withdraw(env: Env, caller: Address, amount: i128) {
        caller.require_auth();
        env.storage().persistent().set(&caller, &amount);
    }

    pub fn set_fee(env: Env, admin: Address, fee_bps: u32) {
        admin.require_auth();
        env.storage().instance().set(&admin, &fee_bps);
    }
}
