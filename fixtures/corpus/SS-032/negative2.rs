#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, IntoVal};

#[contract]
pub struct SingleTransfer;

#[contractimpl]
impl SingleTransfer {
    pub fn transfer(env: Env, sender: Address, recipient: Address, amount: i128) {
        sender.require_auth_for_args((&recipient, amount).into_val(&env));
        env.storage().persistent().set(&recipient, &amount);
    }
}
