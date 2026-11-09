#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Vec};

#[contract]
pub struct BatchDistributor;

#[contractimpl]
impl BatchDistributor {
    pub fn distribute(env: Env, admin: Address, recipients: Vec<Address>, amount: i128) {
        admin.require_auth();
        for recipient in recipients.iter() {
            env.storage().persistent().set(&recipient, &amount);
        }
    }
}
