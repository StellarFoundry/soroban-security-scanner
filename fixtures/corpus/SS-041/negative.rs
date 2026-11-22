// SS-041 negative: unconditional authorization at the top of the loop.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env, Vec};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn batch(env: Env, admin: Address, recipients: Vec<Address>) {
        for recipient in recipients.iter() {
            admin.require_auth();
            env.storage().persistent().set(recipient, &1);
        }
    }
}
