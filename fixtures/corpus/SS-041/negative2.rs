// SS-041 negative: authorization is hoisted before the loop.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env, Vec};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn batch(env: Env, admin: Address, recipients: Vec<Address>) {
        admin.require_auth();
        for recipient in recipients.iter() {
            env.storage().persistent().set(recipient, &1);
        }
    }
}
