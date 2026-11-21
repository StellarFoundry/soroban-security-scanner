// SS-032 negative: authorization is hoisted before the loop.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env, Vec};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn pay(env: Env, admin: Address, recipients: Vec<Address>) {
        admin.require_auth();
        for recipient in recipients.iter() {
            let _ = (&env, recipient);
        }
    }
}
