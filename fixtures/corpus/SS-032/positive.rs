// SS-032 positive: require_auth is called inside a for loop body.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env, Vec};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn pay(env: Env, admin: Address, recipients: Vec<Address>) {
        for recipient in recipients.iter() {
            admin.require_auth();
            recipient.require_auth();
            let _ = &env;
        }
    }
}
