// SS-041 positive: conditional authorization and authorization after a write.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env, Vec};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn batch_conditional(env: Env, admin: Address, recipients: Vec<Address>) {
        for recipient in recipients.iter() {
            if recipient != admin {
                admin.require_auth();
            }
            env.storage().persistent().set(recipient, &1);
        }
    }

    pub fn batch_after_write(env: Env, admin: Address, recipients: Vec<Address>) {
        for recipient in recipients.iter() {
            env.storage().persistent().set(recipient, &1);
            admin.require_auth();
        }
    }
}
