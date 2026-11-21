// SS-032 negative: the loop lives in a private helper, not an entry point.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env, Vec};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn pay(env: Env, admin: Address, recipients: Vec<Address>) {
        admin.require_auth();
        let _ = &env;
        self::authorize_each(admin, recipients);
    }

    fn authorize_each(admin: Address, recipients: Vec<Address>) {
        for recipient in recipients.iter() {
            admin.require_auth();
            recipient.require_auth();
        }
    }
}
