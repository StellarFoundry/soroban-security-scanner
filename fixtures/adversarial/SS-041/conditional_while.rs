// SS-041 adversarial: a conditional auth inside a while loop still fires.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn drain(env: Env, admin: Address, mut remaining: u32) {
        while remaining > 0 {
            if remaining % 2 == 0 {
                admin . require_auth ( ) ;
            }
            env.storage().persistent().set(&admin, &remaining);
            remaining -= 1;
        }
    }
}
