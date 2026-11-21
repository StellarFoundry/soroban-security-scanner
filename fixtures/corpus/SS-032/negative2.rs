// SS-032 negative: there is no loop around the authorization.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set(env: Env, admin: Address) {
        admin.require_auth();
        let _ = &env;
    }
}
