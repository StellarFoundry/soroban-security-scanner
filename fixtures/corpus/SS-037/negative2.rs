// SS-037 negative: only one actor is authorized.

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
