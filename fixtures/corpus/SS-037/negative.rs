// SS-037 negative: the same actor is authorized twice.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn settle(env: Env, admin: Address) {
        admin.require_auth();
        admin.require_auth_for_args((admin.clone(),));
        let _ = &env;
    }
}
