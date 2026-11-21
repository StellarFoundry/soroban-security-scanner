// SS-037 adversarial: parenthesized receivers still render as distinct actors.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn settle(env: Env, a: Address, b: Address) {
        (a).require_auth();
        (&b).require_auth_for_args((1_u32,));
        let _ = &env;
    }
}
