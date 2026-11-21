// SS-029 positive: a public debug hook exposed as a contract entry point.
//
// The entry point name contains the `debug` segment, so it is treated as a
// potential backdoor that could be reachable in production.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn debug_set_admin(_env: Env, admin: Address) {
        let _ = admin;
    }
}
