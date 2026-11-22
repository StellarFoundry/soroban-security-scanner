// SS-042 must trigger: the only authorization check follows an unconditional
// return, so it is dead code.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set(env: Env, admin: Address) {
        return;
        admin.require_auth();
        env.storage().persistent().set(&admin, &1);
    }
}
