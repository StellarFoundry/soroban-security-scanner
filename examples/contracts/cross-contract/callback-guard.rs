// SPDX-License-Identifier: MIT
//! Category: cross-contract
//! Focus: Guard a cross-contract callback with a one-shot flag.

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn on_callback(env: Env, caller: Address) {
        let expected: Address = env.storage().instance().get(&0).unwrap();
        if caller != expected {
            panic!("unexpected callback");
        }
        let busy: bool = env.storage().instance().get(&1).unwrap_or(false);
        if busy {
            panic!("reentrant callback");
        }
        env.storage().instance().set(&1, &true);
    }
}
