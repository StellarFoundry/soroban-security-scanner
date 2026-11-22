// SPDX-License-Identifier: MIT
//! Category: events
//! Focus: Emit an event when privileged configuration changes.

use soroban_sdk::{contractimpl, contractevent, Address, Env};

#[contractevent]
pub struct AdminChanged {
    pub old: Address,
    pub new: Address,
}

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_admin(env: Env, old: Address, new: Address) {
        old.require_auth();
        env.storage().instance().set(&0, &new);
        AdminChanged { old, new }.publish(&env);
    }
}
