// SPDX-License-Identifier: MIT
//! Category: authorization
//! Focus: Check a stored role before allowing an operator action.

use soroban_sdk::{contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum Role {
    Operator,
    Admin,
}

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn rotate(env: Env, caller: Address) {
        let role: Role = env.storage().instance().get(&0).unwrap();
        if !matches!(role, Role::Admin) {
            panic!("admin role required");
        }
        caller.require_auth();
        env.storage().instance().set(&1, &caller);
    }
}
