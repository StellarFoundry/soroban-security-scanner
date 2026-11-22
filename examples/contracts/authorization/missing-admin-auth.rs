// SPDX-License-Identifier: MIT
//! Category: authorization
//! Focus: Show a privileged write that forgets authorization (intentionally unsafe).

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_value(env: Env, value: u32) {
        // Missing: load the admin and call require_auth before this write.
        env.storage().persistent().set(&1, &value);
    }
}
