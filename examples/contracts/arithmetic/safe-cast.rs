// SPDX-License-Identifier: MIT
//! Category: arithmetic
//! Focus: Convert a wide amount to a narrow type with try_into.

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn store(env: Env, amount: i128) {
        let narrow: u32 = amount.try_into().expect("amount out of range");
        env.storage().instance().set(&0, &narrow);
    }
}
