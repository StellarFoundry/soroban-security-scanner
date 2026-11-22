// SPDX-License-Identifier: MIT
//! Category: arithmetic
//! Focus: Use checked multiplication before storing a computed total.

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn total(env: Env, price: i128, quantity: i128) -> i128 {
        let total = price.checked_mul(quantity).expect("overflow");
        env.storage().instance().set(&0, &total);
        total
    }
}
