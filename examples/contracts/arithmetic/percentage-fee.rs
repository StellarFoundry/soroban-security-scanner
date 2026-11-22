// SPDX-License-Identifier: MIT
//! Category: arithmetic
//! Focus: Compute a fee with checked multiplication and division.

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn fee(env: Env, amount: i128) -> i128 {
        let product = amount.checked_mul(30).expect("overflow");
        let fee = product.checked_div(10_000).expect("nonzero divisor");
        env.storage().instance().set(&0, &fee);
        fee
    }
}
