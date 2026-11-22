// SPDX-License-Identifier: MIT
//! Category: arithmetic
//! Focus: Use checked subtraction to prevent negative balances.

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn debit(env: Env, balance: i128, amount: i128) -> i128 {
        let next = balance.checked_sub(amount).unwrap_or_else(|| panic!("insufficient"));
        env.storage().instance().set(&0, &next);
        next
    }
}
