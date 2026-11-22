// SPDX-License-Identifier: MIT
//! Category: arithmetic
//! Focus: Keep debit and credit sides of an accounting entry consistent.

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn settle(env: Env, debit: i128, credit: i128) {
        let next_debit = debit.checked_add(credit).expect("overflow");
        let next_credit = credit.checked_sub(debit).unwrap_or(0);
        env.storage().instance().set(&0, &next_debit);
        env.storage().instance().set(&1, &next_credit);
    }
}
