// SPDX-License-Identifier: MIT
//! Category: errors
//! Focus: Assert an invariant after updating two related entries.

use soroban_sdk::{contractimpl, contracterror, Env};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    Invariant = 1,
}

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn settle(env: Env, debit: i128, credit: i128) -> Result<(), Error> {
        let total = debit.checked_add(credit).ok_or(Error::Invariant)?;
        env.storage().instance().set(&0, &debit);
        env.storage().instance().set(&1, &credit);
        if total < 0 {
            return Err(Error::Invariant);
        }
        Ok(())
    }
}
