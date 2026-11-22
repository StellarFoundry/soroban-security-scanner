// SPDX-License-Identifier: MIT
//! Category: errors
//! Focus: Reject an out-of-range input before it reaches storage.

use soroban_sdk::{contractimpl, contracterror, Env};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    OutOfRange = 1,
}

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set(env: Env, value: u32) -> Result<(), Error> {
        if value > 1_000 {
            return Err(Error::OutOfRange);
        }
        env.storage().instance().set(&0, &value);
        Ok(())
    }
}
