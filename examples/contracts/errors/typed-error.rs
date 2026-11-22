// SPDX-License-Identifier: MIT
//! Category: errors
//! Focus: Return a typed contract error instead of a string panic.

use soroban_sdk::{contractimpl, contracterror, Env};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    Invalid = 1,
}

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set(env: Env, value: u32) -> Result<(), Error> {
        if value == 0 {
            return Err(Error::Invalid);
        }
        env.storage().instance().set(&0, &value);
        Ok(())
    }
}
