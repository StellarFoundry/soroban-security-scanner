// SPDX-License-Identifier: MIT
//! Category: errors
//! Focus: Return an authorization error with a typed variant.

use soroban_sdk::{contractimpl, contracterror, Address, Env};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    Unauthorized = 1,
}

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set(env: Env, caller: Address) -> Result<(), Error> {
        let admin: Address = env.storage().instance().get(&0).unwrap();
        if caller != admin {
            return Err(Error::Unauthorized);
        }
        caller.require_auth();
        Ok(())
    }
}
