// SPDX-License-Identifier: MIT
//! Category: events
//! Focus: Publish only a reference, never secret material, in an event.

use soroban_sdk::{contractimpl, contractevent, Env};

#[contractevent]
pub struct CommitmentStored {
    pub commitment: u32,
}

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn store(env: Env, secret: u32) {
        let commitment = secret.checked_mul(31).unwrap_or(0);
        env.storage().persistent().set(&0, &commitment);
        CommitmentStored { commitment }.publish(&env);
    }
}
