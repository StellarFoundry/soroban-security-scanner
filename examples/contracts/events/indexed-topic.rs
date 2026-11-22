// SPDX-License-Identifier: MIT
//! Category: events
//! Focus: Index a caller address as the event topic for filtering.

use soroban_sdk::{contractimpl, contractevent, Address, Env};

#[contractevent]
pub struct Called {
    #[topic]
    pub caller: Address,
    pub payload: u32,
}

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn record(env: Env, caller: Address, payload: u32) {
        caller.require_auth();
        Called { caller, payload }.publish(&env);
    }
}
