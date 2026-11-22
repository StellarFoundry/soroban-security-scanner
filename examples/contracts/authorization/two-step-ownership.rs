// SPDX-License-Identifier: MIT
//! Category: authorization
//! Focus: Transfer ownership through a propose and accept handshake.

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn propose_owner(env: Env, current: Address, next: Address) {
        current.require_auth();
        env.storage().instance().set(&0, &next);
    }

    pub fn accept_owner(env: Env, next: Address) {
        next.require_auth();
        let pending: Address = env.storage().instance().get(&0).unwrap();
        if pending != next {
            panic!("not the proposed owner");
        }
    }
}
