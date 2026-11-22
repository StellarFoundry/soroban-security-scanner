// SPDX-License-Identifier: MIT
//! Category: upgrade-admin
//! Focus: Update a bounded fee only through the administrator.

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_fee(env: Env, admin: Address, fee_bps: u32) {
        admin.require_auth();
        let configured: Address = env.storage().instance().get(&0).unwrap();
        if admin != configured || fee_bps > 500 {
            panic!("invalid fee change");
        }
        env.storage().instance().set(&1, &fee_bps);
    }
}
