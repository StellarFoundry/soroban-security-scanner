// SPDX-License-Identifier: MIT
//! Category: upgrade-admin
//! Focus: Gate state changes behind an administrator pause switch.

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_paused(env: Env, admin: Address, paused: bool) {
        admin.require_auth();
        let configured: Address = env.storage().instance().get(&0).unwrap();
        if admin != configured {
            panic!("not the admin");
        }
        env.storage().instance().set(&1, &paused);
    }

    pub fn deposit(env: Env, amount: i128) {
        let paused: bool = env.storage().instance().get(&1).unwrap_or(false);
        if paused {
            panic!("paused");
        }
        env.storage().persistent().set(&2, &amount);
    }
}
