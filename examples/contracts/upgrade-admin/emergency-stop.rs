// SPDX-License-Identifier: MIT
//! Category: upgrade-admin
//! Focus: Stop operations irreversibly after an emergency.

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn emergency_stop(env: Env, admin: Address) {
        admin.require_auth();
        let configured: Address = env.storage().instance().get(&0).unwrap();
        if admin != configured {
            panic!("not the admin");
        }
        env.storage().instance().set(&9, &true);
    }

    pub fn operate(env: Env) {
        let stopped: bool = env.storage().instance().get(&9).unwrap_or(false);
        if stopped {
            panic!("stopped");
        }
    }
}
