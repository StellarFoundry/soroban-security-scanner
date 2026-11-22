// SPDX-License-Identifier: MIT
//! Category: authorization
//! Focus: Require the stored administrator's authorization before a privileged write.

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_value(env: Env, admin: Address, value: u32) {
        let configured: Address = env.storage().instance().get(&0).unwrap();
        if admin != configured {
            panic!("not the administrator");
        }
        admin.require_auth();
        env.storage().persistent().set(&1, &value);
    }
}
