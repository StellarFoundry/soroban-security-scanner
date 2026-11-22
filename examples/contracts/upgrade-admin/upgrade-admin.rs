// SPDX-License-Identifier: MIT
//! Category: upgrade-admin
//! Focus: Authorize upgrades with the stored administrator.

use soroban_sdk::{contractimpl, Address, BytesN, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn upgrade(env: Env, admin: Address, wasm_hash: BytesN<32>) {
        let configured: Address = env.storage().instance().get(&0).unwrap();
        if admin != configured {
            panic!("not the admin");
        }
        admin.require_auth();
        env.deployer().update_current_contract_wasm(wasm_hash);
    }
}
