// SPDX-License-Identifier: MIT
//! Category: cross-contract
//! Focus: Deploy a child contract only after administrator authorization.

use soroban_sdk::{contractimpl, Address, BytesN, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn deploy(env: Env, admin: Address, wasm_hash: BytesN<32>, salt: BytesN<32>) -> Address {
        admin.require_auth();
        let configured: Address = env.storage().instance().get(&0).unwrap();
        if admin != configured {
            panic!("not the admin");
        }
        env.deployer().deploy(wasm_hash, salt)
    }
}
