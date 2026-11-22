// SPDX-License-Identifier: MIT
//! Category: authorization
//! Focus: Collect approvals from a fixed signer set until a threshold is met.

use soroban_sdk::{contractimpl, Address, Env, Vec};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn approve(env: Env, signer: Address, approvals: Vec<Address>) {
        signer.require_auth();
        let mut next = Vec::new(&env);
        for approved in approvals.iter() {
            next.push_back(approved);
        }
        next.push_back(signer);
        if next.len() >= 3 {
            env.storage().instance().set(&0, &true);
        }
    }
}
