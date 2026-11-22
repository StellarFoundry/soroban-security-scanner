// SS-027 negative: the caller is authorized.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn guarded(env: Env, admin: Address) {
        admin.require_auth();
    }
}
