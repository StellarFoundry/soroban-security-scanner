//! Unsupported SDK fixture: pinned above the supported matrix on purpose.
//! This is test data, not a production contract.

#![no_std]

use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct SdkMatrixUnsupportedContract;

#[contractimpl]
impl SdkMatrixUnsupportedContract {
    pub fn set_admin(env: Env, new_admin: Address) {
        env.storage()
            .persistent()
            .set(&symbol_short!("ADMIN"), &new_admin);
    }
}
