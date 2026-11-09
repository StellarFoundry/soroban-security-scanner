// Must-trigger recall fixture (SS-001)
// Rationale: True positive because `update_treasury` is a public `#[contractimpl]`
// entry point that writes to persistent storage without invoking `require_auth`
// on any caller or administrator address, allowing any account to overwrite state.

#![no_std]
use soroban_sdk::{contractimpl, symbol_short, Address, Env};

pub struct Treasury;

#[contractimpl]
impl Treasury {
    pub fn update_treasury(env: Env, new_recipient: Address) {
        env.storage()
            .persistent()
            .set(&symbol_short!("TREASURY"), &new_recipient);
    }
}
