// Must-trigger recall fixture (SS-006)
// Rationale: True positive because `store_record` writes critical state to
// persistent storage without calling `extend_ttl`, leaving the entry vulnerable
// to unexpected ledger archival expiration.

#![no_std]
use soroban_sdk::{contractimpl, symbol_short, Address, Env};

pub struct Escrow;

#[contractimpl]
impl Escrow {
    pub fn store_record(env: Env, owner: Address, balance: i128) {
        owner.require_auth();
        env.storage()
            .persistent()
            .set(&symbol_short!("RECORD"), &balance);
    }
}
