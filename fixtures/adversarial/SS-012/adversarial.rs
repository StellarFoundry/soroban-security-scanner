// Adversarial fixture (SS-012)
// Technique: Storage-backed `Vec` mutated via `push_back` inside a nested conditional block.
// Expected: trigger (unbounded collection growth on a storage-loaded vector).

#![no_std]
use soroban_sdk::{contractimpl, Address, Env, Vec};

pub struct Log;

#[contractimpl]
impl Log {
    pub fn push_entry(env: Env, admin: Address, item: u32) {
        admin.require_auth();
        let mut list: Vec<u32> = env
            .storage()
            .persistent()
            .get(&DataKey::List)
            .unwrap_or(Vec::new(&env));
        if item > 0 {
            list.push_back(item);
        }
        env.storage().persistent().set(&DataKey::List, &list);
    }
}
