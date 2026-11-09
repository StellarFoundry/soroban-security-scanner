// Must-trigger recall fixture (SS-012)
// Rationale: True positive because `append_member` loads a `Vec` from persistent
// storage, calls `push_back` with no maximum length bound, and writes the growing
// collection back to storage, risking storage entry byte/CPU exhaustion.

#![no_std]
use soroban_sdk::{contractimpl, Address, Env, Vec};

pub struct MemberList;

#[contractimpl]
impl MemberList {
    pub fn append_member(env: Env, admin: Address, member: Address) {
        admin.require_auth();
        let mut members: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Members)
            .unwrap_or(Vec::new(&env));
        members.push_back(member);
        env.storage().persistent().set(&DataKey::Members, &members);
    }
}
