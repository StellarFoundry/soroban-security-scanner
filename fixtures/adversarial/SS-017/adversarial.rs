// Adversarial fixture (SS-017)
// Technique: Persistent storage mutation inside an inner block before `require_auth_for_args`.
// Expected: trigger (state mutation occurs at an earlier byte offset than authorization).

#![no_std]
use soroban_sdk::{contractimpl, Address, Env, IntoVal};

pub struct LateAuth;

#[contractimpl]
impl LateAuth {
    pub fn update(env: Env, admin: Address, val: u32) {
        {
            env.storage().persistent().set(&DataKey::Val, &val);
        }
        admin.require_auth_for_args((val,).into_val(&env));
    }
}
