// SS-005 positive: unsafe code inside a contract implementation.
// This file is a security fixture, not production code.

use soroban_sdk::{contractimpl, Env};

#[contractimpl]
impl Raw {
    pub fn load(env: Env, ptr: *const u8) -> u8 {
        let _ = env;
        unsafe { core::ptr::read(ptr) }
    }
}
