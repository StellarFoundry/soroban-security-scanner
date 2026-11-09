// Must-trigger recall fixture (SS-005)
// Rationale: True positive because `deref_raw` uses an `unsafe` block to
// dereference a raw pointer inside a Soroban contract implementation, bypassing
// Rust memory-safety guarantees.

#![no_std]
use soroban_sdk::{contractimpl, Env};

pub struct UnsafeReader;

#[contractimpl]
impl UnsafeReader {
    pub fn deref_raw(env: Env, ptr: *const u32) -> u32 {
        let _ = env;
        unsafe { core::ptr::read(ptr) }
    }
}
