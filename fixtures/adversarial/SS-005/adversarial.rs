// Adversarial fixture (SS-005)
// Technique: Deeply nested block containing an `unsafe` expression inside an entry point.
// Expected: trigger (unsafe block is detected regardless of block nesting depth).

#![no_std]
use soroban_sdk::{contractimpl, Env};

pub struct RawMem;

#[contractimpl]
impl RawMem {
    pub fn peek(env: Env, ptr: *const u8) -> u8 {
        let _ = env;
        {
            {
                unsafe {
                    *ptr
                }
            }
        }
    }
}
