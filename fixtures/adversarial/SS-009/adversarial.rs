// Adversarial fixture (SS-009)
// Technique: Parenthesized receiver, multiline whitespace, and inline comments inside modulo expression.
// Expected: trigger (combining ledger().sequence() with `%` in an entry point).

#![no_std]
use soroban_sdk::{contractimpl, Env};

pub struct Draw;

#[contractimpl]
impl Draw {
    pub fn roll(env: Env) -> u32 {
        ((env)
            .ledger( )
            /* sequence accessor */
            .sequence( )
            % (6_u32))
    }
}
