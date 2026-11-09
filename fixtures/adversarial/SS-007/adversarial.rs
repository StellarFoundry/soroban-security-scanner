// Adversarial fixture (SS-007)
// Technique: Hardcoded 56-character Stellar address literal inside a local tuple binding.
// Expected: trigger (hardcoded Stellar strkey literal is still extracted from inner expressions).

#![no_std]
use soroban_sdk::{contractimpl, Env};

pub struct Config;

#[contractimpl]
impl Config {
    pub fn default_operator(env: Env) -> &'static str {
        let _ = env;
        let (_tag, addr) = (
            "primary",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        addr
    }
}
