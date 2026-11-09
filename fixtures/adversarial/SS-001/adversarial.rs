// Adversarial fixture (SS-001)
// Technique: Multiline whitespace, comments between method chain segments, and aliased SDK import.
// Expected: trigger (storage write still occurs in a public entry point without require_auth).

#![no_std]
use soroban_sdk::{contractimpl, symbol_short, Address, Env as SorobanEnv};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn/*comment*/set_admin(
        env: SorobanEnv,
        new_admin: Address,
    ) {
        (env)
            .storage( )
            /* persistent tier */
            .persistent( )
            .set(
                &symbol_short!("ADMIN"),
                &new_admin,
            );
    }
}
