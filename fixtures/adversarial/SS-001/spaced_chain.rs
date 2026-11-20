// Adversarial SS-001: qualified macro path, aliased crate, and spaced chains.
use soroban_sdk as sdk;
use sdk::{contractimpl, Address, Env};

#[contractimpl]
impl Vault {
    pub fn set_admin(env: Env, new_admin: Address) {
        env . storage ( ) . persistent ( ) . set ( &sdk::symbol_short!("ADMIN"), &new_admin );
    }
}
