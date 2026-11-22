// SS-035 adversarial: spacing around the checked call does not hide the
// discarded result.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn deposit(env: Env, amount: i128) {
        let _ = amount . checked_add ( 1 );
    }
}
