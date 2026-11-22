// SS-024 negative: boundary types are annotated with #[contracttype].

#![no_std]

use soroban_sdk::{contractimpl, contracttype, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn store(env: Env, value: Payload) -> Receipt {
        let _ = (&env, &value);
        Receipt { ok: true }
    }
}

#[contracttype]
pub struct Payload {
    pub amount: i128,
}

#[contracttype]
pub struct Receipt {
    pub ok: bool,
}