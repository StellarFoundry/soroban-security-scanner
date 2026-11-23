// SS-024 positive: a local boundary type is missing #[contracttype].

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn store(env: Env, value: Payload) -> Receipt {
        let _ = (&env, &value);
        Receipt { ok: true }
    }
}

pub struct Payload {
    pub amount: i128,
}

pub struct Receipt {
    pub ok: bool,
}