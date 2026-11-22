// SS-046 negative: the same key and the same field set are one record shape.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_a(env: Env, admin: Address, user: Address) {
        admin.require_auth();
        env.storage()
            .temporary()
            .set(&DataKey::Balance(user), &Balance { amount: 1 });
    }

    pub fn set_b(env: Env, admin: Address, user: Address) {
        admin.require_auth();
        env.storage()
            .temporary()
            .set(&DataKey::Balance(user), &Balance { amount: 2 });
    }
}
