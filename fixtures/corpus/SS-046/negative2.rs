// SS-046 negative: different keys are separate namespaces even when the value
// field sets differ.

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
            .set(&DataKey::Meta(user), &Meta { owner: 2 });
    }
}
