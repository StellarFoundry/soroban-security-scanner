// SS-046 negative: struct update syntax hides the final field set, so the
// detector does not claim a collision.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_a(env: Env, admin: Address, user: Address, current: Balance) {
        admin.require_auth();
        env.storage().temporary().set(
            &DataKey::Balance(user),
            &Balance {
                amount: 1,
                ..current
            },
        );
    }

    pub fn set_b(env: Env, admin: Address, user: Address, current: Balance) {
        admin.require_auth();
        env.storage().temporary().set(
            &DataKey::Balance(user),
            &Balance {
                amount: 1,
                unlock: 2,
                ..current
            },
        );
    }
}
