// SS-046 must trigger: one key construction stores two different record shapes.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_balance(env: Env, admin: Address, user: Address) {
        admin.require_auth();
        env.storage()
            .temporary()
            .set(&DataKey::Balance(user.clone()), &Balance { amount: 1 });
    }

    pub fn set_balance_locked(env: Env, admin: Address, user: Address) {
        admin.require_auth();
        env.storage().temporary().set(
            &DataKey::Balance(user.clone()),
            &Balance {
                amount: 1,
                unlock: 2,
            },
        );
    }
}
