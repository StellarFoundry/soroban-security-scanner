// SS-046 adversarial: a storage chain and key construction split across lines
// still writes two record shapes through the same key.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_balance(env: Env, admin: Address, user: Address) {
        admin.require_auth();
        env.storage()
            .temporary()
            .set(
                &DataKey::Balance(user.clone()),
                &Balance {
                    amount: 1,
                },
            );
    }

    pub fn set_balance_locked(env: Env, admin: Address, user: Address) {
        admin.require_auth();
        env.storage()
            .temporary()
            .set(
                &DataKey::Balance(user.clone()),
                &Balance {
                    amount: 1,
                    unlock: 2,
                },
            );
    }
}
