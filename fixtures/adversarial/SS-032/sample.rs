// SS-032 adversarial: authorization nested two loops deep still triggers.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env, Vec};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn sweep(env: Env, admin: Address, batches: Vec<Vec<Address>>) {
        for batch in batches.iter() {
            loop {
                admin.require_auth_for_args((1_u32,));
                break;
            }
            let _ = (&env, batch);
        }
    }
}
