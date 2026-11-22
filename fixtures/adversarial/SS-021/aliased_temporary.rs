// SS-021 adversarial: an aliased Temporary import used through a UFCS call
// still writes a durable-looking key to temporary storage.

#![no_std]

use soroban_sdk::storage::Temporary as Store;
use soroban_sdk::{contractimpl, Address, Env};

pub struct Settings;

#[contractimpl]
impl Settings {
    pub fn set_owner(env: Env, owner: Address) {
        let store = env.storage().temporary();
        Store::set(&store, &DataKey::Owner, &owner);
    }
}
