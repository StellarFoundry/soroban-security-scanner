// SS-049 negative fixture: an explicit fallback replaces the panic path.
#![no_std]

use soroban_sdk::{contractimpl, Bytes, Env, String};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_name(env: Env, bytes: Bytes) {
        let name = String::from_utf8(bytes).unwrap_or_default();
        env.storage().persistent().set(&Key::Name, &name);
    }
}
