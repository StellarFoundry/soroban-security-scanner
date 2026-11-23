// SS-049 adversarial sample: a conversion result split across lines is still
// unwrapped, so invalid UTF-8 panics.
#![no_std]

use soroban_sdk::{contractimpl, Bytes, Env, String};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_name(env: Env, bytes: Bytes) {
        let name = String::from_utf8(bytes)
            .unwrap();
        env.storage().persistent().set(&Key::Name, &name);
    }
}
