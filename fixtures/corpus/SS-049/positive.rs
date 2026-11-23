// SS-049 positive fixture: bytes are converted to text and unwrapped, so invalid
// UTF-8 panics the entry point.
#![no_std]

use soroban_sdk::{contractimpl, Bytes, Env, String};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_name(env: Env, bytes: Bytes) {
        let name = String::from_utf8(bytes).unwrap();
        env.storage().persistent().set(&Key::Name, &name);
    }

    pub fn set_description(env: Env, bytes: Bytes) {
        let text = std::str::from_utf8(&bytes).expect("valid utf-8");
        env.storage().persistent().set(&Key::Description, &text);
    }
}
