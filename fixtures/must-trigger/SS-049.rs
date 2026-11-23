// SS-049 must trigger: a public entry point converts caller-supplied bytes to a
// `String` and unwraps the result, so invalid UTF-8 panics.

#![no_std]

use soroban_sdk::{contractimpl, Bytes, Env, String};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_name(env: Env, bytes: Bytes) {
        let name = String::from_utf8(bytes).unwrap();
        env.storage().persistent().set(&Key::Name, &name);
    }
}
