// SS-049 negative fixture: only a private helper unwraps the conversion.
#![no_std]

use soroban_sdk::{contractimpl, Bytes, Env, String};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_name(env: Env, bytes: Bytes) {
        let name = Self::decode(bytes);
        env.storage().persistent().set(&Key::Name, &name);
    }

    fn decode(bytes: Bytes) -> String {
        String::from_utf8(bytes).unwrap()
    }
}
