// SS-049 negative fixture: the lossy conversion cannot fail.
#![no_std]

use soroban_sdk::{contractimpl, Bytes, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_name(env: Env, bytes: Bytes) {
        let name = String::from_utf8_lossy(&bytes);
        env.storage().persistent().set(&Key::Name, &name);
    }
}
