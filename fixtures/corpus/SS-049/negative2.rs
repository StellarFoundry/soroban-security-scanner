// SS-049 negative fixture: the conversion result is matched and handled.
#![no_std]

use soroban_sdk::{contractimpl, Bytes, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_name(env: Env, bytes: Bytes) -> Result<(), Error> {
        match std::str::from_utf8(&bytes) {
            Ok(name) => {
                env.storage().persistent().set(&Key::Name, &name);
                Ok(())
            }
            Err(_) => Err(Error::InvalidUtf8),
        }
    }
}
