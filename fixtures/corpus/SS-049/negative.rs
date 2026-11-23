// SS-049 negative fixture: the conversion error is propagated with `?`.
#![no_std]

use soroban_sdk::{contractimpl, Bytes, Env, String};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_name(env: Env, bytes: Bytes) -> Result<(), Error> {
        let name = String::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
        env.storage().persistent().set(&Key::Name, &name);
        Ok(())
    }
}
