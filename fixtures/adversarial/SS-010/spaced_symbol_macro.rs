// Adversarial SS-010: the privileged key is a macro invocation with spaces.
use soroban_sdk::{contractimpl, symbol_short, Address, Env};

#[contractimpl]
impl Config {
    pub fn set_admin(env: Env, admin: Address) {
        env.storage().persistent().set(&symbol_short ! ( "ADMIN" ), &admin);
    }
}
