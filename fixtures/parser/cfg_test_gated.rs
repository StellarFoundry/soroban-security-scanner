// Parser fixture: items gated behind cfg attributes.
// `cfg(test)` items are skipped by default; `cfg(not(test))` and
// `cfg(feature = "...")` code is production code and must still be scanned.
// This file is a security fixture, not production code.

use soroban_sdk::{contractimpl, symbol_short, Address, Env};

#[contractimpl]
impl Vault {
    // Unauthorized write in production code: always reported.
    pub fn set_admin(env: Env, new_admin: Address) {
        env.storage()
            .persistent()
            .set(&symbol_short!("ADMIN"), &new_admin);
    }

    // Unauthorized write gated behind a feature: still production code.
    #[cfg(feature = "extras")]
    pub fn set_fee(env: Env, fee: i128) {
        env.storage().persistent().set(&symbol_short!("FEE"), &fee);
    }

    // Test-only helper: skipped by default.
    #[cfg(test)]
    pub fn test_reset(env: Env) {
        env.storage().persistent().set(&symbol_short!("ADMIN"), &0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[contractimpl]
    impl Helper {
        pub fn seed(env: Env) {
            env.storage().persistent().set(&symbol_short!("SEED"), &1);
        }
    }
}
