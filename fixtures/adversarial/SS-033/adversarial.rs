// Adversarial fixture (SS-033)
// Technique: Wildcard `use ::soroban_sdk::*;` inside an inline module.
// Expected: trigger (wildcard import from soroban_sdk is detected inside inline modules).

#![no_std]

pub mod inner {
    use soroban_sdk::*;

    #[contract]
    pub struct InnerContract;

    #[contractimpl]
    impl InnerContract {
        pub fn ping(_env: Env) -> Symbol {
            symbol_short!("pong")
        }
    }
}
