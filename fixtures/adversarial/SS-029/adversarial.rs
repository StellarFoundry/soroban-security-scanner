// Adversarial fixture (SS-029)
// Technique: Mixed-case `DeBuG` segment inside an inline module with comments and attributes.
// Expected: trigger (case-insensitive `_`-separated segment matching still flags `DeBuG`).

#![no_std]
use soroban_sdk::{contractimpl, Address, Env};

pub struct Hooked;

#[contractimpl]
impl Hooked {
    #[allow(non_snake_case, unused_variables)]
    pub fn /*comment*/ DeBuG_mint(
        env: Env,
        to: Address,
    ) {
        let _ = (env, to);
    }
}
