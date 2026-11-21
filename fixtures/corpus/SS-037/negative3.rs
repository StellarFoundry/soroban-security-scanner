// SS-037 negative: documented multi-sig pattern using one multisig actor.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    // The caller passes a single Stellar multisig account; the network enforces
    // the signing policy for that account, so one authorization is sufficient.
    pub fn settle(env: Env, multisig: Address) {
        multisig.require_auth();
        let _ = &env;
    }
}
