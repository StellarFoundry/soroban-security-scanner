// SS-031 adversarial: aliased SDK import and spaced publish chain still expose
// the caller-controlled topic.

#![no_std]

use soroban_sdk::{contractimpl, symbol_short as tag, Address, Env};

pub struct Events;

#[contractimpl]
impl Events {
    pub fn announce(env: Env, account: Address) {
        env . events () . publish ((tag!("announce"), account . clone ()), 0);
    }
}
