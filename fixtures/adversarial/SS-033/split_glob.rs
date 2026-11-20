// Adversarial SS-033: the glob import is split across lines.
#[allow(unused_imports)]
use soroban_sdk::
    *;

#[contractimpl]
impl Contract {
    pub fn ping(env: Env) -> Symbol {
        symbol_short!("pong")
    }
}
