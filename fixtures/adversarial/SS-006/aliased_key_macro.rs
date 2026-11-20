// Adversarial SS-006: the storage key macro is aliased; the persistent write
// and the missing TTL management are still visible.
use soroban_sdk::{contractimpl, symbol_short as key, Address, Env};

#[contractimpl]
impl Vault {
    pub fn set_admin(env: Env, admin: Address, new_admin: Address) {
        admin.require_auth();
        env.storage().persistent().set(&key!("ADMIN"), &new_admin);
    }
}
