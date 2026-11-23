use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct AdminVault;

#[contractimpl]
impl AdminVault {
    // VULNERABLE: Modifies administrative state without calling admin.require_auth()
    pub fn update_admin(env: Env, _new_admin: Address) {
        env.storage().instance().set(&1u32, &_new_admin);
    }
}
