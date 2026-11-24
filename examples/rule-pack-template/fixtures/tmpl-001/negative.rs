use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct AdminVault;

#[contractimpl]
impl AdminVault {
    // CLEAN: Checks caller authorization before updating admin
    pub fn update_admin(env: Env, admin: Address, new_admin: Address) {
        admin.require_auth();
        env.storage().instance().set(&1u32, &new_admin);
    }
}
