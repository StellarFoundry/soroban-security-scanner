use soroban_sdk::contractimpl;

#[contractimpl]
impl Vault {
    pub fn set(value: u32) {
        store(value);
    }
}

fn store(value: u32) {
    unsafe { let _ = value; }
}
