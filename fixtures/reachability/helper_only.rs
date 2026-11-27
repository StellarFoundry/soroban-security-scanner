use soroban_sdk::contractimpl;

#[contractimpl]
impl Vault {
    pub fn set(value: u32) {
        let _ = value;
    }
}

fn unused(value: u32) {
    unsafe { let _ = value; }
}
