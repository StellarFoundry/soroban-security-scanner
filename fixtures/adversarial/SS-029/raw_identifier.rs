// Adversarial SS-029: the debug hook is inside a nested module inside the
// contract impl and uses raw identifiers for its unused environment argument.
#[contractimpl]
impl C {
    pub fn debug_set_admin(r#env: Env, admin: Address) {
        let _ = r#env;
        let _ = admin;
    }
}
