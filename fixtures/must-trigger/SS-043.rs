// SS-043 must trigger: a canonical network passphrase is embedded in source.
const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";

fn sign_for_testnet() {
    let _ = NETWORK_PASSPHRASE;
}
