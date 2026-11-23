const NETWORK_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

fn network() {
    let _ = stellar_sdk::networks::Networks::TESTNET;
    let _ = NETWORK_PASSPHRASE;
}
