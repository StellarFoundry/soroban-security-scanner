fn unrelated_constant() {
    let _ = my_app::networks::Networks::TESTNET;
    let _ = stellar_sdk::network::Network::Custom;
}
