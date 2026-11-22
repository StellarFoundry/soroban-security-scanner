// Taint fixture: every documented amount sanitizer clears the transfer flow.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn checked_add_case(env: Env, token_id: Address, to: Address, amount: i128) {
        let value = checked_add(&env, amount);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &value);
    }

    pub fn checked_sub_case(env: Env, token_id: Address, to: Address, amount: i128) {
        let value = checked_sub(&env, amount);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &value);
    }

    pub fn checked_mul_case(env: Env, token_id: Address, to: Address, amount: i128) {
        let value = checked_mul(&env, amount);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &value);
    }

    pub fn checked_div_case(env: Env, token_id: Address, to: Address, amount: i128) {
        let value = checked_div(&env, amount);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &value);
    }

    pub fn checked_neg_case(env: Env, token_id: Address, to: Address, amount: i128) {
        let value = checked_neg(&env, amount);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &value);
    }

    pub fn try_from_case(env: Env, token_id: Address, to: Address, amount: u64) {
        let value = i128::try_from(amount);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &value);
    }

    pub fn try_into_case(env: Env, token_id: Address, to: Address, amount: u64) {
        let value = amount.try_into();
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &value);
    }

    pub fn clamp_case(env: Env, token_id: Address, to: Address, amount: i128) {
        let value = amount.clamp(0, 100);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &value);
    }

    pub fn min_case(env: Env, token_id: Address, to: Address, amount: i128) {
        let value = amount.min(100);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &value);
    }

    pub fn max_case(env: Env, token_id: Address, to: Address, amount: i128) {
        let value = amount.max(0);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &value);
    }

    pub fn validate_amount_case(env: Env, token_id: Address, to: Address, amount: i128) {
        let value = validate_amount(&env, amount);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &value);
    }

    pub fn checked_amount_case(env: Env, token_id: Address, to: Address, amount: i128) {
        let value = checked_amount(&env, amount);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &value);
    }

    pub fn verified_amount_case(env: Env, token_id: Address, to: Address, amount: i128) {
        let value = verified_amount(&env, amount);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &value);
    }
}
