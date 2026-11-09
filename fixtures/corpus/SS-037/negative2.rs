#![no_std]
//! Documented multi-sig pattern: each signer authorizes a proposal hash across
//! a signer list or separate approval invocations rather than hardcoding
//! competing actor receivers in a single entry point.
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, IntoVal, Vec};

#[contract]
pub struct MultiSigTreasury;

#[contractimpl]
impl MultiSigTreasury {
    pub fn approve_proposal(env: Env, signer: Address, proposal_id: BytesN<32>) {
        signer.require_auth_for_args((&proposal_id,).into_val(&env));
        env.storage().persistent().set(&proposal_id, &signer);
    }

    pub fn execute_with_signers(env: Env, signers: Vec<Address>, payload: BytesN<32>) {
        for signer in signers.iter() {
            signer.require_auth_for_args((&payload,).into_val(&env));
        }
        env.storage().persistent().set(&payload, &true);
    }
}
