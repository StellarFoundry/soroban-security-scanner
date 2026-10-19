//! Built-in security rules (detectors).
//!
//! Each detector documents the problem it addresses, the evidence it relies on,
//! its limitations, and its known false positives. Detectors must be
//! deterministic and must only report findings backed by concrete evidence.
//!
//! Detector documentation lives in `docs/rules/detectors/`.

pub mod util;
pub mod validation;

mod cross_contract_auth;
mod cross_contract_before_state_update;
mod hardcoded_address;
mod insecure_randomness;
mod missing_authorization;
mod panic_prone;
mod public_test_hooks;
mod token_transfer_amount;
mod ttl_management;
mod unbounded_iteration;
mod unchecked_arithmetic;
mod unprotected_initializer;
mod unsafe_code;

#[cfg(test)]
pub mod test_support;

use crate::registry::{RegistryError, RuleRegistry};

/// Registers every built-in rule with the registry.
pub fn register_all(registry: &mut RuleRegistry) -> Result<(), RegistryError> {
    registry.register(Box::new(missing_authorization::MissingAuthorization))?;
    registry.register(Box::new(cross_contract_auth::CrossContractAuth))?;
    registry.register(Box::new(unbounded_iteration::UnboundedIteration))?;
    registry.register(Box::new(panic_prone::PanicProne))?;
    registry.register(Box::new(unsafe_code::UnsafeCode))?;
    registry.register(Box::new(ttl_management::TtlManagement))?;
    registry.register(Box::new(hardcoded_address::HardcodedAddress))?;
    registry.register(Box::new(unchecked_arithmetic::UncheckedArithmetic))?;
    registry.register(Box::new(insecure_randomness::InsecureRandomness))?;
    registry.register(Box::new(public_test_hooks::PublicTestHooks))?;
    registry.register(Box::new(unprotected_initializer::UnprotectedInitializer))?;
    registry.register(Box::new(
        cross_contract_before_state_update::CrossContractBeforeStateUpdate,
    ))?;
    registry.register(Box::new(token_transfer_amount::TokenTransferAmount))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::registry::RuleRegistry;

    #[test]
    fn default_registry_contains_all_detectors() {
        let registry = RuleRegistry::with_default_rules();
        let ids: Vec<_> = registry.metadata_sorted().iter().map(|m| m.id).collect();
        assert_eq!(
            ids,
            vec![
                "SS-001", "SS-002", "SS-003", "SS-004", "SS-005", "SS-006", "SS-007", "SS-008",
                "SS-009", "SS-011", "SS-013", "SS-014", "SS-029"
            ]
        );
    }
}
