use satspath_core::PaymentMethod;

use crate::fees::FeeEstimate;

/// Apply the protocol-specified safety margin to a raw fee rate.
/// `selected_feerate = max(raw + ceil(raw * 0.10), 1)`
pub fn apply_fee_safety_margin(raw_sat_vb: u64) -> u64 {
    let margin = raw_sat_vb.div_ceil(10); // ceil(raw * 0.10)
    std::cmp::max(raw_sat_vb + margin, 1)
}

/// Estimate on-chain fee in sats for a standard P2WPKH transaction (~141 vBytes).
pub fn estimate_onchain_fee_sats(fee_rate_sat_vb: u64) -> u64 {
    141 * apply_fee_safety_margin(fee_rate_sat_vb)
}

/// Check whether an on-chain address is available in the method list.
pub fn is_onchain_available(methods: &[PaymentMethod]) -> bool {
    methods
        .iter()
        .any(|m| matches!(m, PaymentMethod::Onchain { .. }))
}

/// Find the first available on-chain method.
pub fn first_onchain_method(methods: &[PaymentMethod]) -> Option<&PaymentMethod> {
    methods
        .iter()
        .find(|m| matches!(m, PaymentMethod::Onchain { .. }))
}

/// On-chain is viable only if the hour fee is cheap (<= 10 sat/vB).
///
/// We use `hourFee` to match the protocol specification: on-chain is
/// selected when the 1-hour confirmation fee is <= 10 sat/vB.
///
/// Threshold: 10 sat/vB — matches protocol spec for "cheap" on-chain.
pub fn is_onchain_fee_acceptable(estimate: &FeeEstimate) -> bool {
    estimate.hour_fee <= 10
}
