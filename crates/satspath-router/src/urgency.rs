use serde::{Deserialize, Serialize};

use crate::fees::FeeEstimate;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PaymentUrgency {
    Urgent,
    Commercial,
    #[default]
    Normal,
    Economy,
}

impl PaymentUrgency {
    /// Map urgency to the appropriate fee-rate tier from a `FeeEstimate`.
    pub fn select_fee_rate(&self, estimate: &FeeEstimate) -> u64 {
        match self {
            PaymentUrgency::Urgent => estimate.fastest_fee,
            PaymentUrgency::Commercial => estimate.half_hour_fee,
            PaymentUrgency::Normal => estimate.hour_fee,
            PaymentUrgency::Economy => estimate.economy_fee,
        }
    }

    pub fn expected_confirmation(&self) -> &'static str {
        match self {
            PaymentUrgency::Urgent => "~10 minutes (next block)",
            PaymentUrgency::Commercial => "~30 minutes",
            PaymentUrgency::Normal => "~1 hour",
            PaymentUrgency::Economy => "~2+ hours",
        }
    }
}
