use serde::{Deserialize, Serialize};

/// A split payment request distributing a total amount across multiple recipients.
/// v0.1: Data structure only — not routed or executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitPaymentRequest {
    pub version: u32,
    pub total_amount_sats: u64,
    pub splits: Vec<SplitRecipient>,
    pub memo: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitRecipient {
    pub alias: String,
    pub percent: u8,
}

impl SplitPaymentRequest {
    /// Validate that percentages sum to 100 and all aliases are valid.
    pub fn validate(&self) -> crate::Result<()> {
        let total: u16 = self.splits.iter().map(|s| s.percent as u16).sum();
        if total != 100 {
            return Err(crate::SatsPathError::InvalidPaymentPointer(format!(
                "split percentages sum to {total}, expected 100"
            )));
        }
        if self.splits.is_empty() {
            return Err(crate::SatsPathError::InvalidPaymentPointer(
                "split payment requires at least one recipient".into(),
            ));
        }
        for split in &self.splits {
            if split.percent == 0 {
                return Err(crate::SatsPathError::InvalidPaymentPointer(format!(
                    "split for '{}' has 0%",
                    split.alias
                )));
            }
            crate::privacy::validate_ascii_identifier(&split.alias)?;
        }
        Ok(())
    }

    /// Calculate individual amounts from the total (integer rounding).
    pub fn amounts(&self) -> Vec<(&str, u64)> {
        self.splits
            .iter()
            .map(|s| {
                let amount = self.total_amount_sats * u64::from(s.percent) / 100;
                (s.alias.as_str(), amount)
            })
            .collect()
    }
}
