use async_trait::async_trait;

use crate::resolver::ProfileResolver;
use crate::{Result, SatsPathError, SignedPaymentProfile};

pub struct PlatformApiResolver {
    pub base_url: String,
}

#[async_trait]
impl ProfileResolver for PlatformApiResolver {
    async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile> {
        let _ = &self.base_url;
        Err(SatsPathError::AliasNotFound(format!(
            "platform API resolver scaffold only: {alias}"
        )))
    }
}
