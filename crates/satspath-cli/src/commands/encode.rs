use anyhow::Result;

use satspath_core::{
    codec::{decode_payment_request, encode_payment_request},
    privacy::mask_identifier,
};

pub fn cmd_encode(alias: &str, amount_sats: u64, memo: Option<&str>) -> Result<()> {
    let uri = encode_payment_request(alias, Some(amount_sats), memo, None)?;
    println!("Encoded SatsPath URI:");
    println!("{}", uri);
    Ok(())
}

pub fn cmd_decode(uri: &str) -> Result<()> {
    let req = decode_payment_request(uri)?;
    println!("Decoded payment request:");
    println!("  Version:     {}", req.version);
    println!("  Alias:       {}", mask_identifier(&req.alias));
    println!(
        "  Amount:      {}",
        req.amount_sats
            .map(|a| format!("{} sats", a))
            .unwrap_or_else(|| "not specified".into())
    );
    println!("  Memo:        {}", req.memo.as_deref().unwrap_or("(none)"));
    println!(
        "  Profile hint:{}",
        req.profile_hint.as_deref().unwrap_or("(none)")
    );
    Ok(())
}
