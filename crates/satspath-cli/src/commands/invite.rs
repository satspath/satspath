use anyhow::Result;

use satspath_core::{create_invite, privacy::mask_identifier};

use super::open_registry;

pub async fn cmd_invite(alias: &str, amount_sats: u64) -> Result<()> {
    let registry = open_registry()?;

    if registry.is_registered(alias) {
        println!(
            "'{}' is already registered on SatsPath. Use `satspath pay` instead.",
            mask_identifier(alias)
        );
        return Ok(());
    }

    let invite = create_invite(alias, amount_sats, None, 24 * 3600);

    println!(
        "'{}' is not registered on SatsPath.",
        mask_identifier(alias)
    );
    println!();
    println!("Invite link (Non-custodial Intent):");
    println!("{}", invite.claim_url);
    println!();
    println!("Alias hash:  {}", invite.alias_hash);
    println!("Amount:      {} sats", invite.amount_sats);
    println!("Created at:  {}", invite.created_at);
    println!();
    println!("WARNING: {}", invite.warning);

    Ok(())
}
