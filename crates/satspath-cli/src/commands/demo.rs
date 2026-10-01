use anyhow::Result;
use satspath_core::privacy::mask_identifier;

use super::{cmd_decode, cmd_init, cmd_invite, cmd_pay, cmd_quote, cmd_register, cmd_show};

pub async fn cmd_demo() -> Result<()> {
    println!("══════════════════════════════════════════════════");
    println!("  SatsPath — Full Demo Flow");
    println!("══════════════════════════════════════════════════");
    println!();

    step(1, "Initialize SatsPath");
    cmd_init()?;
    println!();

    step(2, "Register r***@satspath.dev");
    // Re-registration is idempotent for demo — if already registered, show message.
    cmd_register("rodrigo@satspath.dev", None, None, None, None).await?;
    println!();

    step(3, "Show signed profile");
    cmd_show("rodrigo@satspath.dev", false).await?;
    println!();

    step(
        4,
        "Encode universal payment request (21,000 sats, memo: coffee)",
    );
    let uri = satspath_core::codec::encode_payment_request(
        "rodrigo@satspath.dev",
        Some(21_000),
        Some("coffee"),
        None,
    )?;
    println!("URI: {}", uri);
    println!();

    step(5, "Decode payment request");
    cmd_decode(&uri)?;
    println!();

    step(6, "Get route quote for 21,000 sats");
    cmd_quote("rodrigo@satspath.dev", 21_000).await?;
    println!();

    step(7, "Preview payment route for 21,000 sats");
    cmd_pay(
        "rodrigo@satspath.dev",
        21_000,
        None,
        false,
        false,
        false,
        false,
    )
    .await?;
    println!();

    step(8, "Try paying an unknown user (j***@example.com)");
    println!(
        "Attempting to pay {}...",
        mask_identifier("julian@example.com")
    );
    let registry = super::open_registry()?;
    if registry.is_registered("julian@example.com") {
        println!(
            "{} is already registered.",
            mask_identifier("julian@example.com")
        );
    } else {
        println!(
            "{} is not registered. Generating invite...",
            mask_identifier("julian@example.com")
        );
        println!();

        step(9, "Generate invite link for j***@example.com");
        cmd_invite("julian@example.com", 21_000).await?;
    }

    println!();
    println!("══════════════════════════════════════════════════");
    println!("  Demo complete.");
    println!("══════════════════════════════════════════════════");
    println!();
    println!("Next steps:");
    println!("  satspath register <your-alias>");
    println!("  satspath pay <alias> <amount_sats>");
    println!("  satspath invite <unregistered@example.com> <amount>");
    Ok(())
}

fn step(n: u32, title: &str) {
    println!("──────────────────────────────────────────────────");
    println!("Step {}: {}", n, title);
    println!("──────────────────────────────────────────────────");
}
