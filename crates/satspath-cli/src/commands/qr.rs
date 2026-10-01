use anyhow::Result;
use qrcode::render::unicode;
use qrcode::QrCode;

pub fn print_qr(data: &str) -> Result<()> {
    let code =
        QrCode::new(data.as_bytes()).map_err(|e| anyhow::anyhow!("QR encode error: {}", e))?;
    let image = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Dark)
        .light_color(unicode::Dense1x2::Light)
        .quiet_zone(true)
        .build();
    println!("{}", image);
    Ok(())
}

/// BIP-21 Bitcoin URI: `bitcoin:<address>?amount=<btc>`
pub fn bitcoin_uri(address: &str, amount_sats: u64) -> String {
    let btc = amount_sats as f64 / 100_000_000.0;
    format!("bitcoin:{}?amount={:.8}", address, btc)
}
