#![no_main]

use libfuzzer_sys::fuzz_target;
use satspath_core::crypto::{sign_profile, verify_signed_profile};
use satspath_core::profile::PaymentProfile;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

fuzz_target!(|data: &[u8]| {
    if let Ok(mut profile) = serde_json::from_slice::<PaymentProfile>(data) {
        let key = SecretKey::from_slice(&[1; 32]).unwrap();
        profile.identity_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &key).to_string();
        if let Ok(signed) = sign_profile(profile, &key) {
            assert!(verify_signed_profile(&signed).unwrap());
            let mut modified = signed.clone();
            modified.profile.methods.clear();
            modified.profile.alias.push('x');
            assert!(!verify_signed_profile(&modified).unwrap_or(false));
            let mut changed_sig = signed;
            changed_sig.signature = "00".repeat(64);
            assert!(!verify_signed_profile(&changed_sig).unwrap_or(false));
        }
    }
});
