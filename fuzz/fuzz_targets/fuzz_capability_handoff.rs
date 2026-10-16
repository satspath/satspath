#![no_main]

use libfuzzer_sys::fuzz_target;
use satspath_core::profile::PaymentMethod;
use satspath_router::handoff::validate_payload;

fuzz_target!(|data: &[u8]| {
    if let Ok(method) = serde_json::from_slice::<PaymentMethod>(data) {
        let _ = method.ownership_descriptor();
        // No arbitrary method should panic while validating a bounded public
        // payload; validation errors must remain errors, not wallet calls.
        let _ = validate_payload(
            &method,
            "bitcoin:invalid?amount=0.00000001",
            "testnet",
            Some(1),
        );
        let _ = validate_payload(&method, "lntb1invalid", "regtest", Some(u64::MAX));
    }
});
