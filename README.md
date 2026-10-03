# crypto-core

Platform-agnostic signing logic for [corisco-wallet](https://github.com/corisco-wallet/corisco-wallet)'s
ESP32 hardware signer: BIP32 derivation, BIP39 mnemonic handling, ECDSA/
Schnorr signing, FROST threshold signing, and the leaf-ownership-transfer
"key tweak" crypto (Feldman VSS + ECIES) Spark's protocol needs.

Pure Rust, no hardware dependency by default -- builds and tests on any
normal host. `corisco-wallet`'s firmware wraps this crate to run the same
logic on real hardware.

## Feature flags

| Feature | What it adds | When you need it |
|---|---|---|
| `hw-sha512` | Routes BIP39's PBKDF2-HMAC-SHA512 through ESP-IDF's hardware SHA accelerator | On-device only -- pure software takes ~25s and trips the watchdog |
| `seed-lock` | AES-256-GCM encryption of the seed at rest, keyed by a PIN via PBKDF2 | Anywhere a seed needs to be persisted behind a PIN |
| `transfer-crypto` | Feldman VSS secret splitting + ECIES, for Spark's leaf-ownership-transfer key tweak | Claiming/sending leaf-swap payments |

None are enabled by default; a consumer picks what it needs.

## Building and testing

```bash
cargo test --features seed-lock,transfer-crypto
cargo clippy --features seed-lock,transfer-crypto --all-targets -- -D warnings
cargo fmt --check
```

Not `--all-features`: `hw-sha512` depends on `esp-idf-sys`, which only
builds against the ESP-IDF/Xtensa target, not a plain host. Everything
else here is host-testable -- no cross-compilation toolchain needed.

## Where this is used

See [corisco-wallet](https://github.com/corisco-wallet/corisco-wallet)'s
`docs/architecture.md` for how this fits into the full signing flow
(mobile app <-> BLE <-> ESP32 signer).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
