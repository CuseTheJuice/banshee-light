# Banshee Light

Windows companion for a Banshee board (LilyGO T-Display S3). Light holds the oracle key and wrap share. The device holds the wrapped 64-byte BIP39 seed. Both are required to sign.

**Apache License 2.0.** Based on [Sparrow Wallet](https://github.com/sparrowwallet/sparrow), [Lark](https://github.com/sparrowwallet/lark), and [Drongo](https://github.com/sparrowwallet/drongo).

Current release: **1.3.4** (pairs with firmware **0.1.66**).

## About this repository

This is the published source for Banshee Light, here so the wallet can be read and audited.

It is source only. Build files, packaging templates, and installer tooling are deliberately not included, so this tree does not compile as-is and cannot produce an installer. The signed Windows installer is sold separately on the Banshee Light site. This repository does not publish installers.

Banshee Light installs separately from production Banshee Desktop. Do not mix config directories.

## What it does

1. **Connect** — USB, or Scan Bluetooth and pick the name that matches the ID on the screen. USB power is enough for Bluetooth; Light will not steal the USB serial port just because a charge cable is plugged in. Flashing firmware still needs USB.
2. **Unlock** — 6–12 left/right presses, both sides. Screen unlock only. Three failures wipe the device. Not part of the backup.
3. **Dice** — 100 on-device d6 rolls. Chip RNG makes the hidden 24-word seed (never shown). Dice entropy is the BIP39 passphrase. After the roll the device shows 12 five-digit codes (3 screens × 4). Write those down and keep them away from the backup file.
4. **Backup** — `.banshee-backup` (format v7: clone seed + oracle, sealed with SHA-256 of the 12 dice codes). Older word-sealed backups still open.
5. **Restore** — device, oracle, or both. Restore oracle from the original Light's backup, then unlock with that board's screen sequence.
6. **Sign** — USB or Bluetooth `SIGN_PSBT`.
7. **Flash** — bundled firmware **0.1.66**. Studio Secure Boot boards: choose the original `.pem` to update app firmware only. New unfused chips: unsigned bins to bootloader PID `1001`. A blank fused board is recovered in Studio Full reflash, not Light.

**Light** wallets are singlesig P2WPKH. **Vault** 2-of-3 is still available from New Wallet.

In the app, everything above lives under File → Set up Banshee.

## Layout

| Path | Contents |
| --- | --- |
| `src/` | The JavaFX desktop application, resources, and tests |
| `drongo/` | Bitcoin library (Sparrow's Drongo, forked) |
| `lark/` | Hardware wallet library (Sparrow's Lark, forked), including the Banshee USB and BLE clients |
| `scripts/` | USB device diagnostics |

Signed flash uses in-process RSA-3072 Secure Boot v2. Flashing itself uses the bundled `espflash`.

## Bundled binaries

This repo ships prebuilt binaries it needs at runtime: `espflash`, `libbwt_jni`, `libsecp256k1`, the `banshee-ble` BLE helper, and the 0.1.66 firmware images under `src/main/resources/firmware/`. Confirm they match the recorded hashes:

```bash
sha256sum -c SHA256SUMS.txt
```

A mismatch means a binary was changed after release — do not flash or run it.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Security

See [SECURITY.md](SECURITY.md). Do not file security issues in the public tracker.
