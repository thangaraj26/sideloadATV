<div align="center">

# sideloadATV

**Sideload IPAs onto an Apple TV from Android — over Wi-Fi, no computer, no cable.**

Sign in with an Apple ID, pair with an Apple TV on your network, pick an `.ipa`,
and it's re-signed with your account and installed wirelessly.

</div>

---

## What it does

sideloadATV is a native Android app that reproduces the AltStore/Impactor sideloading
flow, but targets **tvOS over the network** instead of iOS over USB. Everything runs
on the phone:

- 🔎 **Discovery** — finds Apple TVs on the local network via mDNS (`NsdManager` + a multicast lock).
- 🔐 **Apple ID login** — GrandSlam authentication (SRP-6a) with 2FA support.
- 🤝 **Pairing** — modern RemoteXPC pairing with a PIN shown on the TV, then a TLS-PSK tunnel.
- ✍️ **Re-signing** — registers the device with Apple's Developer API as a **tvOS** device, provisions a certificate + profile, and codesigns the IPA against your team — all on-device.
- 📲 **Wireless install** — uploads the signed IPA over AFC and installs it through `installation_proxy`, across the pairing tunnel.
- ⏱️ **Expiry tracking** — free Apple accounts get a 7-day signing window; the app tracks each installed app's expiry and offers a one-tap **Refresh** (re-sign + re-install without re-picking the file).

> **Free vs. paid Apple accounts.** A free Apple ID works but imposes Apple's usual
> limits: apps expire after 7 days, and there's a cap on active app IDs / registered
> devices. A paid Developer account lifts the 7-day window.

## Architecture

A Kotlin/Compose UI over a Rust core, bridged by [UniFFI]. The heavy protocol work
(Apple auth, pairing, signing, the userspace TCP tunnel) lives in Rust and is compiled
to a single `.so`; the generated Kotlin bindings call into it via JNA.

```
app/                         Android app (Kotlin, Jetpack Compose, Material 3)
 └─ src/main/java/com/darkshadow/sideloadatv/
      discovery/             mDNS device discovery + device list
      auth/                  GrandSlam login UI + account storage
      pairing/               device detail, pairing, install flow
      ui/                    theme + shared Compose components
rust/
 ├─ ffi/                     UniFFI surface: auth, pairing, tunnel, signing, install, store
 └─ vendor/                  vendored + patched dependencies (see Credits)
```

**Why Rust + a vendored dependency tree.** The Apple-side protocols only have mature,
correct implementations in the Rust sideloading ecosystem (`idevice`, PlumeImpactor).
Rather than reimplement SRP auth, RemoteXPC pairing, and Mach-O codesigning in Kotlin,
the app reuses those crates. Several had to be **vendored and patched** to cross-compile
to Android and to target tvOS rather than iOS — each `rust/vendor/*/Cargo.toml` documents
exactly what was changed and why. Notably:

- **tvOS device type** — patched `plume_core` to send `DTDK_Platform: tvos` so Apple issues tvOS-valid device records and provisioning profiles (not iOS ones).
- **Android cross-compilation** — swapped `native-tls`/OpenSSL for `rustls`, replaced a deleted `srp` git fork with the upstream RustCrypto crate, and inlined workspace fields.
- **Large-transfer reliability** — vendored `jktcp` to raise the retransmit give-up threshold, so 100 MB+ IPAs survive multi-second Apple TV stalls mid-upload; the negotiated tunnel MTU is now applied to the TCP MSS.

## Building

**Prerequisites**

- Android Studio (compileSdk 36) and an Android device on **API 35+** (`minSdk = 35`).
- A Rust toolchain with the Android target and [`cargo-ndk`]:
  ```sh
  rustup target add aarch64-linux-android
  cargo install cargo-ndk uniffi-bindgen
  ```

**1. Build the native library** (arm64 shown; add other ABIs as needed):

```sh
cd rust
cargo ndk -t arm64-v8a -o ../app/src/main/jniLibs build --release -p sideloadatv-ffi
```

**2. Regenerate the Kotlin bindings** — only needed when the Rust FFI surface changes:

```sh
cargo run -p sideloadatv-ffi --bin uniffi-bindgen -- generate \
  --library ../app/src/main/jniLibs/arm64-v8a/libsideloadatv_ffi.so \
  --language kotlin --out-dir ../app/src/main/java
```

**3. Build the app** from Android Studio, or:

```sh
./gradlew :app:assembleDebug
```

> The compiled `.so` and `rust/target/` are git-ignored — clone, then run steps 1–3.

## Usage

1. Put your phone and Apple TV on the **same Wi-Fi network**.
2. Open the app → your Apple TV appears in the device list.
3. Sign in with your Apple ID (enter the 2FA code if prompted).
4. Tap the device → **Pair**, and enter the PIN shown on the TV.
5. **Install IPA…**, pick a file. It's signed and installed wirelessly.
6. Track expiry from the device screen; **Refresh** re-signs before the 7 days run out.

## Status

Working end-to-end on a real Apple TV: discovery → login → pairing → signing → wireless
install, with expiry tracking and refresh. Known gaps: no multi-team picker yet (uses the
first team on the account); tested primarily on arm64 hardware.

## ⚠️ Disclaimer

This is an independent project for **personal, lawful use** — installing software you have
the right to install onto hardware you own. It is not affiliated with, authorized, or
endorsed by Apple. "Apple TV", "tvOS", and "Apple ID" are trademarks of Apple Inc. Use
your own Apple ID at your own risk; sideloading may violate Apple's terms of service.

## Credits

This project stands on the shoulders of the Rust sideloading community. Vendored copies
(with local patches) live in `rust/vendor/`; upstream authors and licenses:

| Component | Upstream | Author(s) | License |
|---|---|---|---|
| `idevice` — Apple device protocols (RemoteXPC pairing, AFC, installation_proxy) | [jkcoxson/idevice] | Jackson Coxson | — |
| `jktcp` — userspace TCP stack over the tunnel | [jkcoxson/jktcp] | Jackson Coxson | MIT |
| `plume_core` — GrandSlam auth + Apple Developer API + signing core | [BoardTM/PlumeImpactor] | khcrysalis (Samara M) | MPL-2.0 |
| `plume_utils` — IPA signing orchestration (bundle walk, codesign, re-zip) | [bitxeno/PlumeImpactor] | CLARATION | MIT |
| `apple-codesign` — Mach-O code signing | [PlumeImpactor/plume-apple-platform-rs] (fork of [indygreg/apple-platform-rs]) | Gregory Szorc et al. | Apache-2.0 |
| [UniFFI] — Rust ↔ Kotlin bindings | Mozilla | — | MPL-2.0 |

Inspired by the broader sideloading ecosystem: **AltStore/SideStore**, **PlumeImpactor**,
and **Impactor**. Huge thanks to everyone whose reverse-engineering made this possible.

## License

The application code in this repository is licensed under the [MIT License](LICENSE).
Vendored dependencies under `rust/vendor/` retain their **original licenses** (see the
`LICENSE` files there and the table above) — the MIT license covers only the first-party
code, not the vendored crates.

[UniFFI]: https://github.com/mozilla/uniffi-rs
[`cargo-ndk`]: https://github.com/bbqsrc/cargo-ndk
[jkcoxson/idevice]: https://github.com/jkcoxson/idevice
[jkcoxson/jktcp]: https://github.com/jkcoxson/jktcp
[BoardTM/PlumeImpactor]: https://github.com/BoardTM/PlumeImpactor
[bitxeno/PlumeImpactor]: https://github.com/bitxeno/PlumeImpactor
[PlumeImpactor/plume-apple-platform-rs]: https://github.com/PlumeImpactor/plume-apple-platform-rs
[indygreg/apple-platform-rs]: https://github.com/indygreg/apple-platform-rs
