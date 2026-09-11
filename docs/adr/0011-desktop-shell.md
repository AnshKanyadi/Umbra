# ADR 0011: Tauri, and signing proved before any UI exists

- Status: accepted
- Date: 2026-09-10

## Context

Phase 6 targets someone who cannot use a terminal. That person downloads an app,
double-clicks it, and either it opens or they delete it. Two decisions had to be
made before any interface was worth designing: what the shell is, and whether
the app can be distributed at all.

Signing and notarization were done **first, on a window that does nothing**.
They are the step with the least to show for themselves and the most capacity to
eat unexpected days, and finding that out in week one is worth more than a
prototype that cannot ship.

## Tauri, not Electron

Electron bundles Chromium: about 150 MB before any application code. A tool
whose pitch is "local, small, no cloud" that arrives as a 150 MB download has
argued against itself on the download page.

Tauri uses the system webview -- WKWebView here -- and calls out to a binary.
That matters more for this project than for most, because the binary already
exists: `umbra_ai` is 5.3 MB and links nothing but `libc++` and system
frameworks, so there are no dylibs to bundle and no rpath surgery. Tauri's
sidecar mechanism is built for exactly that shape.

**Measured, for the stub:**

| | |
|---|---|
| `Umbra.app` | **3.8 MB** |
| `Umbra_0.0.1_aarch64.dmg` | **1.2 MB** |
| incremental rebuild after touching `main.rs` | 59s |
| first build | ~5 minutes, 84 crates |
| `src-tauri/target` on disk | **773 MB** |

The 773 MB is the honest cost of a Rust toolchain and it never leaves the
machine; the thing users download is 1.2 MB plus whatever the app grows to.

The price is Rust, which is a new language in this project. In practice almost
none gets written: the sidecar pattern makes commands thin wrappers around a
process. `src-tauri/src/main.rs` in this stub is nine lines.

## What signing and notarization actually took

Everything needed was already present, which is the useful finding:

- a **Developer ID Application** certificate in the keychain (the Apple
  Developer Program at $99/yr, already paid)
- `notarytool` and `stapler`, which ship with Xcode

Tauri does the signing itself when `APPLE_SIGNING_IDENTITY` is set. It produced,
with no extra configuration:

```
Authority=Developer ID Application: Ansh Kanyadi (7XN53CFB52)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
CodeDirectory flags=0x10000(runtime)
Timestamp=Sep 10, 2026 at 4:56:16 PM
```

Hardened runtime and a secure timestamp are both prerequisites for
notarization, and both came for free. `codesign --verify --deep --strict` says
`valid on disk` and `satisfies its Designated Requirement`.

**And Gatekeeper still refuses it:**

```
$ spctl -a -t exec -vvv Umbra.app
Umbra.app: rejected
source=Unnotarized Developer ID
```

That line is why this was done first. A correctly signed app from a paid
developer account is still rejected on another person's machine. Signing is
necessary and is not sufficient; notarization is not a polish step.

## The loop, closed and timed

Submitted, accepted, stapled, and Gatekeeper now says yes:

```
$ xcrun notarytool submit Umbra_0.0.1_aarch64.dmg --keychain-profile umbra --wait
  status: Accepted                                   # 23 seconds, round trip

$ xcrun stapler staple Umbra_0.0.1_aarch64.dmg
The staple and validate action worked!

$ spctl -a -t open --context context:primary-signature -vvv Umbra_0.0.1_aarch64.dmg
accepted
source=Notarized Developer ID
```

**23 seconds.** Fast enough that notarization belongs in CI rather than in
someone's memory, and `.github/workflows/release.yml` now does it on a tag. It
uses an App Store Connect API key rather than a keychain profile, because a
runner has no keychain and no person to have stored one, and because a key is
scoped and revocable on its own in a way an Apple ID password is not.

The certificate is imported into a throwaway keychain with a random password and
deleted in an `always()` step, so a signing identity is never left behind on a
shared runner.

**STAPLE THE APP, NOT ONLY THE DISK IMAGE.** Stapling the DMG leaves the bundle
inside it without a ticket:

```
$ xcrun stapler validate Umbra.app
Umbra.app does not have a ticket stapled to it.
```

It still passes Gatekeeper while the DMG is mounted, because the check can go
online or read the image's ticket -- so this is invisible in testing and
appears on someone else's machine, offline, after they have dragged the app to
Applications. `stapler` will attach a ticket to the `.app` directly once the
submission is accepted; both were stapled here and both validate.

The release order is therefore: build signed, submit, staple the `.app`, staple
the `.dmg`, verify both with `spctl`.

## What notarization needs

Credentials are deliberately not in this repository. One of:

- an **app-specific password** from appleid.apple.com, plus the Apple ID and
  team id, stored once with `xcrun notarytool store-credentials`, or
- an **App Store Connect API key** (`.p8` plus key id and issuer id), which is
  the better choice for CI because it is scoped and revocable

Stapling is what makes the app open on a machine that is offline or has never
seen it before.

## Consequences

- **macOS only in v1.** Windows adds a code-signing certificate (a few hundred
  a year, or Azure Trusted Signing) or SmartScreen warns on every download.
  Linux adds AppImage packaging and WebKitGTK version differences. Neither is
  hard; both are surface before anyone has asked for them.
- **No auto-update in v1.** Tauri's updater needs its own signing key and a
  hosted manifest. Manual download until there is something worth updating.
- **The stub stays.** It is the thing to reach for when a signing or packaging
  question comes up, because it builds in a minute and cannot itself be at
  fault.
- **`gen/schemas` and `target/` are ignored**, and `.gitignore` gained a
  `target/` rule that is unanchored on purpose: cargo makes one wherever it is
  invoked, and a rule pinned to `app/src-tauri/target` would fail open the first
  time a second crate appears.
