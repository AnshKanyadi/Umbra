# The desktop app

A stub window, built first on purpose.

Signing and notarization are the step with the least to show for themselves and
the most capacity to eat days, so they are exercised here, in week one, against
an app that cannot itself be broken. The UI comes after. See
`docs/adr/0011-desktop-shell.md` for what was measured.

## Build

```sh
cd app
npm install
npm run build            # unsigned
```

Signed, with a Developer ID certificate in the keychain:

```sh
APPLE_SIGNING_IDENTITY="Developer ID Application: NAME (TEAMID)" npm run build
```

Notarization needs credentials that are not in the repository; see the ADR.

## The sidecar binaries

`src-tauri/binaries/` holds copies of the C++ binaries, named with the Rust
target triple as Tauri requires. They are build output and are not tracked.
Populate them from a cmake build before packaging:

```sh
cmake -S .. -B ../b-rel -DCMAKE_BUILD_TYPE=Release
cmake --build ../b-rel --target umbra_ai umbra_sync -j
TRIPLE=$(rustc -vV | awk '/host:/{print $2}')
cp ../b-rel/umbra_ai   src-tauri/binaries/umbra_ai-$TRIPLE
cp ../b-rel/umbra_sync src-tauri/binaries/umbra_sync-$TRIPLE
```

## The model

The embedding weights are not in the repository and not in the bundle; see
ADR 0010. Until the downloader exists, put the GGUF where the app looks:

```sh
mkdir -p ~/Library/Application\ Support/Umbra/models
cp all-minilm.gguf ~/Library/Application\ Support/Umbra/models/all-minilm-797b70c4.gguf
```

## Testing the download path

The model downloader is the only part of the install that needs the network, and
the only part that cannot be exercised by opening the app on the machine that
built it. `src/bin/dlcheck.rs` calls the same function the app calls:

```sh
cd /tmp && cp all-minilm.gguf . && python3 -m http.server 8731 &
cp all-minilm.gguf bad.gguf && printf 'x' | dd of=bad.gguf bs=1 seek=1000 conv=notrunc

UMBRA_MODEL_URL=http://127.0.0.1:8731/bad.gguf         cargo run --release --bin dlcheck
UMBRA_MODEL_URL=http://127.0.0.1:8731/all-minilm.gguf  cargo run --release --bin dlcheck
```

The first must refuse and leave no `.part` file; the second must install; a
third run must be a no-op.
