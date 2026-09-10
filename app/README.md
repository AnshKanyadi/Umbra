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
