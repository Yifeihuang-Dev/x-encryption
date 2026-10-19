# XEncryption

**Three-factor local file encryption that runs entirely in your browser.**

Password ‖ certificate file ‖ hardware key → one master key. AES-256-GCM, chunked streaming, zero network requests, zero dependencies.

> ⚠️ **Status: not independently audited.** The cryptographic primitives come from the browser's own Web Crypto API, but the container format, AAD construction and state machine were written for this project and have not been reviewed by a third party. Do not rely on it as the only protection for high-value assets — see [Security model](#security-model).

---

## Why three factors

Most file encryption tools ask for one thing: a password. That means the entire security of your data rests on how well a human picked and remembered a string.

XEncryption splits the key into three independent pieces:

```
k1 = PBKDF2-HMAC-SHA256(password, salt, 600,000)   ← something you know
k2 = certificate file contents (32 random bytes)   ← something you have
k3 = WebAuthn PRF output (Touch ID / YubiKey)      ← something you are / hold

master = HKDF-SHA256(k1 ‖ k2 ‖ k3)
```

The factors are **merged, not layered**. This matters: without the certificate file an attacker cannot even verify whether a guessed password is correct, because `k2` is missing from the derivation. **There is nothing to attack offline.**

---

## Features

| | |
|---|---|
| **Cipher** | AES-256-GCM, 1 MiB chunks, each with its own nonce and authentication tag |
| **Streaming** | Memory stays flat regardless of file size; writes to disk via File System Access API when available |
| **Certificate file** | 32 random bytes, printable text format, generated per file (or reused for many) |
| **Hardware key** | WebAuthn PRF — Touch ID, Windows Hello, and YubiKey share one code path |
| **Recovery code** | A full backup of factor 3, for lost devices or re-enrolled fingerprints |
| **Encrypted metadata** | File name, type and size are encrypted — not visible without the key |
| **Verify first** | A 48-byte block is decrypted before anything else; wrong keys are rejected immediately |
| **Bilingual** | English (default) and Chinese, switchable in the header |

---

## Quick start

```bash
git clone https://github.com/Yifeihuang-Dev/x-encryption.git
cd x-encryption
node serve.js          # or: python3 serve.py
# open http://localhost:8443/
```

**Why a local server instead of opening `index.html` directly?** WebAuthn requires a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts). `http://localhost` qualifies; `file://` does not. Nothing leaves your machine either way — the server only serves files from this directory.

### Encrypt

1. Drop a file (any type, any size)
2. Enter a password
3. **Choose where to save the certificate file** — the tool asks *before* encrypting, so you always know where it went
4. Optionally enable the hardware key; a recovery code is generated alongside it

### Decrypt

Drop the `.enc1` file → the tool tells you which factors it needs → supply them → done.

---

## Container format

```
[header 88+N] [verify 48] [metaLen 2] [meta N] [chunk0 .. chunkN-1]

header: magic "ENC1" | version | flags | kdfId | iterations | salt(16)
        certId(16) | credentialIdHash(16) | prfSalt(16) | nonceBase(7)
        chunkSizeLog2 | totalChunks | credentialIdLen | credentialId
```

Two properties worth pointing out:

- **The entire header is fed into every chunk's AAD.** Tampering with the salt, the iteration count, or the "certificate required" flag causes authentication to fail — no downgrade attacks.
- **Chunk index and total count are in the AAD as well.** Blocks cannot be reordered, truncated, or rolled back to an earlier version of a single file.

The header stores only a **fingerprint** (16 bytes) of the certificate, never key material — so a wrong certificate is reported instantly instead of after a full KDF run.

---

## Security model

| An attacker has… | Outcome | Why |
|---|---|---|
| The ciphertext only | ✅ Cannot open | No `k2` — nothing to verify guesses against |
| Ciphertext + certificate | ⚠️ Depends on password | Offline attack possible; see benchmark below |
| Ciphertext + certificate + your machine (locked) | ✅ Cannot open | `k3` never leaves the secure hardware |
| All three | ❌ Can open | True for every encryption tool |
| Your machine while running, with malware | ❌ Cannot help | Keyloggers and memory dumps defeat any userspace crypto |
| A quantum computer | ✅ Essentially safe | AES-256 under Grover: ~2¹²⁸ |

### Measured brute-force cost

Benchmarked on an Apple M2, all 8 cores saturated, against the real derivation code:

```
62.5 guesses/second   (600,000 PBKDF2 iterations per guess)
4-digit numeric password → cracked in 118 seconds
```

| Password | One M2 | 100× that (cloud / GPU cluster) |
|---|---|---|
| 6 digits | 4.4 hours | 2.6 minutes |
| 8 digits | 18.5 days | 4.4 hours |
| 8 lowercase | 106 years | ~1 year |
| 8 alphanumeric | 1,430 years | ~14 years |
| 10 alphanumeric | 1.8 million years | 18,000 years |
| 12 mixed + symbols | 2.7 × 10¹⁴ years | 2.7 × 10¹² years |

The benchmark script ships with the repo (`tests/crack-bench.mjs`) and runs against the same code path used for real decryption, so you can reproduce these numbers on your own hardware.

### Honest limitations

- **PBKDF2, not Argon2 or scrypt.** Web Crypto offers nothing better without pulling in a WASM dependency. This is the weakest technical choice in the project, and it is substantially mitigated by the certificate factor — but not eliminated.
- **JavaScript cannot fully wipe memory.** Secrets are zeroed after use, but intermediate values from `deriveBits` may linger until garbage collection.
- **No protection against malware on your own machine.** True for every userspace encryption tool; use full-disk encryption as the real defence.
- **Deleting the original on an SSD is not erasure.** Wear leveling can leave data behind. The tool says so rather than offering a fake "delete original" checkbox.
- **No PRF, no factor 3.** If a device lacks WebAuthn PRF, the hardware factor is **refused**, not silently downgraded. FIDO2's common ES256 signatures are randomised and cannot derive a stable key.

---

## What it deliberately does not do

- No network requests, no telemetry, no CDN — every asset is a local file
- No MD5 / DES / ECB / home-grown algorithms
- No back door: forgotten password + lost certificate = permanently locked out
- No X.509 chains, no self-extracting executables
- No compression before encryption (most files are already compressed; it would only waste CPU)

---

## Testing

```bash
npm test
```

29 assertions covering round-trips plus cases that **must** fail: wrong password, missing certificate, wrong certificate, wrong recovery code, tampered ciphertext, tampered header (KDF downgrade), truncated file, reordered chunks.

---

## Repository layout

```
index.html  styles.css
assets/X.png              logo
js/i18n.js                bilingual dictionary (English default)
js/crypto.js              KDF, three-factor HKDF merge, AES-GCM, nonce/AAD
js/container.js           .enc1 container: header, verify block, metadata, streaming
js/certfile.js            certificate files and recovery codes
js/webauthn.js            WebAuthn PRF factor
js/file-io.js             streaming writes, Blob fallback, drag & drop
js/app.js                 UI logic
serve.js  serve.py        local server
tests/smoke.mjs           core round-trip and attack tests
tests/crack-bench.mjs     brute-force benchmark
```

---

## License

MIT — see [LICENSE](LICENSE).
