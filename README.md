<p align="center">
  <img src="https://raw.githubusercontent.com/georgekimaninjoroge/Sentinel/main/banner.png" alt="Sentinel" width="100%"/>
</p>

<p align="center">
  <img src="https://img.shields.io/npm/v/sentinel-jwt?style=flat-square&color=EF9F27&labelColor=1a1814" alt="npm version"/>
  <img src="https://img.shields.io/npm/dm/sentinel-jwt?style=flat-square&color=EF9F27&labelColor=1a1814" alt="npm downloads"/>
  <img src="https://img.shields.io/badge/license-MIT-EF9F27?style=flat-square&labelColor=1a1814" alt="MIT license"/>
  <img src="https://img.shields.io/badge/zero_dependencies-✓-EF9F27?style=flat-square&labelColor=1a1814" alt="zero dependencies"/>
  <img src="https://img.shields.io/badge/Web_Crypto_API-native-EF9F27?style=flat-square&labelColor=1a1814" alt="Web Crypto API"/>
  <img src="https://img.shields.io/badge/AES--256--GCM-encrypted-EF9F27?style=flat-square&labelColor=1a1814" alt="AES-256-GCM"/>
</p>

<p align="center">
  Zero-dependency browser JWT security. Vanilla JS + Web Crypto API.
</p>

---

## Install

```bash
npm install sentinel-jwt
```

Or import directly (no bundler):

```html
<script type="module">
  import Sentinel from "https://cdn.jsdelivr.net/npm/sentinel-jwt/sentinel.js";
</script>
```

---

## What it does

Sentinel protects JWTs in the browser without any npm packages. It fingerprints the device, encrypts the token with AES-256-GCM using a key derived from that fingerprint, signs it with HMAC-SHA256, and queues token refresh via Service Worker — even offline.

| Feature | How |
|---|---|
| Token fingerprinting | SHA-256 hash of screen / timezone / UA / hardware signals |
| Encrypted storage | AES-256-GCM, key derived via PBKDF2(fingerprint) |
| Tamper detection | HMAC-SHA256 MAC stored alongside token |
| Offline refresh | Background Sync API + postMessage fallback |

---

## File map

```
sentinel/
  fingerprint.js     device fingerprint (SHA-256 of browser signals)
  crypto-store.js    AES-256-GCM IndexedDB storage
  tamper.js          HMAC-SHA256 sign + verify
  refresh-worker.js  Service Worker (offline queue + broadcast)
  sentinel.js        orchestrator — import this
```

---

## Quick start

```js
import Sentinel from "sentinel-jwt";

// 1. Boot — register Service Worker
await Sentinel.init();

// 2. After login — store token
await Sentinel.storeToken("access_token", jwtString);

// 3. Every request — read + verify
const token = await Sentinel.getToken("access_token");
if (!token) { /* tampered / wrong device → re-auth */ }

// 4. Trigger refresh (works offline — queues and fires on reconnect)
await Sentinel.queueRefresh();

// 5. Logout
await Sentinel.removeToken("access_token");
```

---

## Server-side binding

Attach the fingerprint as a JWT claim at login:

```js
const fp = await Sentinel.getFingerprint();
// POST /login  body: { username, password, fingerprint: fp }
```

Validate on every request:

```python
# pseudocode
if token.claims["fpHash"] != sha256(request_fingerprint):
    raise Unauthorized("Device mismatch")
```

---

## Security notes

- AES-GCM IV is random per write — same token stored twice = different ciphertext
- PBKDF2 iterations: 100k (encrypt), 50k (HMAC) — slow brute-force
- Tamper detection purges corrupted entries automatically
- Service Worker broadcasts new token to all tabs after refresh
- Fingerprint is not biometric — no PII stored

---

## Browser support

| Browser | Minimum version |
|---|---|
| Chrome | 60+ |
| Firefox | 57+ |
| Safari | 11.1+ |
| Edge | 79+ |

> **Background Sync** (optional): Chrome/Edge only. postMessage fallback handles all other browsers automatically.

---

## License

MIT © [George Kimani Njoroge](https://github.com/georgekimanjoroge)
