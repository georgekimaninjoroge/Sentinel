import Fingerprint from "./fingerprint.js";

const Tamper = (() => {

  const HMAC_KEY_SALT = "sentinel_tamper_v1";



  async function _deriveHmacKey(fingerprint) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(fingerprint + HMAC_KEY_SALT),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: enc.encode(HMAC_KEY_SALT),
        iterations: 50_000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
  }



  async function _sign(data, key) {
    const enc = new TextEncoder();
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
    return btoa(String.fromCharCode(...new Uint8Array(sig)));
  }

  async function _verify(data, b64Sig, key) {
    const enc = new TextEncoder();
    const sigBuf = Uint8Array.from(atob(b64Sig), c => c.charCodeAt(0));
    return crypto.subtle.verify("HMAC", key, sigBuf, enc.encode(data));
  }



    async function sign(token) {
    const fp = await Fingerprint.get();
    const key = await _deriveHmacKey(fp);
    return _sign(token, key);
  }

    async function verify(token, mac) {
    try {
      const fp = await Fingerprint.get();
      const key = await _deriveHmacKey(fp);
      return await _verify(token, mac, key);
    } catch {
      return false;
    }
  }

  return { sign, verify };
})();

export default Tamper;