import Fingerprint from "./fingerprint.js";

const CryptoStore = (() => {

  const DB_NAME = "sentinel_store";
  const DB_VERSION = 1;
  const STORE_NAME = "tokens";
  const PBKDF2_ITERATIONS = 100_000;
  const SALT = "sentinel_v1_salt"; 



  function _openDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = e => {
        e.target.result.createObjectStore(STORE_NAME);
      };
      req.onsuccess = e => resolve(e.target.result);
      req.onerror = e => reject(e.target.error);
    });
  }

  function _dbPut(db, key, value) {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      tx.objectStore(STORE_NAME).put(value, key);
      tx.oncomplete = resolve;
      tx.onerror = e => reject(e.target.error);
    });
  }

  function _dbGet(db, key) {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const req = tx.objectStore(STORE_NAME).get(key);
      req.onsuccess = e => resolve(e.target.result ?? null);
      req.onerror = e => reject(e.target.error);
    });
  }

  function _dbDelete(db, key) {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      tx.objectStore(STORE_NAME).delete(key);
      tx.oncomplete = resolve;
      tx.onerror = e => reject(e.target.error);
    });
  }



  async function _deriveKey(fingerprint) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(fingerprint),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: enc.encode(SALT),
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }



  async function _encrypt(plaintext, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const cipherBuf = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      enc.encode(plaintext)
    );

    const combined = new Uint8Array(iv.byteLength + cipherBuf.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(cipherBuf), iv.byteLength);
    return btoa(String.fromCharCode(...combined));
  }

  async function _decrypt(b64, key) {
    const combined = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    const cipherBuf = combined.slice(12);
    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      cipherBuf
    );
    return new TextDecoder().decode(plainBuf);
  }



    async function store(tokenKey, token) {
    const [fp, db] = await Promise.all([Fingerprint.get(), _openDB()]);
    const key = await _deriveKey(fp);
    const encrypted = await _encrypt(token, key);
    await _dbPut(db, tokenKey, encrypted);
  }

    async function retrieve(tokenKey) {
    try {
      const [fp, db] = await Promise.all([Fingerprint.get(), _openDB()]);
      const encrypted = await _dbGet(db, tokenKey);
      if (!encrypted) return null;
      const key = await _deriveKey(fp);
      return await _decrypt(encrypted, key);
    } catch {
      return null; 
    }
  }

    async function remove(tokenKey) {
    const db = await _openDB();
    await _dbDelete(db, tokenKey);
  }

  return { store, retrieve, remove };
})();

export default CryptoStore;