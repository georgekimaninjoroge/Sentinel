/**
 * Sentinel — sentinel.js
 * Main orchestrator. Wires fingerprint + crypto-store + tamper + SW refresh.
 *
 * Usage:
 *   import Sentinel from "./sentinel.js";
 *
 *   await Sentinel.init();                       // register SW
 *   await Sentinel.storeToken("access", jwt);    // encrypt + mac + store
 *   const token = await Sentinel.getToken("access"); // verify + decrypt
 *   await Sentinel.removeToken("access");
 *   await Sentinel.queueRefresh();               // trigger SW refresh
 */

import Fingerprint from "./fingerprint.js";
import CryptoStore from "./crypto-store.js";
import Tamper from "./tamper.js";

const MAC_SUFFIX = "__mac";
const SW_PATH = "/sentinel/refresh-worker.js";

const Sentinel = (() => {

  let _swRegistration = null;

  // ─── Init ─────────────────────────────────────────────────────────────────

  /**
   * Registers Service Worker. Call once on app boot.
   * Safe to call multiple times.
   */
  async function init(swPath = SW_PATH) {
    if (!("serviceWorker" in navigator)) {
      console.warn("[Sentinel] SW not supported — offline refresh unavailable");
      return;
    }
    try {
      _swRegistration = await navigator.serviceWorker.register(swPath, {
        scope: "/",
      });

      // Listen for new tokens broadcast from SW
      navigator.serviceWorker.addEventListener("message", e => {
        if (e.data?.type === "SENTINEL_NEW_TOKEN" && e.data.token) {
          storeToken("access_token", e.data.token).catch(console.error);
        }
      });

      console.info("[Sentinel] Service Worker registered");
    } catch (err) {
      console.error("[Sentinel] SW registration failed:", err);
    }
  }

  // ─── Store ────────────────────────────────────────────────────────────────

  /**
   * Encrypt token + compute MAC + store both in IndexedDB.
   * MAC binds to device fingerprint — stolen token unusable elsewhere.
   * @param {string} key   e.g. "access_token" | "refresh_token"
   * @param {string} token JWT string
   */
  async function storeToken(key, token) {
    const [mac] = await Promise.all([
      Tamper.sign(token),
      CryptoStore.store(key, token),
    ]);
    await CryptoStore.store(key + MAC_SUFFIX, mac);
  }

  // ─── Retrieve ─────────────────────────────────────────────────────────────

  /**
   * Decrypt + verify token integrity.
   * Returns null if: missing, wrong device, tampered, or decryption fails.
   * @param {string} key
   * @returns {string|null}
   */
  async function getToken(key) {
    const [token, mac] = await Promise.all([
      CryptoStore.retrieve(key),
      CryptoStore.retrieve(key + MAC_SUFFIX),
    ]);

    if (!token || !mac) return null;

    const valid = await Tamper.verify(token, mac);
    if (!valid) {
      console.warn("[Sentinel] Tamper detected for key:", key);
      await removeToken(key); // purge compromised entry
      return null;
    }

    return token;
  }

  // ─── Remove ───────────────────────────────────────────────────────────────

  /**
   * Remove token + its MAC from store.
   * @param {string} key
   */
  async function removeToken(key) {
    await Promise.all([
      CryptoStore.remove(key),
      CryptoStore.remove(key + MAC_SUFFIX),
    ]);
  }

  // ─── Refresh ──────────────────────────────────────────────────────────────

  /**
   * Queues / triggers token refresh via Service Worker.
   * If online: executes immediately.
   * If offline: queues; executes on next reconnect (Background Sync).
   * @param {string} [endpoint] override refresh endpoint
   */
  async function queueRefresh(endpoint) {
    if (!_swRegistration) {
      console.warn("[Sentinel] SW not registered — call init() first");
      return;
    }

    // Try Background Sync API first
    if ("SyncManager" in window) {
      try {
        await _swRegistration.sync.register("sentinel-refresh");
        return;
      } catch {
        // Fallback to postMessage
      }
    }

    // Fallback: postMessage to SW
    const sw = _swRegistration.active ?? _swRegistration.waiting;
    if (sw) {
      sw.postMessage({
        type: "SENTINEL_QUEUE_REFRESH",
        endpoint: endpoint ?? undefined,
      });
    }
  }

  // ─── Fingerprint ─────────────────────────────────────────────────────────

  /**
   * Returns current device fingerprint (hex string).
   * Use to attach as JWT claim server-side for binding validation.
   */
  async function getFingerprint() {
    return Fingerprint.get();
  }

  // ─── Debug ────────────────────────────────────────────────────────────────

  /**
   * Returns raw device signals (no hashing). For debugging only.
   */
  function getSignals() {
    return Fingerprint.getSignals();
  }

  return {
    init,
    storeToken,
    getToken,
    removeToken,
    queueRefresh,
    getFingerprint,
    getSignals,
  };
})();

export default Sentinel;
