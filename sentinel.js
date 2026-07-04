import Fingerprint from "./fingerprint.js";
import CryptoStore from "./crypto-store.js";
import Tamper from "./tamper.js";

const MAC_SUFFIX = "__mac";
const SW_PATH = "/sentinel/refresh-worker.js";

const Sentinel = (() => {

  let _swRegistration = null;



    async function init(swPath = SW_PATH) {
    if (!("serviceWorker" in navigator)) {
      console.warn("[Sentinel] SW not supported — offline refresh unavailable");
      return;
    }
    try {
      _swRegistration = await navigator.serviceWorker.register(swPath, {
        scope: "/",
      });


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



    async function storeToken(key, token) {
    const [mac] = await Promise.all([
      Tamper.sign(token),
      CryptoStore.store(key, token),
    ]);
    await CryptoStore.store(key + MAC_SUFFIX, mac);
  }



    async function getToken(key) {
    const [token, mac] = await Promise.all([
      CryptoStore.retrieve(key),
      CryptoStore.retrieve(key + MAC_SUFFIX),
    ]);

    if (!token || !mac) return null;

    const valid = await Tamper.verify(token, mac);
    if (!valid) {
      console.warn("[Sentinel] Tamper detected for key:", key);
      await removeToken(key); 
      return null;
    }

    return token;
  }



    async function removeToken(key) {
    await Promise.all([
      CryptoStore.remove(key),
      CryptoStore.remove(key + MAC_SUFFIX),
    ]);
  }



    async function queueRefresh(endpoint) {
    if (!_swRegistration) {
      console.warn("[Sentinel] SW not registered — call init() first");
      return;
    }


    if ("SyncManager" in window) {
      try {
        await _swRegistration.sync.register("sentinel-refresh");
        return;
      } catch {

      }
    }


    const sw = _swRegistration.active ?? _swRegistration.waiting;
    if (sw) {
      sw.postMessage({
        type: "SENTINEL_QUEUE_REFRESH",
        endpoint: endpoint ?? undefined,
      });
    }
  }



    async function getFingerprint() {
    return Fingerprint.get();
  }



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