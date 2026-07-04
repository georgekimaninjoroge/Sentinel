const Fingerprint = (() => {

  function _getSignals() {
    return {
      screen: `${screen.width}x${screen.height}x${screen.colorDepth}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      language: navigator.language,
      platform: navigator.platform,
      hardwareConcurrency: navigator.hardwareConcurrency ?? 0,
      deviceMemory: navigator.deviceMemory ?? 0,
      userAgent: navigator.userAgent,
      touchPoints: navigator.maxTouchPoints ?? 0,
    };
  }

  async function _sha256(str) {
    const buf = new TextEncoder().encode(str);
    const hash = await crypto.subtle.digest("SHA-256", buf);
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

    async function get() {
    const signals = _getSignals();
    const raw = JSON.stringify(signals);
    return await _sha256(raw);
  }

    function getSignals() {
    return _getSignals();
  }

  return { get, getSignals };
})();

export default Fingerprint;