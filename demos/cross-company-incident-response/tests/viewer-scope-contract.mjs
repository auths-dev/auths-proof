import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

const turn = () => new Promise(setImmediate);

/** Exercise the shipped controller with controlled fetches, independent of OIDC timing. */
export async function viewerScopeContract() {
  const source = (await readFile(new URL("../control-room/public/app.js", import.meta.url), "utf8"))
    .replace(/^import[\s\S]*?;\r?\n/gm, "")
    .replace(/wire\(\);\s*await bootstrap\(\);\s*$/, "");
  for (const order of ["old-first", "public-first"]) {
    for (const publicFailure of [false, true]) {
      for (const oldFailure of [false, true]) {
        const nodes = new Map();
        const get = (id) => {
          if (!nodes.has(id)) nodes.set(id, {
            innerHTML: "", textContent: "", dataset: {}, listeners: {},
            classList: { add() {}, remove() {}, toggle() {} },
            replaceChildren() { this.innerHTML = ""; this.textContent = ""; },
            addEventListener(event, action) { this.listeners[event] = action; },
          });
          return nodes.get(id);
        };
        const publicButton = get("public");
        publicButton.dataset.receiptRole = "public";
        const storage = new Map([["auths.incident.viewer-token", "auditor"]]);
        const requests = [];
        const context = vm.createContext({
          URL, URLSearchParams,
          location: { search: "?code=one&state=expected", origin: "http://localhost", pathname: "/" },
          history: { replaceState() {} },
          sessionStorage: { getItem: (key) => storage.get(key) ?? null,
            setItem: (key, value) => storage.set(key, value), removeItem: (key) => storage.delete(key) },
          document: { getElementById: get,
            querySelectorAll: (selector) => selector === "[data-receipt-role]" ? [publicButton] : [] },
          fetch(url, options) { return new Promise((resolve, reject) => requests.push({ url, options, resolve, reject })); },
        });
        vm.runInContext(source, context);
        vm.runInContext('wire(); state = { receiptView: "full", receipts: [{ state: "PRIVATE-EVIDENCE", outcome: "committed" }] }; render();', context);
        assert.match(get("receipts").innerHTML, /PRIVATE-EVIDENCE/);
        const old = vm.runInContext("refresh()", context);
        publicButton.listeners.click();
        assert.equal(requests.length, 4);
        assert.equal(requests[0].options.headers.authorization, "Bearer auditor");
        assert.equal(requests[2].options.headers.authorization, undefined);
        assert.equal(get("receipts").innerHTML, "");
        assert.equal(vm.runInContext("state.receipts.length", context), 0);
        const respond = async (offset, failure, body) => {
          requests[offset].resolve({ ok: !failure, json: async () => body });
          requests[offset + 1].resolve({ ok: true, json: async () => ({}) });
          await turn();
        };
        const releaseOld = () => respond(0, oldFailure, { receiptView: "full",
          receipts: [{ state: "PRIVATE-EVIDENCE", outcome: "committed" }] });
        const releasePublic = () => respond(2, publicFailure, { receiptView: "opaque", receipts: [] });
        if (order === "old-first") {
          await releaseOld();
          assert.doesNotMatch(get("receipts").innerHTML, /PRIVATE-EVIDENCE/);
          await releasePublic();
        } else {
          await releasePublic();
          await releaseOld();
        }
        await old; // A stale failure is consumed, not republished or rethrown.
        assert.doesNotMatch(get("receipts").innerHTML, /PRIVATE-EVIDENCE/);
        assert.equal(vm.runInContext("state.receipts.length", context), 0);
        assert.match(get("receipt-access-status").textContent,
          publicFailure ? /unavailable/ : /Unauthenticated viewer/);

        if (order === "old-first" && !publicFailure && !oldFailure) {
          // A token response from an older callback is also a publication:
          // public selection must not let it revive the auditor scope.
          for (const completion of ["success", "fetch-error", "json-error"]) {
            storage.set("auths.incident.oauth-state", "expected");
            storage.set("auths.incident.pkce-verifier", "verifier");
            vm.runInContext('state.identityProvider = "http://identity.example"', context);
            const offset = requests.length;
            const login = vm.runInContext("completeViewerLogin()", context);
            assert.equal(requests.length, offset + 1);
            publicButton.listeners.click();
            if (completion === "fetch-error") {
              requests[offset].reject(new Error("old login network failure"));
            } else {
              requests[offset].resolve({ ok: true, json: async () => {
                if (completion === "json-error") throw new SyntaxError("old login invalid JSON");
                return { access_token: "late-auditor" };
              } });
            }
            await login;
            assert.equal(storage.has("auths.incident.viewer-token"), false);
            assert.equal(vm.runInContext("viewerToken", context), "");
            await respond(offset + 1, false, { receiptView: "opaque", receipts: [] });
            assert.doesNotMatch(get("receipts").innerHTML, /PRIVATE-EVIDENCE/);
          }
        }
      }
    }
  }
}
