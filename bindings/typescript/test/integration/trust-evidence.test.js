import assert from "node:assert/strict";
import test from "node:test";
import {
  loadOfflineTrustBundle,
  trustedContextFromOfflineBundle,
} from "../../dist/trust.js";
import { ROOT, packagedWasm, vector } from "./helpers/mcp-fixture.js";

test("bounded offline evidence preserves provenance and revalidates exact trust", async () => {
  const wasm = await packagedWasm();
  const events = [];
  const bundle = await loadOfflineTrustBundle({
    sourceId: "fixture.trust",
    evaluationTime: 50n,
    correlationId: "trust-fixture",
    telemetry: { emit(event) { events.push(event); } },
    port: {
      async load(request) {
        assert.equal(request.maximumRedirects, 0);
        assert.equal(request.allowPrivateNetwork, false);
        return {
          bytes: vector("mcp.context.cbor"),
          provenance: {
            source: "fixture.trust",
            observedAt: 40n,
            validUntil: 60n,
            version: "snapshot-1",
          },
        };
      },
    },
  });
  await Promise.resolve();
  assert.deepEqual(events.map(({ stage, outcome }) => [stage, outcome]), [
    ["acquisition", "started"],
    ["acquisition", "succeeded"],
  ]);
  assert.equal(bundle.provenance.version, "snapshot-1");
  assert.ok(bundle.export().length > 0);
  const source = await trustedContextFromOfflineBundle(
    "offline.fixture",
    bundle,
    ROOT,
    wasm.configurationV1(),
  );
  assert.equal(source.sourceId, "offline.fixture");
});

test("evidence acquisition rejects stale and oversized source output", async () => {
  await assert.rejects(() => loadOfflineTrustBundle({
    sourceId: "stale",
    evaluationTime: 50n,
    port: { async load() { return {
      bytes: new Uint8Array([1]),
      provenance: { source: "stale", observedAt: 1n, validUntil: 2n, version: "1" },
    }; } },
  }), /stale/);
  await assert.rejects(() => loadOfflineTrustBundle({
    sourceId: "oversized",
    evaluationTime: 1n,
    maximumBytes: 1,
    port: { async load() { return {
      bytes: new Uint8Array([1, 2]),
      provenance: { source: "oversized", observedAt: 1n, validUntil: 2n, version: "1" },
    }; } },
  }), /invalid bytes/);
});
