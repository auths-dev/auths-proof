import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { GatewayClient, GatewayEndpoint } from "../../dist/gateway.js";

test("gateway client submits proof/action only and separates observed from effect", { skip: process.platform === "win32" }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "auths-gateway-"));
  const path = join(directory, "app.sock");
  const seen = [];
  const server = createServer((socket) => {
    let bytes = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.length < 4 || bytes.length < bytes.readUInt32BE(0) + 4) return;
      seen.push(JSON.parse(bytes.subarray(4, bytes.readUInt32BE(0) + 4).toString("utf8")));
      const reply = Buffer.from('{"outcome":"observed","status":200,"matched":true}');
      const frame = Buffer.alloc(4 + reply.length);
      frame.writeUInt32BE(reply.length, 0);
      reply.copy(frame, 4);
      socket.end(frame);
    });
  });
  try {
    await new Promise((resolve) => server.listen(path, resolve));
    const result = await new GatewayClient(new GatewayEndpoint(path)).submit({
      proof: new Uint8Array([1, 2]),
      action: new Uint8Array([3, 4]),
    });
    assert.deepEqual(result, { outcome: "observed", status: 200, matched: true });
    assert.deepEqual(seen, [{
      schema: "auths.gateway-submit/1",
      proof_b64: "AQI",
      action_b64: "AwQ",
    }]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
});

test("gateway endpoint refuses provider URLs and client refuses empty actions", async () => {
  assert.throws(() => new GatewayEndpoint("https://api.example.com"), TypeError);
  const client = new GatewayClient(new GatewayEndpoint("/tmp/auths-test.sock"));
  await assert.rejects(
    client.submit({ proof: new Uint8Array([1]), action: new Uint8Array() }),
    TypeError,
  );
});
