import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import {
  createServiceClient,
  githubIssueAddress,
} from "../../dist/service.js";
import { loadPackagedWorkflowEngine } from "../../dist/verifier/wasm.js";

const fixture = JSON.parse(await readFile(
  new URL("../../../../product/fixtures/v1/production-client/contract-v1.json", import.meta.url),
  "utf8",
));

test("Rust, TypeScript, and canonical client request bytes agree", async () => {
  const native = await loadPackagedWorkflowEngine();
  for (const vector of fixture.requests) {
    const projection = vector.projection;
    const encoded = native.encodeProductionRequestV1({
      verb: projection.verb,
      profile: projection.profile,
      identity: decode(projection.identity),
      ...(projection.authority === null ? {} : { authority: decode(projection.authority) }),
      ...(projection.body === null ? {} : { body: decode(projection.body) }),
      ...(projection.recoveryReference === null ? {} : { recoveryReference: projection.recoveryReference }),
    });
    assert.equal(Buffer.from(encoded).toString("hex"), vector.bytesHex, vector.id);
    assert.deepEqual(JSON.parse(native.decodeProductionRequestV1(encoded)), projection, vector.id);
  }
});

test("Rust-owned finite response projections are identical in TypeScript", async () => {
  const native = await loadPackagedWorkflowEngine();
  for (const vector of fixture.responses) {
    assert.deepEqual(
      JSON.parse(native.decodeProductionResponseV1(Buffer.from(vector.bytesHex, "hex"))),
      vector.projection,
      vector.id,
    );
  }
  for (const vector of fixture.adversarial) {
    const decodeVector = vector.target === "request"
      ? native.decodeProductionRequestV1
      : native.decodeProductionResponseV1;
    assert.throws(
      () => decodeVector(Buffer.from(vector.bytesHex, "hex")),
      new RegExp(vector.expectedCode.replaceAll(".", "\\.")),
      vector.id,
    );
  }
});

test("the service client uses five verbs and closed profile routes", async () => {
  const completed = fixture.responses.find((item) => item.id === "completed");
  const calls = [];
  // Explicit named constructor. This used to be `createAuths`, which chose
  // between the local facade and this client by testing the argument for an
  // `endpoint` property.
  const auths = createServiceClient({
    endpoint: "https://operator.example",
    identity: new Uint8Array(32).fill(1),
    profile: githubIssueAddress(),
    transport: {
      async send(request) {
        calls.push(request.url.pathname);
        return {
          status: 200,
          contentType: fixture.contentType,
          body: Buffer.from(completed.bytesHex, "hex"),
        };
      },
    },
  });
  const authority = await auths.create(new Uint8Array([1]));
  assert.equal(authority.kind, "authority");
  const executed = await auths.execute(authority, new Uint8Array([2]));
  assert.equal(executed.kind, "completed");
  assert.deepEqual(calls, [
    "/v1/authority/create",
    "/v1/profiles/github/issue-address/execute",
  ]);
});

function decode(value) {
  return Buffer.from(value, "base64url");
}
