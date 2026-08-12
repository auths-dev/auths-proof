import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  createReceiptDisclosure,
  inspectReceipt,
} from "../../dist/verify.js";

const fixture = JSON.parse(await readFile(
  new URL("../../../../product/fixtures/v1/receipt-disclosure/inspection-v1.json", import.meta.url),
  "utf8",
));

test("Rust, TypeScript, and Python share the receipt disclosure contract", async () => {
  const receipt = fixtureReceipt();
  const command = hexBytes(fixture.commandHex);
  const result = hexBytes(fixture.resultHex);
  const disclosure = await createReceiptDisclosure({
    receipt,
    profileId: fixture.profile.id,
    profileVersion: fixture.profile.version,
    command,
    result,
  });
  assert.deepEqual(disclosure, hexBytes(fixture.disclosureHex));

  for (const scenario of fixture.cases) {
    const input = await scenarioInput(scenario, receipt, command, result, disclosure);
    const inspected = await inspectReceipt(input);
    assert.equal(inspected.kind, scenario.kind, scenario.id);
    if (inspected.kind === "invalid") {
      assert.equal(inspected.code, scenario.code, scenario.id);
    }
  }

  const opaque = await inspectReceipt({ receipt });
  assert.equal(opaque.kind, "verified-opaque");
  assert.equal("summary" in opaque, false);
  assert.equal("disclosure" in opaque, false);
  assert.equal("command" in opaque, false);

  const summary = await inspectReceipt({ receipt, mode: "summary", disclosure });
  assert.equal(summary.kind, "verified-disclosed");
  assert.deepEqual(
    summary.summary.fields.slice(0, 4).map((field) => field.label),
    ["Fleet", "Device", "Command", "Sequence"],
  );
  assert.equal(summary.disclosure, undefined);
  assert.equal("effectCapable" in summary, false);

  const full = await inspectReceipt({ receipt, mode: "full", disclosure });
  assert.equal(full.kind, "verified-disclosed");
  assert.deepEqual(full.disclosure?.command, command);
  assert.deepEqual(full.disclosure?.result, result);

  await assert.rejects(
    () => createReceiptDisclosure({
      receipt,
      profileId: fixture.profile.id,
      profileVersion: fixture.profile.version,
      command: new Uint8Array(1024 * 1024 + 1),
    }),
    /disclosure-limit-exceeded/,
  );
});

async function scenarioInput(scenario, receipt, command, result, disclosure) {
  let selectedReceipt = receipt;
  let selectedDisclosure = disclosure;
  if (scenario.mutation === "missing") selectedDisclosure = undefined;
  if (scenario.mutation === "malformed") selectedDisclosure = Uint8Array.of(0xff);
  if (scenario.mutation === "receipt-id") {
    const changed = receipt.execution.receiptId.slice();
    changed[0] ^= 1;
    selectedDisclosure = await createReceiptDisclosure({
      receipt: { ...receipt, execution: { ...receipt.execution, receiptId: changed } },
      profileId: fixture.profile.id,
      profileVersion: fixture.profile.version,
      command,
      result,
    });
  }
  if (scenario.mutation === "profile") {
    selectedDisclosure = await createReceiptDisclosure({
      receipt,
      profileId: "auths.http",
      profileVersion: 1,
      command,
      result,
    });
  }
  if (scenario.mutation === "command") {
    const changed = command.slice();
    changed[changed.length - 2] ^= 1;
    selectedDisclosure = await createReceiptDisclosure({
      receipt,
      profileId: fixture.profile.id,
      profileVersion: fixture.profile.version,
      command: changed,
      result,
    });
  }
  if (scenario.mutation === "result") {
    const changed = result.slice();
    changed[changed.length - 2] ^= 1;
    selectedDisclosure = await createReceiptDisclosure({
      receipt,
      profileId: fixture.profile.id,
      profileVersion: fixture.profile.version,
      command,
      result: changed,
    });
  }
  if (scenario.mutation === "evidence") {
    selectedReceipt = {
      ...receipt,
      execution: {
        ...receipt.execution,
        signer: { ...receipt.execution.signer, evidence: Uint8Array.of(0xff) },
      },
    };
  }
  if (scenario.mutation === "receipt") {
    const changed = receipt.execution.bytes.slice();
    changed[changed.length - 1] ^= 1;
    selectedReceipt = { ...receipt, execution: { ...receipt.execution, bytes: changed } };
  }
  return {
    receipt: selectedReceipt,
    mode: scenario.mode,
    ...(selectedDisclosure === undefined ? {} : { disclosure: selectedDisclosure }),
  };
}

function fixtureReceipt() {
  return {
    decision: fixtureMember(fixture.receipt.decision),
    execution: fixtureMember(fixture.receipt.execution),
  };
}

function fixtureMember(value) {
  return {
    kind: value.kind,
    receiptId: hexBytes(value.receiptIdHex),
    bytes: hexBytes(value.bytesHex),
    signer: {
      principal: value.signer.principal,
      verificationMethod: value.signer.verificationMethod,
      suite: value.signer.suite,
      evidence: hexBytes(value.signer.evidenceHex),
    },
  };
}

function hexBytes(value) {
  return Uint8Array.from(value.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
}
