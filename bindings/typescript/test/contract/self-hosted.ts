import {
  arrayField, booleanField, bytesField, exactMcpTool, integerField, objectField, optionalField, optionalStringField,
  runOnce, stringField, type AttemptStore, type AuthorizedCommand,
  type SelfHostedProviderAdapter,
} from "../../src/self-hosted.js";

const contract = exactMcpTool({
  service: "todoist",
  name: "create_task",
  fields: {
    content: stringField({ minBytes: 1, maxBytes: 120 }),
    project: optionalStringField({ maxBytes: 64 }),
    count: integerField({ minimum: 0, maximum: 10 }),
    enabled: booleanField(),
    retryCount: optionalField(integerField({ minimum: 0, maximum: 3 })),
  },
});

void contract.prepare(
  { content: "Review budget", project: null, count: 2, enabled: true, retryCount: null },
  {
    actor: "key:sha256:actor",
    terminalGrant: new Uint8Array([1]),
    challenge: new Uint8Array(32),
    evaluationTime: 100n,
  },
);

// @ts-expect-error missing required command field
void contract.prepare({ project: null }, {});

// @ts-expect-error optional field is still a bounded string or null
void contract.prepare({ content: "Review budget", project: 42, count: 2, enabled: true, retryCount: null }, {});

// @ts-expect-error booleans are not integers
void contract.prepare({ content: "Review budget", project: null, count: true, enabled: true, retryCount: null }, {});

// @ts-expect-error optional integer cannot be replaced with a string
void contract.prepare({ content: "Review budget", project: null, count: 2, enabled: true, retryCount: "2" }, {});

// @ts-expect-error callers cannot label a plain object as an authorized projection
const forged: AuthorizedCommand<{ readonly content: string }> = {
  kind: "authorized", command: { content: "fake" },
  actionCommitment: new Uint8Array(32), decision: {} as never,
};
void forged;

declare const attempts: AttemptStore;
const adapter: SelfHostedProviderAdapter<{
  readonly content: string;
  readonly project: string | null;
  readonly count: number;
  readonly enabled: boolean;
  readonly retryCount: number | null;
}, string, string> = {
  credential: () => "application-held-token",
  invoke: async (command, credential) => ({ kind: "accepted", value: command.content + credential }),
  observe: async () => "observed",
};
void runOnce({
  contract, proof: new Uint8Array(), action: new Uint8Array(),
  trustedContext: new Uint8Array(), attempts, operationKey: "one", adapter,
});

const nested = exactMcpTool({
  service: "example-service", name: "nested_v1",
  fields: {
    target: objectField({ recordId: stringField({ minBytes: 1, maxBytes: 32 }) }),
    labels: arrayField(stringField({ minBytes: 1, maxBytes: 16 }), { minItems: 1, maxItems: 3 }),
    payload: bytesField({ minBytes: 2, maxBytes: 16 }),
  },
});
void nested.prepare({
  target: { recordId: "rec-1" }, labels: ["demo"], payload: new Uint8Array([1, 2]),
}, { actor: "key:sha256:actor", terminalGrant: new Uint8Array([1]),
  challenge: new Uint8Array(32), evaluationTime: 100n });

// @ts-expect-error bytes cannot be an untyped base64 string in the public command
void nested.prepare({ target: { recordId: "rec-1" }, labels: ["demo"], payload: "AQI" }, {});

// @ts-expect-error nested objects cannot gain arbitrary provider parameters
void nested.prepare({ target: { recordId: "rec-1", url: "https://wrong.example" }, labels: ["demo"], payload: new Uint8Array([1, 2]) }, {});
