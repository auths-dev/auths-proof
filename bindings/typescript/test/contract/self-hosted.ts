import {
  booleanField, exactMcpTool, integerField, optionalStringField, stringField,
  type AuthorizedCommand,
} from "../../src/self-hosted.js";

const contract = exactMcpTool({
  service: "todoist",
  name: "create_task",
  fields: {
    content: stringField({ minBytes: 1, maxBytes: 120 }),
    project: optionalStringField({ maxBytes: 64 }),
    count: integerField({ minimum: 0, maximum: 10 }),
    enabled: booleanField(),
  },
});

void contract.prepare(
  { content: "Review budget", project: null, count: 2, enabled: true },
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
void contract.prepare({ content: "Review budget", project: 42, count: 2, enabled: true }, {});

// @ts-expect-error booleans are not integers
void contract.prepare({ content: "Review budget", project: null, count: true, enabled: true }, {});

// @ts-expect-error callers cannot label a plain object as an authorized projection
const forged: AuthorizedCommand<{ readonly content: string }> = {
  kind: "authorized", command: { content: "fake" },
  actionCommitment: new Uint8Array(32), decision: {} as never,
};
void forged;
