import { exactMcpTool, optionalStringField, stringField } from "../../src/self-hosted.js";

const contract = exactMcpTool({
  service: "todoist",
  name: "create_task",
  fields: {
    content: stringField({ minBytes: 1, maxBytes: 120 }),
    project: optionalStringField({ maxBytes: 64 }),
  },
});

void contract.prepare(
  { content: "Review budget", project: null },
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
void contract.prepare({ content: "Review budget", project: 42 }, {});
