import type { ApprovalProvider, ApprovalRequest } from "../../src/workflow.js";

declare const provider: ApprovalProvider;
declare const request: ApprovalRequest;

void provider.approve(request, { signal: new AbortController().signal });
// @ts-expect-error Approval cancellation context is an explicit required argument.
void provider.approve(request);
