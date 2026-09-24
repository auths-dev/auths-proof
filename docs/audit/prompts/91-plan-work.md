# Prompt: plan work from verified findings

Input: the verified findings of one pass (the output of `90-verify.md`), and
`docs/PROGRAM_BOARD.md`: the epics in flight, the queue, and the board's rules.

Put every confirmed or partly confirmed finding in exactly one place:
1. **Private advisory:** an exploitable security weakness within the scope of `SECURITY.md`. Public files get only the advisory ID.
2. **Issue:** real, not already tracked, and it needs an owner decision or work across layers. Use one issue per coherent fix, and merge findings that share a fix.
3. **Existing epic:** it belongs inside work already on the board. Check that epic's open PR first, since it may already cover the finding. Otherwise add it to the epic's done gate instead of filing an issue.
4. **Cleanup PR:** small and mechanical. Batch these into one PR.
5. **Settled:** rejected findings and documented limits go to `docs/audit/settled.md`, with the reason.

Real findings too small to schedule go under "Parked" so they aren't lost.

For each package give: the findings it holds, where it goes, its size in hours of agent time, what it depends on, and the one decision the owner has to make, if any.

Follow the board's rules: the WIP limit, backlog items as one paragraph (rule 3), and the narrower reading of anything that would widen a claim (rule 8).

Output: `passes/<date>/work.md`, in the same shape as the most recent pass.
