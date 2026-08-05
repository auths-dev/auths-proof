import {
  type ApplicationProfile,
  type CanonicalProfileAction,
} from "../profiles/application/index.js";
import { AuthsWorkflowError } from "../workflow/errors.js";

type SecurityProjection =
  | "canonicalAction"
  | "resource"
  | "resourceNamespace"
  | "audience"
  | "budget";

export interface ProfileConformanceOptions<Input extends object> {
  readonly baseline: Input;
  readonly mutations: Readonly<Partial<{
    [Key in keyof Input]: readonly Input[Key][];
  }>>;
}

export interface ProfileConformanceResult<Input extends object> {
  mustChange(expectations: Readonly<Partial<Record<keyof Input, readonly SecurityProjection[]>>>): void;
}

/** Mutation harness for application-owned profile semantics. */
export function profileConformance<Input extends object, Command>(
  profile: ApplicationProfile<Input, Command>,
  options: ProfileConformanceOptions<Input>,
): ProfileConformanceResult<Input> {
  const baseline = profile.inspectAction(profile.action(options.baseline));
  const observations = new Map<keyof Input, readonly CanonicalProfileAction[]>();
  for (const key of Object.keys(options.mutations) as (keyof Input)[]) {
    const values = options.mutations[key] ?? [];
    observations.set(
      key,
      values.map((value) => profile.inspectAction(profile.action({
        ...options.baseline,
        [key]: value,
      }))),
    );
  }
  return Object.freeze({
    mustChange(
      expectations: Readonly<Partial<Record<keyof Input, readonly SecurityProjection[]>>>,
    ) {
      for (const key of Object.keys(expectations) as (keyof Input)[]) {
        const projections = expectations[key] ?? [];
        const candidates = observations.get(key) ?? [];
        if (candidates.length === 0) {
          throw new AuthsWorkflowError("invalid-profile", `profile mutation ${String(key)} has no candidates`);
        }
        for (const candidate of candidates) {
          for (const projection of projections) {
            if (!projectionChanged(projection, baseline, candidate)) {
              throw new AuthsWorkflowError(
                "invalid-profile",
                `profile mutation ${String(key)} did not change ${projection}`,
              );
            }
          }
        }
      }
    },
  });
}

function projectionChanged(
  projection: SecurityProjection,
  baseline: CanonicalProfileAction,
  candidate: CanonicalProfileAction,
): boolean {
  switch (projection) {
    case "canonicalAction":
      return !equalBytes(baseline.body, candidate.body) || baseline.mediaType !== candidate.mediaType;
    case "resource":
      return baseline.permission.resource !== candidate.permission.resource ||
        baseline.permission.capability !== candidate.permission.capability;
    case "resourceNamespace":
      return baseline.resourceNamespace !== candidate.resourceNamespace;
    case "audience":
      return baseline.audience !== candidate.audience;
    case "budget":
      return baseline.budget?.algebra !== candidate.budget?.algebra ||
        baseline.budget?.value !== candidate.budget?.value;
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}
