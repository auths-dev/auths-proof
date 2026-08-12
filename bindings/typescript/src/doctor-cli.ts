#!/usr/bin/env node

import { doctor, renderDoctor } from "./doctor.js";

declare const process: {
  readonly argv: readonly string[];
  readonly stdout: { write(value: string): void };
  readonly stderr: { write(value: string): void };
  exitCode: number;
};

if (process.argv.length !== 3 || process.argv[2] !== "doctor") {
  process.stderr.write("usage: auths doctor\n");
  process.exitCode = 2;
} else {
  try {
    process.stdout.write(`${renderDoctor(await doctor())}\n`);
  } catch {
    process.stderr.write("Auths doctor could not initialize the packaged runtime\n");
    process.exitCode = 1;
  }
}
