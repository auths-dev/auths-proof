const packagedEngines = new WeakSet<object>();

/** Records an engine loaded from the SDK-packaged, integrity-bound WASM subject. */
export function registerPackagedEngine<T extends object>(engine: T): T {
  packagedEngines.add(engine);
  return engine;
}

/** Reports whether this exact object was produced by the packaged loader. */
export function isPackagedEngine(engine: unknown): boolean {
  return typeof engine === "object" && engine !== null && packagedEngines.has(engine);
}
