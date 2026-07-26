const MAX_RESULT_BYTES = 16 * 1024 * 1024;
const MAX_DEPTH = 64;
const AUTHORIZED_TOKEN = Symbol("auths-authorized");
export class VerifiedAction {
    #canonicalAction;
    constructor(token, canonicalAction) {
        if (token !== AUTHORIZED_TOKEN)
            throw new TypeError("sealed Auths action");
        this.#canonicalAction = canonicalAction.slice();
    }
    static fromEngine(token, canonicalAction) {
        return new VerifiedAction(token, canonicalAction);
    }
    canonicalBytes() {
        return this.#canonicalAction.slice();
    }
}
export class Auths {
    #engine;
    constructor(engine) {
        this.#engine = engine;
    }
    verify(proofCbor, canonicalActionCbor, trustedContextCbor) {
        const bytes = this.#engine.verifyV1(proofCbor, canonicalActionCbor, trustedContextCbor);
        const decoded = decodeResult(bytes);
        const explanation = explain(decoded.kind, decoded.code);
        const common = {
            code: decoded.code,
            stage: decoded.stage,
            explanation,
            metrics: decoded.metrics,
            resultCbor: bytes.slice(),
        };
        if (decoded.kind === "authorized") {
            return {
                ...common,
                kind: "authorized",
                action: VerifiedAction.fromEngine(AUTHORIZED_TOKEN, canonicalActionCbor),
            };
        }
        return { ...common, kind: decoded.kind };
    }
}
export async function loadAuths(options = {}) {
    const moduleUrl = options.moduleUrl ??
        new URL("../wasm/auths_proof_wasm.js", import.meta.url).href;
    const loaded = (await import(moduleUrl));
    if (loaded.default !== undefined) {
        if (options.wasmInput === undefined)
            await loaded.default();
        else
            await loaded.default({ module_or_path: options.wasmInput });
    }
    if (typeof loaded.verifyV1 !== "function") {
        throw new TypeError("Auths WASM module omitted verifyV1");
    }
    return new Auths({ verifyV1: loaded.verifyV1 });
}
class Reader {
    #bytes;
    #offset = 0;
    constructor(bytes) {
        if (bytes.length === 0 || bytes.length > MAX_RESULT_BYTES) {
            throw new RangeError("Auths result exceeds byte bounds");
        }
        this.#bytes = bytes;
    }
    get complete() {
        return this.#offset === this.#bytes.length;
    }
    head() {
        const initial = this.#take();
        const major = initial >>> 5;
        const additional = initial & 31;
        if (additional < 24)
            return [major, BigInt(additional)];
        const width = additional === 24 ? 1 :
            additional === 25 ? 2 :
                additional === 26 ? 4 :
                    additional === 27 ? 8 : 0;
        if (width === 0)
            throw new TypeError("indefinite CBOR is not canonical");
        let value = 0n;
        for (let index = 0; index < width; index += 1) {
            value = (value << 8n) | BigInt(this.#take());
        }
        if ((width === 1 && value < 24n) ||
            (width === 2 && value <= 0xffn) ||
            (width === 4 && value <= 0xffffn) ||
            (width === 8 && value <= 0xffffffffn)) {
            throw new TypeError("non-minimal CBOR integer");
        }
        return [major, value];
    }
    uint() {
        const [major, value] = this.head();
        if (major !== 0)
            throw new TypeError("expected CBOR unsigned integer");
        return value;
    }
    text() {
        const [major, length] = this.head();
        if (major !== 3 || length > BigInt(this.#bytes.length - this.#offset)) {
            throw new TypeError("invalid CBOR text");
        }
        const size = Number(length);
        const value = new TextDecoder("utf-8", { fatal: true }).decode(this.#bytes.subarray(this.#offset, this.#offset + size));
        this.#offset += size;
        return value;
    }
    map() {
        const [major, length] = this.head();
        if (major !== 5 || length > 1000000n) {
            throw new TypeError("invalid CBOR map");
        }
        return Number(length);
    }
    skip(depth = 0) {
        if (depth > MAX_DEPTH)
            throw new RangeError("CBOR depth exceeded");
        const [major, argument] = this.head();
        if (major === 0 || major === 1)
            return;
        if (major === 2 || major === 3) {
            const size = Number(argument);
            if (argument > BigInt(this.#bytes.length - this.#offset)) {
                throw new TypeError("truncated CBOR value");
            }
            this.#offset += size;
            return;
        }
        if (major === 4) {
            for (let index = 0; index < Number(argument); index += 1) {
                this.skip(depth + 1);
            }
            return;
        }
        if (major === 5) {
            for (let index = 0; index < Number(argument); index += 1) {
                this.skip(depth + 1);
                this.skip(depth + 1);
            }
            return;
        }
        if (major === 7 && [20n, 21n, 22n].includes(argument))
            return;
        throw new TypeError("unsupported CBOR result value");
    }
    #take() {
        const value = this.#bytes[this.#offset];
        if (value === undefined)
            throw new TypeError("truncated CBOR result");
        this.#offset += 1;
        return value;
    }
}
function decodeResult(bytes) {
    const reader = new Reader(bytes);
    if (reader.map() !== 14)
        throw new TypeError("invalid Auths result shape");
    let decision = -1;
    let stage = -1;
    let code = "";
    let metrics = [];
    for (let index = 0; index < 14; index += 1) {
        const key = Number(reader.uint());
        if (key === 0)
            decision = Number(reader.uint());
        else if (key === 1)
            stage = Number(reader.uint());
        else if (key === 2) {
            if (reader.map() !== 2 || reader.uint() !== 0n) {
                throw new TypeError("invalid Auths result code");
            }
            reader.uint();
            if (reader.uint() !== 1n)
                throw new TypeError("invalid result code key");
            code = reader.text();
        }
        else if (key === 11) {
            if (reader.map() !== 7)
                throw new TypeError("invalid result metrics");
            metrics = [];
            for (let metric = 0; metric < 7; metric += 1) {
                if (reader.uint() !== BigInt(metric)) {
                    throw new TypeError("non-canonical result metrics");
                }
                metrics.push(reader.uint());
            }
        }
        else {
            reader.skip();
        }
    }
    if (!reader.complete || !code || metrics.length !== 7) {
        throw new TypeError("incomplete Auths result");
    }
    const kinds = ["authorized", "denied", "indeterminate"];
    const stages = [
        "decode",
        "resolve",
        "principal-control",
        "authority",
        "complete",
    ];
    const kind = kinds[decision];
    const stageName = stages[stage];
    if (kind === undefined || stageName === undefined) {
        throw new TypeError("unknown Auths result discriminator");
    }
    return {
        kind,
        code,
        stage: stageName,
        metrics: {
            proofBytes: metrics[0],
            actionBytes: metrics[1],
            contextBytes: metrics[2],
            objectCount: metrics[3],
            planLeaves: metrics[4],
            planDepth: metrics[5],
            workUnits: metrics[6],
        },
    };
}
function explain(kind, code) {
    if (kind === "authorized") {
        return {
            code,
            message: "the proof establishes exact authority for this action",
            retryable: false,
        };
    }
    if (kind === "indeterminate") {
        return {
            code,
            message: "a required trustworthy fact or implementation is unavailable",
            retryable: true,
        };
    }
    return {
        code,
        message: "the supplied proof does not authorize this exact action",
        retryable: false,
    };
}
