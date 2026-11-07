// Installed npm SDK process fixture; its fresh private key is never exported
// through the orchestration pipe. Native Rust owns all authorization semantics.
import { generateKeyPairSync, sign } from "node:crypto";
import { open, readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { request } from "node:http";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { GatewayClient, GatewayEndpoint } from "@auths-dev/sdk/gateway";

const MAX = 8 * 1024 * 1024;
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
let received;
let pendingReception;
let retainedAck;
const decode = (value) => {
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length > MAX || bytes.toString("base64url") !== value) throw new Error("encoding");
  return bytes;
};

async function receive(value) {
  // The SDK exposes control/acquisition/ACK transport. The maintained native
  // CLI supplies the recipient protocol; it runs as this same recipient UID.
  const directory = await mkdtemp(join(tmpdir(), "ap073-recipient-"));
  try {
    for (const name of ["proof", "action", "approval", "binding", "target"]) {
      await writeFile(join(directory, name), decode(value[name]), { mode: 0o600 });
    }
    const child = spawn(value.gateway, ["disclosure-receive", "--app-socket", value.socket,
      "--proof", join(directory, "proof"), "--action", join(directory, "action"),
      "--approval", join(directory, "approval"), "--target", join(directory, "target"),
      "--expected-binding", join(directory, "binding"), "--expected-bytes", String(value.bytes),
      "--content-out", join(directory, "content"), "--acknowledgement-out", join(directory, "ack"),
      "--recipient-seed-stdin"], { env: { PATH: process.env.PATH }, stdio: ["pipe", "pipe", "pipe"] });
    const seed = decode(privateKey.export({format:"jwk"}).d);
    child.stdin.end(seed, () => seed.fill(0));
    const output = [];
    let size = 0;
    child.stdout.on("data", (bytes) => { size += bytes.length; if (size > 4096) child.kill(); else output.push(bytes); });
    child.stderr.resume();
    const timer = setTimeout(() => child.kill(), 30000);
    let status;
    try {
      status = await new Promise((resolve, reject) => {child.once("error", reject); child.once("close", resolve);});
    } finally {clearTimeout(timer);}
    if (status !== 0) throw new Error("recipient refused");
    const result = JSON.parse(Buffer.concat(output).toString("utf8"));
    if (result.outcome !== "recipient-ack-sent") {
      // A historical response must not create a content or acknowledgement file.
      for (const name of ["content", "ack"]) {
        try {await readFile(join(directory, name)); throw new Error("redelivery");}
        catch (error) {if (error.code !== "ENOENT") throw error;}
      }
      return result;
    }
    received = await readFile(join(directory, "content"));
    if (received.length !== value.bytes) throw new Error("length");
    return {outcome:result.outcome, bytes:received.length};
  } finally {await rm(directory, {recursive:true, force:true});}
}

async function receiveWithoutAck(value) {
  if (pendingReception) throw new Error("recipient already active");
  const directory = await mkdtemp(join(tmpdir(), "ap073-lost-ack-"));
  let child;
  try {
    for (const name of ["proof", "action", "approval", "binding", "target"]) {
      await writeFile(join(directory, name), decode(value[name]), {mode:0o600});
    }
    await writeFile(join(directory, "details"), JSON.stringify({socket:value.socket, bytes:value.bytes}), {mode:0o600});
    child = spawn(value.native_test, ["--exact", "delegation_process::recipient::recipient_without_ack_process", "--nocapture"], {
      env:{PATH:process.env.PATH, AUTHS_DELEGATION_RECIPIENT_DIR:directory}, stdio:["pipe", "ignore", "ignore"]});
    const exited = new Promise((resolve) => {child.once("error", () => resolve(true)); child.once("close", () => resolve(true));});
    const seed = decode(privateKey.export({format:"jwk"}).d);
    child.stdin.on("error", () => {});
    child.stdin.end(seed, () => seed.fill(0));
    const deadline = Date.now() + 15000;
    for (;;) {
      try {await readFile(join(directory, "ready")); break;}
      catch (error) {if (error.code !== "ENOENT") throw error;}
      if (Date.now() >= deadline || child.exitCode !== null) throw new Error("recipient did not reach checkpoint");
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    received?.fill(0);
    received = await readFile(join(directory, "content"));
    retainedAck = await readFile(join(directory, "ack"));
    if (received.length !== value.bytes || retainedAck.length > 4096) throw new Error("receipt bound");
    pendingReception = {child, exited, directory};
    return {outcome:"received-ack-retained-not-sent", bytes:received.length};
  } catch (error) {
    if (child) child.kill("SIGKILL");
    await rm(directory, {recursive:true, force:true});
    throw error;
  }
}

async function crashRecipient() {
  if (!pendingReception) throw new Error("no active recipient");
  const {child, exited, directory} = pendingReception;
  child.kill("SIGKILL");
  await exited;
  await rm(directory, {recursive:true, force:true});
  pendingReception = undefined;
  return {crashed:true};
}

async function call(value) {
  switch (value.operation) {
    case "public": return {public_key: publicKey.export({format:"jwk"}).x, uid:process.getuid(), pid:process.pid,
      package:import.meta.resolve("@auths-dev/sdk/gateway"), language:"typescript"};
    case "sign": return {signature:sign(null, decode(value.message), privateKey).toString("base64url")};
    case "probe": {
      const readable = [];
      for (const filename of value.files) {
        try {const file = await open(filename, "r"); await file.close(); readable.push(true);} catch {readable.push(false);}
      }
      return {readable};
    }
    case "direct-provider": return new Promise((resolve, reject) => {
      const outgoing = request({hostname:"127.0.0.1", port:value.port, path:"/unauthorized", method:"PATCH", timeout:5000},
        (response) => {response.resume(); response.on("end", () => resolve({status:response.statusCode}));});
      outgoing.on("timeout", () => outgoing.destroy()); outgoing.on("error", reject); outgoing.end("{}");
    });
    case "receive": return receive(value);
    case "receive-without-ack": return receiveWithoutAck(value);
    case "crash-recipient": return crashRecipient();
    case "received": return {matches:received !== undefined && received.equals(decode(value.expected))};
  }
  const gateway = new GatewayClient(new GatewayEndpoint(value.socket));
  if (value.operation === "late-ack") {
    if (!retainedAck) throw new Error("no original acknowledgement");
    return JSON.parse(Buffer.from(await gateway.acknowledgeDisclosure(value.source_operation, retainedAck)).toString("utf8"));
  }
  if (value.operation === "control") return JSON.parse(Buffer.from(await gateway.participantControl(decode(value.evidence))).toString("utf8"));
  const submission = Object.fromEntries(["proof","action","approval"].map((name) => [name, decode(value[name])]));
  if (value.operation === "submit") return gateway.submit(submission);
  if (value.operation === "acquire") return JSON.parse(Buffer.from(await gateway.acquireContent(submission)).toString("utf8"));
  throw new Error("unsupported operation");
}

async function respond(line) {
  try {
    process.stdout.write(JSON.stringify(await call(JSON.parse(line.toString("utf8")))) + "\n");
  } catch {process.stdout.write('{"actor_error":"request-refused"}\n');}
}
// Bound input before assembling a line, including a line without a delimiter.
let pending = Buffer.alloc(0);
for await (const chunk of process.stdin) {
  let start = 0;
  for (let end = chunk.indexOf(10); end !== -1; end = chunk.indexOf(10, start)) {
    if (pending.length + end - start > MAX) throw new Error("size");
    await respond(Buffer.concat([pending, chunk.subarray(start, end)]));
    pending = Buffer.alloc(0);
    start = end + 1;
  }
  if (pending.length + chunk.length - start > MAX) throw new Error("size");
  pending = Buffer.concat([pending, chunk.subarray(start)]);
}
received?.fill(0);
retainedAck?.fill(0);
if (pendingReception) await crashRecipient();
