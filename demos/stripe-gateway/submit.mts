/** Installed TypeScript gateway client. No provider API, credentials or private SDK. */
import { GatewayClient, GatewayEndpoint } from '@auths-dev/sdk/gateway';

const [flag, socket] = process.argv.slice(2);
if (flag !== '--socket' || !socket || process.argv.length !== 4) throw new Error('demo.invalid-arguments');
if (Object.keys(process.env).some(name => /STRIPE|AWS|PYTHONPATH/.test(name))) throw new Error('demo.credential-environment');
let input = '';
for await (const chunk of process.stdin) {
  input += String(chunk);
  if (input.length > 8 * 1024 * 1024) throw new Error('demo.packet-bound');
}
const packet = JSON.parse(input) as Record<string, unknown>;
if (Object.keys(packet).sort().join(',') !== 'action_b64,proof_b64') throw new Error('demo.invalid-packet');
function bytes(value: unknown): Uint8Array {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('demo.invalid-packet');
  const result = Buffer.from(value, 'base64url');
  if (result.toString('base64url') !== value) throw new Error('demo.invalid-packet');
  return result;
}
const client = new GatewayClient(new GatewayEndpoint(socket));
console.log(JSON.stringify(await client.submit({proof: bytes(packet.proof_b64), action: bytes(packet.action_b64)})));
