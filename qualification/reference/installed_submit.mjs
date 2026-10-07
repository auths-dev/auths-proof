/** Installed TypeScript consumer; accepts public proof/action paths only. */
import { readFile, realpath, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, isAbsolute, join } from 'node:path';

function requireFact(value) {
  if (!value) throw new Error('qualification.consumer.refused');
}
const digest = value => createHash('sha256').update(value).digest('hex');

try {
  requireFact(Object.keys(process.env).every(name => ['PATH', 'LC_CTYPE', 'LANG'].includes(name)));
  const gatewayFile = await realpath(fileURLToPath(import.meta.resolve('@auths-dev/sdk/gateway')));
  requireFact(gatewayFile.endsWith('/node_modules/@auths-dev/sdk/dist/gateway.js'));
  const packageRoot = dirname(dirname(gatewayFile));
  const metadata = JSON.parse(await readFile(join(packageRoot, 'package.json'), 'utf8'));
  requireFact(metadata.name === '@auths-dev/sdk' && typeof metadata.version === 'string');
  const sdk = await import('@auths-dev/sdk/gateway');
  const [operation, ...arguments_] = process.argv.slice(2);
  let result;
  if (operation === 'inspect') {
    requireFact(arguments_.length === 0);
    result = { schema: 'auths.qualification-consumer-provenance/1', language: 'typescript',
      package_name: metadata.name, version: metadata.version, installation: 'node_modules',
      module_sha256: digest(await readFile(gatewayFile)), repository_imported: false,
      provider_token_received: false };
  } else {
    requireFact(operation === 'submit' && arguments_.length === 3 && arguments_.every(isAbsolute));
    const [endpoint, proofPath, actionPath] = arguments_;
    async function bounded(path, maximum) {
      const info = await stat(path);
      requireFact(info.isFile() && info.size > 0 && info.size <= maximum);
      const bytes = await readFile(path);
      requireFact(bytes.length > 0 && bytes.length <= maximum);
      return bytes;
    }
    result = await new sdk.GatewayClient(new sdk.GatewayEndpoint(endpoint)).submit({
      proof: await bounded(proofPath, 4 * 1024 * 1024), action: await bounded(actionPath, 65536) });
    // Map the installed client's documented field spelling back to the
    // shipping native result carrier; no decision or evidence is invented.
    if (result.outcome === 'observed-by-provider') {
      result = { outcome: result.outcome, status: result.status, evidence: {
        channel: result.evidence.channel, echo: result.evidence.echo,
        evidence_digest: result.evidence.evidenceDigest, observed_at: result.evidence.observedAt } };
    }
  }
  const encoded = JSON.stringify(result);
  requireFact(Buffer.byteLength(encoded) <= 65536);
  process.stdout.write(encoded + '\n');
} catch {
  process.stderr.write('qualification.consumer.refused\n');
  process.exitCode = 1;
}
