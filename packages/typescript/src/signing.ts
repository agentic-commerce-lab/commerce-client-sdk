import { createHash, createPrivateKey, randomBytes, sign, type KeyObject } from 'node:crypto';
import type { PreparedRequest, Signer } from './index.js';
/** RFC 9421: sign the components UCP requires: method, authority, path, agent header, idempotency key and exact body bytes. */
export function createSigner(options: { keyId: string; privateKey: string | KeyObject; now?: () => number; nonce?: () => string }): Signer {
  const key = typeof options.privateKey === 'string' ? createPrivateKey(options.privateKey) : options.privateKey;
  const algorithm = key.asymmetricKeyType === 'ed25519' ? 'ed25519' : key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1' ? 'ecdsa-p256-sha256' : undefined;
  if (!algorithm) throw new Error('Expected an Ed25519 or P-256 private key');
  if (!options.keyId || /["\\\r\n]/.test(options.keyId)) throw new Error('Invalid key ID');
  return (request: PreparedRequest) => {
    const headers: Record<string, string> = { ...request.headers };
    const target = new URL(request.url);
    // The covered components UCP verifiers require: @authority and @path, not @target-uri.
    const components = ['@method', '@authority', '@path', ...(target.search ? ['@query'] : []), 'ucp-agent'];
    if (request.idempotencyKey) components.push('idempotency-key');
    if (request.body !== undefined) { headers['content-digest'] = `sha-256=:${createHash('sha256').update(request.body).digest('base64')}:`; components.push('content-digest', 'content-type'); }
    const created = Math.floor((options.now ?? (() => Date.now() / 1000))());
    const nonce = (options.nonce ?? (() => randomBytes(16).toString('hex')))();
    if (/["\\\r\n]/.test(nonce)) throw new Error('Invalid signature nonce');
    // UCP derives the algorithm from the key; alg is not a Signature-Input parameter.
    const parameters = `(${components.map(name => `"${name}"`).join(' ')});created=${created};keyid="${options.keyId}";nonce="${nonce}"`;
    const values: Record<string, string> = { '@method': request.method, '@authority': target.host, '@path': target.pathname, '@query': target.search, ...headers };
    const lines = components.map(name => `"${name}": ${values[name]}`);
    lines.push(`"@signature-params": ${parameters}`);
    const signature = sign(algorithm === 'ed25519' ? null : 'sha256', Buffer.from(lines.join('\n')), { key, dsaEncoding: 'ieee-p1363' }).toString('base64');
    return { ...(request.body !== undefined ? { 'content-digest': headers['content-digest'] } : {}), 'signature-input': `sig1=${parameters}`, signature: `sig1=:${signature}:` };
  };
}
