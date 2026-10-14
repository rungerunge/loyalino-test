'use strict';
const { createCipheriv, createDecipheriv, hkdfSync, randomBytes, createHash } = require('node:crypto');
const magic = Buffer.from('OKAYIOS1');
exports.sha = b => createHash('sha256').update(b).digest('hex');
const MAX_BYTES = 512 * 1024 * 1024;
function validate(context, direction) {
  if (!context || Object.keys(context).sort().join(',') !== 'operation,workflowSha' ||
      !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(context.operation) ||
      !/^[a-f0-9]{40}$/.test(context.workflowSha) || !['input', 'output'].includes(direction)) throw Error('CONTEXT');
}
function derived(key, context, direction) {
  validate(context, direction);
  if (!Buffer.isBuffer(key) || key.length !== 32) throw Error('KEY');
  return Buffer.from(hkdfSync('sha256', key, Buffer.from(context.operation), Buffer.from(`okayscale-ios-v1:${context.workflowSha}:${direction}`), 32));
}
exports.seal = (plain, key, context, direction) => {
  validate(context, direction);
  if (!Buffer.isBuffer(plain) || plain.length < 1 || plain.length > MAX_BYTES) throw Error('PAYLOAD');
  const header = Buffer.from(JSON.stringify({ operation: context.operation, workflowSha: context.workflowSha, direction }));
  const length = Buffer.alloc(4); length.writeUInt32BE(header.length);
  const nonce = randomBytes(12), subkey = derived(key, context, direction);
  try {
    const cipher = createCipheriv('aes-256-gcm', subkey, nonce);
    cipher.setAAD(Buffer.concat([magic, length, header]));
    const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
    return Buffer.concat([magic, length, header, nonce, cipher.getAuthTag(), encrypted]);
  } finally { subkey.fill(0); }
};
exports.open = (sealed, key, context, direction) => {
  validate(context, direction);
  if (!Buffer.isBuffer(sealed) || sealed.length > MAX_BYTES + 1064 || sealed.length < 41 || !sealed.subarray(0, 8).equals(magic)) throw Error('ENVELOPE');
  const n = sealed.readUInt32BE(8);
  if (n < 1 || n > 1024 || sealed.length <= 40 + n) throw Error('HEADER');
  const actual = JSON.parse(sealed.subarray(12, 12 + n));
  if (JSON.stringify(actual) !== JSON.stringify({ operation: context.operation, workflowSha: context.workflowSha, direction })) throw Error('BINDING');
  const subkey = derived(key, context, direction); let partial;
  try {
    const decipher = createDecipheriv('aes-256-gcm', subkey, sealed.subarray(12 + n, 24 + n));
    decipher.setAAD(sealed.subarray(0, 12 + n)); decipher.setAuthTag(sealed.subarray(24 + n, 40 + n));
    partial = decipher.update(sealed.subarray(40 + n));
    return Buffer.concat([partial, decipher.final()]);
  } finally { subkey.fill(0); partial?.fill(0); }
};
