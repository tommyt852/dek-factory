/**
 * DEK factory crypto — Web Crypto only.
 * Schema MUST match chatroom (www/js/crypto.js) and ARTIFACTS.md.
 *
 * Wrap: PBKDF2-SHA-256 (600000) → 32-byte KEK → AES-256-GCM wrap DEK
 *   store salt(16), iv(12), tag(16), wrappedKey(ciphertext only)
 * History: AES-256-GCM with DEK; separate iv/tag/ciphertext; revision
 */

export const VERSION = 1;
export const CIPHER = 'AES-256-GCM';
export const KDF = 'PBKDF2-SHA-256';
export const KDF_ITERATIONS = 600000;
export const WRAP = 'AES-256-GCM';
export const DEK_BYTES = 32;
export const SALT_BYTES = 16;
export const IV_BYTES = 12;
export const TAG_BYTES = 16;
export const KEK_BYTES = 32;
export const MIN_PASSPHRASE_LENGTH = 12;

export const PASSPHRASE_DENYLIST = [
  'demo-pass-only',
  'password',
  'passphrase',
  '123456789012',
  'changeme',
  'secret',
  'admin',
  'letmein',
  'qwertyuiopas',
];

export function bufToB64(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function b64ToBuf(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.byteLength + b.byteLength);
  out.set(new Uint8Array(a), 0);
  out.set(new Uint8Array(b), a.byteLength);
  return out;
}

/** Split Web Crypto sealed blob into ciphertext + trailing 16-byte tag. */
function splitSealed(sealed) {
  const sealedBytes = new Uint8Array(sealed);
  if (sealedBytes.length < TAG_BYTES) {
    throw new Error('Sealed ciphertext too short');
  }
  const tag = sealedBytes.slice(sealedBytes.length - TAG_BYTES);
  const ciphertext = sealedBytes.slice(0, sealedBytes.length - TAG_BYTES);
  return { tag, ciphertext };
}

export function assertPassphraseStrength(passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`密碼太弱：至少需要 ${MIN_PASSPHRASE_LENGTH} 個字元`);
  }
  const lower = passphrase.toLowerCase();
  if (PASSPHRASE_DENYLIST.some((w) => w.toLowerCase() === lower)) {
    throw new Error('密碼太弱：命中拒絕清單，請換更強的口令');
  }
}

export function generateDek() {
  return crypto.getRandomValues(new Uint8Array(DEK_BYTES));
}

export async function deriveKek(passphrase, saltBytes, iterations = KDF_ITERATIONS) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function importDekKey(dekBytes, extractable = false) {
  const raw = dekBytes instanceof Uint8Array ? dekBytes : new Uint8Array(dekBytes);
  if (raw.byteLength !== DEK_BYTES) {
    throw new Error(`無效 DEK：預期 ${DEK_BYTES} bytes，實際 ${raw.byteLength}`);
  }
  return crypto.subtle.importKey(
    'raw',
    raw,
    { name: 'AES-GCM', length: 256 },
    extractable,
    ['encrypt', 'decrypt'],
  );
}

export async function exportDekRaw(dekKey) {
  const raw = await crypto.subtle.exportKey('raw', dekKey);
  return new Uint8Array(raw);
}

/**
 * AES-256-GCM encrypt; returns separate iv / tag / ciphertext (tag not appended).
 * @param {CryptoKey} key
 * @param {BufferSource} plaintext
 * @param {Uint8Array} [iv]
 */
export async function aesGcmEncrypt(key, plaintext, iv) {
  const ivBytes = iv || crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: ivBytes },
    key,
    plaintext,
  );
  const { tag, ciphertext } = splitSealed(sealed);
  return { iv: ivBytes, tag, ciphertext };
}

/**
 * AES-256-GCM decrypt with separate tag (concatenated for Web Crypto).
 */
export async function aesGcmDecrypt(key, iv, tag, ciphertext) {
  const ctWithTag = concatBytes(ciphertext, tag);
  try {
    return await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(iv) },
      key,
      ctWithTag,
    );
  } catch {
    throw new Error('解密失敗（密碼錯誤或資料損壞）');
  }
}

/** Wrap DEK bytes with passphrase → keyring user fields (base64). */
export async function wrapDek(dekBytes, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const kek = await deriveKek(passphrase, salt);
  const raw =
    dekBytes instanceof Uint8Array ? dekBytes : new Uint8Array(dekBytes);
  const { iv, tag, ciphertext } = await aesGcmEncrypt(kek, raw);
  return {
    salt: bufToB64(salt),
    iv: bufToB64(iv),
    tag: bufToB64(tag),
    wrappedKey: bufToB64(ciphertext),
  };
}

/** Unwrap DEK from keyring user entry → raw 32-byte Uint8Array. */
export async function unwrapDek(entry, passphrase, iterations) {
  const salt = b64ToBuf(entry.salt);
  const iv = b64ToBuf(entry.iv);
  const tag = b64ToBuf(entry.tag);
  const wrapped = b64ToBuf(entry.wrappedKey);
  const kek = await deriveKek(
    passphrase,
    salt,
    iterations || entry.kdfIterations || KDF_ITERATIONS,
  );
  const rawDek = await aesGcmDecrypt(kek, iv, tag, wrapped);
  const bytes = new Uint8Array(rawDek);
  if (bytes.byteLength !== DEK_BYTES) {
    throw new Error(`無效 DEK 長度：${bytes.byteLength}`);
  }
  return bytes;
}

export function createEmptyKeyring() {
  return {
    version: VERSION,
    cipher: CIPHER,
    kdf: KDF,
    kdfIterations: KDF_ITERATIONS,
    wrap: WRAP,
    users: [],
  };
}

export function createEmptyMessages() {
  return {
    version: VERSION,
    messages: [],
  };
}

/**
 * Encrypt messages object/string → chat-history.enc shape.
 * Pretty-prints JSON with null, 2 to match prior Node factory.
 */
export async function encryptHistory(dekKeyOrBytes, plaintext, revision = 1) {
  const dekKey =
    dekKeyOrBytes instanceof CryptoKey
      ? dekKeyOrBytes
      : await importDekKey(dekKeyOrBytes, false);

  const utf8 =
    typeof plaintext === 'string'
      ? new TextEncoder().encode(plaintext)
      : new TextEncoder().encode(JSON.stringify(plaintext, null, 2));

  const { iv, tag, ciphertext } = await aesGcmEncrypt(dekKey, utf8);
  const rev = typeof revision === 'number' && revision >= 1 ? revision : 1;
  return {
    version: VERSION,
    cipher: CIPHER,
    revision: rev,
    iv: bufToB64(iv),
    tag: bufToB64(tag),
    ciphertext: bufToB64(ciphertext),
  };
}

/** Decrypt chat-history.enc → UTF-8 JSON string. */
export async function decryptHistory(dekKeyOrBytes, enc) {
  const dekKey =
    dekKeyOrBytes instanceof CryptoKey
      ? dekKeyOrBytes
      : await importDekKey(dekKeyOrBytes, false);
  const plainBuf = await aesGcmDecrypt(
    dekKey,
    b64ToBuf(enc.iv),
    b64ToBuf(enc.tag),
    b64ToBuf(enc.ciphertext),
  );
  return new TextDecoder().decode(plainBuf);
}

export function nextRevision(enc) {
  if (!enc || typeof enc !== 'object') return 1;
  const cur = typeof enc.revision === 'number' ? enc.revision : 1;
  return cur + 1;
}

export function parseDekFileBytes(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  if (bytes.byteLength === DEK_BYTES) {
    return bytes;
  }
  // Try UTF-8 base64 text
  const text = new TextDecoder().decode(bytes).trim();
  try {
    const decoded = b64ToBuf(text);
    if (decoded.byteLength === DEK_BYTES) return decoded;
  } catch {
    /* fall through */
  }
  throw new Error(
    `無效 .dek：預期 ${DEK_BYTES} bytes（原始二進位）或同等 base64，實際 ${bytes.byteLength} bytes`,
  );
}
