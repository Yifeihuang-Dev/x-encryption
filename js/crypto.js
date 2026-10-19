/**
 * ENC1 加密核心
 *
 * 设计要点（改动前请先读）：
 * 1. 口令永远不直接当密钥，必须经 PBKDF2 派生。
 * 2. 三个因子是「合并派生」而不是分层加密：缺少任何一个都凑不出 master，
 *    攻击者无法分头击破。
 * 3. nonce 由 domain(1B) + 每文件随机 base(7B) + 块序号(4B) 组成，
 *    保证同一密钥下 nonce 全局唯一，不触碰 GCM 的 64GiB 单一 nonce 上限。
 * 4. AAD 必须包含完整文件头 + domain + 块序号 + 总块数：
 *    - 含文件头 → 攻击者改不动 salt / KDF 轮数 / 因子配置（防降级攻击）
 *    - 含块序号 → 防块重排
 *    - 含总块数 → 配合长度校验防截断回滚
 */

import { t } from './i18n.js';

export const MAGIC = 'ENC1';
export const FORMAT_VERSION = 1;

// KDF 标识
export const KDF_PBKDF2_SHA256 = 1;
export const DEFAULT_PBKDF2_ITERATIONS = 600_000; // OWASP 对 PBKDF2-HMAC-SHA256 的建议量级

// 因子长度
export const K1_BYTES = 32; // 口令派生
export const K2_BYTES = 32; // 证书文件
export const K3_BYTES = 20; // 硬件密钥 / 恢复码（160 bit，正好 32 个 Base32 字符）
export const MASTER_BYTES = 32;

// 分块
export const CHUNK_SIZE_LOG2 = 20; // 1 MiB
export const CHUNK_SIZE = 1 << CHUNK_SIZE_LOG2;
export const TAG_BYTES = 16;

// nonce domain（互不重叠，避免不同用途复用 nonce）
export const DOMAIN_VERIFY = 0x01;
export const DOMAIN_META = 0x02;
export const DOMAIN_DATA = 0x03;

export const VERIFY_PLAINTEXT = new Uint8Array([
  0x45, 0x4e, 0x43, 0x31, 0x20, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x20, 0x63, 0x6f, 0x6e, 0x73,
  0x74, 0x61, 0x6e, 0x74, 0x20, 0x76, 0x31, 0x20, 0x2d, 0x20, 0x6f, 0x6b, 0x21, 0x21, 0x21, 0x21,
]); // "ENC1 verify constant v1 - ok!!!!" 恰好 32 字节

export const utf8 = (s) => new TextEncoder().encode(s);

export function randomBytes(n) {
  const b = new Uint8Array(n);
  // getRandomValues 单次上限 65536 字节（规范限制），大块要分批
  const MAX = 65536;
  for (let off = 0; off < n; off += MAX) {
    crypto.getRandomValues(b.subarray(off, Math.min(off + MAX, n)));
  }
  return b;
}

export async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

export function concat(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let p = 0;
  for (const a of arrays) {
    out.set(a, p);
    p += a.length;
  }
  return out;
}

/** 常量时间比较，避免通过耗时差异泄露信息 */
export function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** 因子 1：口令 → 32 字节 */
export async function derivePasswordKey(password, salt, iterations = DEFAULT_PBKDF2_ITERATIONS) {
  const material = await crypto.subtle.importKey('raw', utf8(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    material,
    K1_BYTES * 8,
  );
  return new Uint8Array(bits);
}

export async function hkdf(ikm, salt, info, lengthBytes) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: typeof info === 'string' ? utf8(info) : info },
    key,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

/**
 * 合并三个因子得到主密钥。
 * 缺失的因子用等长全零填充 —— 此时安全性自然退化为「剩余因子的组合强度」，
 * 这是预期行为，不是漏洞。
 */
export async function combineFactors(k1, k2, k3, salt) {
  const ikm = concat(
    k1 ?? new Uint8Array(K1_BYTES),
    k2 ?? new Uint8Array(K2_BYTES),
    k3 ?? new Uint8Array(K3_BYTES),
  );
  return hkdf(ikm, salt, 'ENC1 v1 master', MASTER_BYTES);
}

export function importAesKey(raw) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** 12 字节 nonce：domain(1) ‖ base(7) ‖ counter(4, 大端) */
export function buildNonce(domain, base, counter) {
  if (base.length !== 7) throw new Error('nonce base 必须是 7 字节');
  const n = new Uint8Array(12);
  n[0] = domain;
  n.set(base, 1);
  new DataView(n.buffer).setUint32(8, counter >>> 0, false);
  return n;
}

export async function seal(key, nonce, aad, plaintext) {
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: TAG_BYTES * 8 },
    key,
    plaintext,
  );
  return new Uint8Array(ct); // Web Crypto 输出 = 密文 ‖ tag
}

export async function open(key, nonce, aad, ciphertext) {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: TAG_BYTES * 8 },
    key,
    ciphertext,
  );
  return new Uint8Array(pt);
}

/* ---------- Base32 (RFC 4648)，用于恢复码 ---------- */

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(str) {
  const clean = String(str).replace(/[-\s]/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(t('err_b32'));
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/** 恢复码：20 字节 → 32 字符 → 8 组，形如 ABCD-EFGH-... */
export function formatRecoveryCode(bytes) {
  const s = base32Encode(bytes);
  return s.match(/.{1,4}/g).join('-');
}

export function parseRecoveryCode(text) {
  const bytes = base32Decode(text);
  if (bytes.length !== K3_BYTES) {
    throw new Error(t('err_rc_len', { bytes: K3_BYTES }));
  }
  return bytes;
}

/* ---------- Base64，用于证书文件 ---------- */

export function toBase64(bytes) {
  let s = '';
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s);
}

export function fromBase64(str) {
  const clean = String(str).replace(/\s+/g, '');
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function fingerprint16(bytes) {
  const h = await sha256(bytes);
  return h.slice(0, 16);
}

/** 展示用：把字节转成短横线分组的十六进制，方便人工核对指纹 */
export function hex(bytes, groupSize = 4) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  if (!groupSize) return s;
  return s.match(new RegExp(`.{1,${groupSize}}`, 'g')).join('-');
}
