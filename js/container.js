/**
 * ENC1 容器格式
 *
 * 文件布局（全部为大端）：
 *   [header : 88 + credentialIdLen]
 *   [verify : 48]                    加密的固定常量，用于「先验证再解密全文」
 *   [metaLen: 2]                     元数据密文长度（明文，内容本身是加密的）
 *   [meta   : metaLen]               加密的文件名/类型/大小
 *   [chunk0 .. chunkN-1]             每块 1MiB 明文 → 明文长度+16(tag)
 *
 * header 字段：
 *   0   4  magic "ENC1"
 *   4   1  version
 *   5   1  flags (bit0 需证书, bit1 需硬件密钥)
 *   6   1  kdfId (1 = PBKDF2-SHA256)
 *   7   4  kdfIterations
 *   11  16 salt
 *   27  16 certId (sha256(证书密钥) 前 16 字节)
 *   43  16 credentialIdHash
 *   59  16 prfSalt
 *   75  7  nonceBase
 *   82  1  chunkSizeLog2
 *   83  4  totalChunks
 *   87  1  credentialIdLen
 *   88  N  credentialId
 *
 * 为什么整段 header 都要进 AAD：
 *   盐、KDF 轮数、因子开关全部写在这里。若不被认证，攻击者可以把
 *   「需要证书/需要硬件密钥」的位清零、把 60 万轮改成 1000 轮来降级攻击。
 *   把 header 放进 AAD 后，任何改动都会导致认证失败。
 */

import {
  MAGIC,
  FORMAT_VERSION,
  KDF_PBKDF2_SHA256,
  DEFAULT_PBKDF2_ITERATIONS,
  CHUNK_SIZE,
  CHUNK_SIZE_LOG2,
  TAG_BYTES,
  DOMAIN_VERIFY,
  DOMAIN_META,
  DOMAIN_DATA,
  VERIFY_PLAINTEXT,
  buildNonce,
  concat,
  derivePasswordKey,
  combineFactors,
  importAesKey,
  seal,
  open,
  sha256,
  randomBytes,
  timingSafeEqual,
  utf8,
} from './crypto.js';
import { certId } from './certfile.js';
import { t } from './i18n.js';

export const HEADER_FIXED_LEN = 88;
export const VERIFY_BLOCK_LEN = VERIFY_PLAINTEXT.length + TAG_BYTES; // 48
export const META_LEN_FIELD = 2;

export const FLAG_CERT = 0x01;
export const FLAG_WEBAUTHN = 0x02;

const ZERO16 = new Uint8Array(16);

/* ---------------- header 编解码 ---------------- */

export function buildHeader({
  flags,
  iterations = DEFAULT_PBKDF2_ITERATIONS,
  salt,
  certIdBytes = ZERO16,
  credentialIdHash = ZERO16,
  prfSalt,
  nonceBase,
  totalChunks,
  credentialId = null,
}) {
  const credLen = credentialId ? credentialId.length : 0;
  if (credLen > 255) throw new Error(t('err_cred_long'));
  const buf = new Uint8Array(HEADER_FIXED_LEN + credLen);
  const dv = new DataView(buf.buffer);

  buf.set(utf8(MAGIC), 0);
  dv.setUint8(4, FORMAT_VERSION);
  dv.setUint8(5, flags);
  dv.setUint8(6, KDF_PBKDF2_SHA256);
  dv.setUint32(7, iterations, false);
  buf.set(salt, 11);
  buf.set(certIdBytes, 27);
  buf.set(credentialIdHash, 43);
  buf.set(prfSalt, 59);
  buf.set(nonceBase, 75);
  dv.setUint8(82, CHUNK_SIZE_LOG2);
  dv.setUint32(83, totalChunks, false);
  dv.setUint8(87, credLen);
  if (credLen) buf.set(credentialId, HEADER_FIXED_LEN);
  return buf;
}

export function parseHeader(bytes) {
  if (bytes.length < HEADER_FIXED_LEN) throw new Error(t('err_too_short'));
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magic = new TextDecoder().decode(bytes.slice(0, 4));
  if (magic !== MAGIC) throw new Error(t('err_not_enc1'));

  const version = dv.getUint8(4);
  if (version !== FORMAT_VERSION) throw new Error(t('err_bad_version', { v: version }));

  const flags = dv.getUint8(5);
  const kdfId = dv.getUint8(6);
  if (kdfId !== KDF_PBKDF2_SHA256) throw new Error(t('err_bad_kdf', { id: kdfId }));

  const iterations = dv.getUint32(7, false);
  // 轮数直接决定 CPU 开销，必须设上下限：否则有人把文件头改成几十亿轮，
  // 就能让你（或任何试图打开它的人）卡死。这是拒绝服务，不是解密失败。
  if (iterations < 1_000 || iterations > 10_000_000) {
    throw new Error(t('err_bad_rounds'));
  }
  const salt = bytes.slice(11, 27);
  const certIdBytes = bytes.slice(27, 43);
  const credentialIdHash = bytes.slice(43, 59);
  const prfSalt = bytes.slice(59, 75);
  const nonceBase = bytes.slice(75, 82);
  const chunkSizeLog2 = dv.getUint8(82);
  if (chunkSizeLog2 < 12 || chunkSizeLog2 > 28) {
    throw new Error(t('err_bad_chunk'));
  }
  const totalChunks = dv.getUint32(83, false);
  const credLen = dv.getUint8(87);

  if (bytes.length < HEADER_FIXED_LEN + credLen) throw new Error(t('err_header_trunc'));
  const credentialId = credLen ? bytes.slice(HEADER_FIXED_LEN, HEADER_FIXED_LEN + credLen) : null;
  const headerLen = HEADER_FIXED_LEN + credLen;

  return {
    version,
    flags,
    kdfId,
    iterations,
    salt,
    certIdBytes,
    credentialIdHash,
    prfSalt,
    nonceBase,
    chunkSize: 1 << chunkSizeLog2,
    totalChunks,
    credentialId,
    headerLen,
    headerBytes: bytes.slice(0, headerLen),
    needCert: (flags & FLAG_CERT) !== 0,
    needWebauthn: (flags & FLAG_WEBAUTHN) !== 0,
  };
}

/** 从文件头部读取并解析（只读前若干字节，不会把整个文件读进内存） */
export async function readHeader(source) {
  const probeLen = Math.min(source.size, HEADER_FIXED_LEN + 512);
  const first = await source.read(0, probeLen);
  const credLen = first[87];
  const headerLen = HEADER_FIXED_LEN + credLen;
  if (source.size < headerLen + VERIFY_BLOCK_LEN + META_LEN_FIELD) {
    throw new Error(t('err_incomplete'));
  }
  const bytes = headerLen > first.length ? await source.read(0, headerLen) : first.slice(0, headerLen);
  const header = parseHeader(bytes);
  header.fileSize = source.size;
  return header;
}

/* ---------------- AAD / nonce ---------------- */

function u32be(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, false);
  return b;
}

function buildAad(headerBytes, domain, index, total) {
  return concat(headerBytes, new Uint8Array([domain]), u32be(index), u32be(total));
}

/* ---------------- 数据源适配 ---------------- */

export function memorySource(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return {
    size: arr.length,
    async read(offset, length) {
      return arr.slice(offset, offset + length);
    },
  };
}

export function fileSource(file) {
  return {
    size: file.size,
    async read(offset, length) {
      const buf = await file.slice(offset, offset + length).arrayBuffer();
      return new Uint8Array(buf);
    },
  };
}

/* ---------------- 加密 ---------------- */

/**
 * @param {object} args
 * @param {{size:number,read:Function}} args.source
 * @param {object} args.meta 元数据（文件名/类型/大小）
 * @param {string} args.password
 * @param {Uint8Array|null} args.certKey 第二因子
 * @param {Uint8Array|null} args.k3 第三因子（硬件密钥 PRF 输出）
 * @param {Uint8Array|null} args.credentialId WebAuthn 凭证 ID，写入 header 以便解密时找回
 * @param {{write:Function}} args.sink
 * @param {Function} args.onProgress
 */
export async function encryptToSink({
  source,
  meta,
  password,
  certKey = null,
  k3 = null,
  credentialId = null,
  prfSalt = null,
  iterations = DEFAULT_PBKDF2_ITERATIONS,
  sink,
  onProgress = () => {},
}) {
  const useCert = !!certKey;
  const useWebauthn = !!k3 && !!credentialId;
  if (k3 && !credentialId) throw new Error(t('err_k3_no_cred'));

  const salt = randomBytes(16);
  // prfSalt 允许外部传入：硬件密钥的 PRF 必须在加密前先算，而 prfSalt 要写进文件头
  const prfSaltInput = prfSalt || randomBytes(16);
  const nonceBase = randomBytes(7);
  const totalChunks = source.size === 0 ? 0 : Math.ceil(source.size / CHUNK_SIZE);

  onProgress('prepare', 0, totalChunks);

  const flags = (useCert ? FLAG_CERT : 0) | (useWebauthn ? FLAG_WEBAUTHN : 0);
  const header = buildHeader({
    flags,
    iterations,
    salt,
    certIdBytes: useCert ? await certId(certKey) : ZERO16,
    credentialIdHash: useWebauthn ? (await sha256(credentialId)).slice(0, 16) : ZERO16,
    prfSalt: prfSaltInput,
    nonceBase,
    totalChunks,
    credentialId: useWebauthn ? credentialId : null,
  });

  const k1 = await derivePasswordKey(password, salt, iterations);
  const master = await combineFactors(k1, certKey, k3, salt);
  const aesKey = await importAesKey(master);
  wipe(k1, master);

  let written = 0;
  const put = async (bytes) => {
    await sink.write(bytes);
    written += bytes.length;
  };

  // 1) header
  await put(header);

  // 2) 验证块
  const verifyNonce = buildNonce(DOMAIN_VERIFY, nonceBase, 0);
  await put(await seal(aesKey, verifyNonce, buildAad(header, DOMAIN_VERIFY, 0, 1), VERIFY_PLAINTEXT));

  // 3) 元数据块
  const metaPlain = utf8(JSON.stringify(meta));
  const metaNonce = buildNonce(DOMAIN_META, nonceBase, 0);
  const metaCipher = await seal(aesKey, metaNonce, buildAad(header, DOMAIN_META, 0, 1), metaPlain);
  if (metaCipher.length > 0xffff) throw new Error(t('err_meta_long'));
  const metaLenBytes = new Uint8Array(2);
  new DataView(metaLenBytes.buffer).setUint16(0, metaCipher.length, false);
  await put(metaLenBytes);
  await put(metaCipher);

  // 4) 数据块
  let offset = 0;
  for (let i = 0; i < totalChunks; i++) {
    const isLast = i === totalChunks - 1;
    const plainLen = isLast ? source.size - offset : CHUNK_SIZE;
    const chunk = await source.read(offset, plainLen);
    const nonce = buildNonce(DOMAIN_DATA, nonceBase, i);
    const aad = buildAad(header, DOMAIN_DATA, i, totalChunks);
    await put(await seal(aesKey, nonce, aad, chunk));
    offset += plainLen;
    onProgress('encrypt', i + 1, totalChunks);
  }

  return { headerBytes: header, header: parseHeader(header), meta, prfSalt: prfSaltInput, written };
}

/* ---------------- 解密 ---------------- */

/**
 * 校验提供的因子与文件头声明是否一致。
 * 先做这一步，可以让「证书拿错」立刻反馈，不用白跑一遍 KDF。
 */
export async function checkFactors(header, { certKey = null, k3 = null }) {
  if (header.needCert && !certKey) throw new Error(t('err_need_cert'));
  if (header.needWebauthn && !k3) throw new Error(t('err_need_k3'));
  if (header.needCert && certKey) {
    const actual = await certId(certKey);
    if (!timingSafeEqual(actual, header.certIdBytes)) {
      throw new Error(t('err_cert_mismatch'));
    }
  }
  if (header.needWebauthn && !header.credentialId) {
    throw new Error(t('err_missing_credid'));
  }
  return true;
}

export async function decryptToSink({
  source,
  password,
  certKey = null,
  k3 = null,
  sink,
  onProgress = () => {},
}) {
  const header = await readHeader(source);
  await checkFactors(header, { certKey, k3 });

  // 先用文件大小反推最后一块明文长度：既能定位，也能发现截断/追加
  const tail = source.size - header.headerLen - VERIFY_BLOCK_LEN - META_LEN_FIELD;
  if (tail < 0) throw new Error(t('err_incomplete'));

  const metaLenBuf = await source.read(header.headerLen + VERIFY_BLOCK_LEN, META_LEN_FIELD);
  const metaLen = new DataView(metaLenBuf.buffer, metaLenBuf.byteOffset, 2).getUint16(0, false);
  const dataStart = header.headerLen + VERIFY_BLOCK_LEN + META_LEN_FIELD + metaLen;
  const dataLen = source.size - dataStart;

  const { totalChunks, chunkSize } = header;
  let lastPlainLen = 0;
  if (totalChunks > 0) {
    const fixedLen = (totalChunks - 1) * (chunkSize + TAG_BYTES);
    const lastCipherLen = dataLen - fixedLen;
    lastPlainLen = lastCipherLen - TAG_BYTES;
    // 最后一块明文长度必须落在 (0, chunkSize]：0 或超过块大小都说明文件被改过
    if (lastPlainLen <= 0 || lastPlainLen > chunkSize) {
      throw new Error(t('err_size_mismatch'));
    }
  } else if (dataLen !== 0) {
    throw new Error(t('err_size_mismatch'));
  }

  onProgress('kdf', 0, totalChunks);
  const k1 = await derivePasswordKey(password, header.salt, header.iterations);
  const master = await combineFactors(k1, certKey, k3, header.salt);
  const aesKey = await importAesKey(master);
  wipe(k1, master);

  onProgress('verify', 0, totalChunks);
  const verifyCipher = await source.read(header.headerLen, VERIFY_BLOCK_LEN);
  const verifyNonce = buildNonce(DOMAIN_VERIFY, header.nonceBase, 0);
  let verifyPlain;
  try {
    verifyPlain = await open(aesKey, verifyNonce, buildAad(header.headerBytes, DOMAIN_VERIFY, 0, 1), verifyCipher);
  } catch {
    throw new Error(t('err_key_or_corrupt'));
  }
  if (!timingSafeEqual(verifyPlain, VERIFY_PLAINTEXT)) {
    throw new Error(t('err_key_or_corrupt'));
  }

  onProgress('meta', 0, totalChunks);
  const metaCipher = await source.read(header.headerLen + VERIFY_BLOCK_LEN + META_LEN_FIELD, metaLen);
  const metaNonce = buildNonce(DOMAIN_META, header.nonceBase, 0);
  let metaPlain;
  try {
    metaPlain = await open(aesKey, metaNonce, buildAad(header.headerBytes, DOMAIN_META, 0, 1), metaCipher);
  } catch {
    throw new Error(t('err_key_or_corrupt'));
  }
  let meta;
  try {
    meta = JSON.parse(new TextDecoder().decode(metaPlain));
  } catch {
    throw new Error(t('err_meta_broken'));
  }

  let offset = dataStart;
  for (let i = 0; i < totalChunks; i++) {
    const plainLen = i === totalChunks - 1 ? lastPlainLen : chunkSize;
    const cipherLen = plainLen + TAG_BYTES;
    const cipher = await source.read(offset, cipherLen);
    const nonce = buildNonce(DOMAIN_DATA, header.nonceBase, i);
    const aad = buildAad(header.headerBytes, DOMAIN_DATA, i, totalChunks);
    let plain;
    try {
      plain = await open(aesKey, nonce, aad, cipher);
    } catch {
      throw new Error(t('err_key_or_corrupt'));
    }
    await sink.write(plain);
    offset += cipherLen;
    onProgress('decrypt', i + 1, totalChunks);
  }

  return { meta, header };
}

function wipe(...arrays) {
  for (const a of arrays) if (a && a.fill) a.fill(0);
}

/** 给 UI 用：这个文件到底需要哪些因子 */
export function describeFactors(header) {
  const list = [{ key: 'password', label: '口令', available: true }];
  if (header.needCert) {
    list.push({ key: 'cert', label: '证书文件', id: header.certIdBytes });
  }
  if (header.needWebauthn) {
    list.push({ key: 'webauthn', label: '硬件密钥 / 恢复码', id: header.credentialIdHash });
  }
  return list;
}

/**
 * 只判断「这组因子对不对」的轻量入口，专为暴力破解测试准备：
 * 不读、不解数据块，只做「派生主密钥 → 解 48 字节验证块 → 比对」。
 *
 * 派生与校验代码与 decryptToSink 完全一致（同一批函数），
 * 所以这里测出来的速率就是真实攻击者的速率，不是某个近似实现的速度。
 */
export async function verifyPasswordAt(header, verifyCipher, { password = '', certKey = null, k3 = null } = {}) {
  const k1 = await derivePasswordKey(password, header.salt, header.iterations);
  const master = await combineFactors(k1, certKey, k3, header.salt);
  const aesKey = await importAesKey(master);
  wipe(k1, master);
  try {
    const verifyPlain = await open(
      aesKey,
      buildNonce(DOMAIN_VERIFY, header.nonceBase, 0),
      buildAad(header.headerBytes, DOMAIN_VERIFY, 0, 1),
      verifyCipher,
    );
    return timingSafeEqual(verifyPlain, VERIFY_PLAINTEXT);
  } catch {
    return false;
  }
}
