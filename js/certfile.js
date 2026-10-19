/**
 * 证书文件（第二因子：持有物）
 *
 * 证书文件本质是一份 32 字节的随机密钥材料，用可打印的文本格式封装，
 * 方便备份、打印、放进 U 盘或密码管理器。
 *
 * 安全约束：
 * - 必须独立随机生成，绝不能由口令派生，否则第二因子形同虚设。
 * - 文件里带的 Checksum 只能发现「损坏/截断」，防不住蓄意改写
 *   （改写者可以重算校验和）。不要向用户承诺它具备防篡改能力。
 */

import {
  K2_BYTES,
  K3_BYTES,
  randomBytes,
  sha256,
  toBase64,
  fromBase64,
  formatRecoveryCode,
  parseRecoveryCode,
  timingSafeEqual,
} from './crypto.js';
import { t } from './i18n.js';

const BEGIN = '-----BEGIN ENC1 CERTIFICATE-----';
const END = '-----END ENC1 CERTIFICATE-----';

export async function generateCertKey() {
  return randomBytes(K2_BYTES);
}

/** 证书 ID：既是文件内的标识，也是密文头部里记录的指纹（用于匹配/防误用） */
export async function certId(certKey) {
  const h = await sha256(certKey);
  return h.slice(0, 16);
}

export async function certChecksum(certKey) {
  const h = await sha256(concatBytes(certKey, new TextEncoder().encode('checksum')));
  return h.slice(0, 8);
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export async function serializeCertificate(certKey, { label = '' } = {}) {
  const id = await certId(certKey);
  const checksum = await certChecksum(certKey);
  const body = toBase64(certKey);
  const lines = [
    BEGIN,
    'Version: 1',
    `Id: ${toBase64(id)}`,
    `Created: ${new Date().toISOString()}`,
    `Checksum: ${toBase64(checksum)}`,
    `Label: ${label || 'ENC1 certificate'}`,
    '',
    body,
    END,
    '',
  ];
  return lines.join('\n');
}

export async function parseCertificate(text) {
  const src = String(text);
  const start = src.indexOf(BEGIN);
  const end = src.indexOf(END);
  if (start < 0 || end < 0 || end <= start) {
    throw new Error(t('err_cert_fmt'));
  }
  const inner = src.slice(start + BEGIN.length, end).trim();
  const nl = inner.indexOf('\n\n');
  if (nl < 0) throw new Error(t('err_cert_nodata'));

  const headerText = inner.slice(0, nl);
  const bodyText = inner.slice(nl + 2);

  const fields = {};
  for (const line of headerText.split('\n')) {
    const m = line.match(/^([A-Za-z]+):\s*(.*)$/);
    if (m) fields[m[1].toLowerCase()] = m[2].trim();
  }

  let certKey;
  try {
    certKey = fromBase64(bodyText);
  } catch {
    throw new Error(t('err_cert_key'));
  }
  if (certKey.length !== K2_BYTES) {
    throw new Error(t('err_cert_len', { bytes: K2_BYTES }));
  }

  let checksumOk = null;
  if (fields.checksum) {
    try {
      const expected = fromBase64(fields.checksum);
      const actual = await certChecksum(certKey);
      checksumOk = timingSafeEqual(expected, actual);
    } catch {
      checksumOk = false;
    }
  }

  return {
    certKey,
    id: await certId(certKey),
    declaredId: fields.id ? fromBase64(fields.id) : null,
    created: fields.created || null,
    label: fields.label || null,
    checksumOk,
  };
}

/**
 * 恢复码（第三因子的等价备份）
 * 它就是 k3 本身，因此与硬件密钥派生的结果完全一致，可以互换。
 */
export function generateRecoveryCode() {
  const k3 = randomBytes(K3_BYTES);
  return { k3, text: formatRecoveryCode(k3) };
}

export function decodeRecoveryCode(text) {
  return parseRecoveryCode(text);
}

export const CERT_FILE_EXT = '.enc1cert';
