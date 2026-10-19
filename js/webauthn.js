/**
 * 第三因子：WebAuthn / FIDO2 硬件密钥（Touch ID、Windows Hello、YubiKey 等）
 *
 * 重要事实，改动前务必理解：
 * 1. 指纹永远不会离开设备，浏览器也拿不到生物特征，只拿到「验证通过」的断言
 *    和一段由安全密钥派生的 PRF 输出。
 * 2. 密钥派生走 WebAuthn 的 PRF 扩展（prf.eval）。它是唯一能稳定输出密钥材料的路径。
 * 3. 【不能用断言签名做降级方案】FIDO2 主流算法是 ES256（ECDSA），其签名含随机数、
 *    每次都不一样，无法稳定派生密钥。因此本模块在 PRF 不可用时直接拒绝启用第三因子，
 *    而不是悄悄退化成一个不安全/不可用的方案。
 * 4. 因为第三因子可能失效（换机器、重录指纹、丢钥匙），必须由 certfile 生成的
 *    「恢复码」做等价备份 —— 恢复码就是 k3 本身，与 PRF 输出可互换。
 */

import { K3_BYTES, randomBytes } from './crypto.js';
import { t } from './i18n.js';

const STORAGE_KEY = 'enc1.webauthn.credentials';

export function isWebAuthnAvailable() {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials;
}

export function isSecureContextOk() {
  // WebAuthn 只在安全上下文可用：https 或 localhost
  return typeof window !== 'undefined' && window.isSecureContext;
}

function friendlyError(err) {
  const name = err?.name || '';
  if (name === 'NotAllowedError') return t('wa_notallowed');
  if (name === 'InvalidStateError') return t('wa_invalidstate');
  if (name === 'NotSupportedError') return t('wa_notsupported');
  if (name === 'SecurityError') return t('wa_security');
  return err?.message || String(err);
}

function b64url(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (const b of arr) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/* ---------- 本地记住已注册的凭证 ID（凭证 ID 不是秘密，可以存） ---------- */

function loadCredentials() {
  if (!isWebAuthnAvailable()) return [];
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
  } catch {
    return [];
  }
}

function saveCredentials(list) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
  } catch {
    /* 忽略：存不下就每次重新注册 */
  }
}

export function getStoredCredentials() {
  return loadCredentials();
}

export function forgetStoredCredentials() {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* noop */
  }
}

function rememberCredential(credentialId, transports, attachment) {
  const list = loadCredentials();
  const id = b64url(new Uint8Array(credentialId));
  if (!list.some((c) => c.id === id)) {
    list.push({ id, transports: transports || [], attachment: attachment || '', addedAt: new Date().toISOString() });
    saveCredentials(list);
  }
  return { id, transports: transports || [], attachment: attachment || '' };
}

function unb64url(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4 ? '='.repeat(4 - (s.length % 4)) : '';
  const bin = atob(s + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/* ---------- 注册 ---------- */

/**
 * 注册一个安全密钥凭证，并立即用 prfSalt 取出密钥材料。
 * @param {Uint8Array} prfSalt 16 字节，来自文件头
 * @param {''|'platform'|'cross-platform'} attachment 认证器类型
 * @returns {{credentialId: Uint8Array, credentialIdB64: string, k3: Uint8Array}}
 */
export async function createCredential(prfSalt, attachment = '') {
  if (!isWebAuthnAvailable()) throw new Error(t('err_wa_browser'));
  if (!isSecureContextOk()) throw new Error(t('err_wa_secure'));

  const challenge = randomBytes(32);
  const userId = randomBytes(16);

  const publicKey = {
    challenge,
    rp: { name: 'ENC1 Local Vault' },
    user: { id: userId, name: 'enc1-local', displayName: 'ENC1 本地密钥' },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 }, // ES256
      { type: 'public-key', alg: -257 }, // RS256
    ],
    authenticatorSelection: {
      userVerification: 'required',
      residentKey: 'preferred',
      requireResidentKey: false,
    },
    timeout: 120_000,
    extensions: { prf: { eval: { first: prfSalt } } },
  };
  if (attachment) publicKey.authenticatorSelection.authenticatorAttachment = attachment;

  let credential;
  try {
    credential = await navigator.credentials.create({ publicKey });
  } catch (err) {
    throw new Error(t('err_wa_reg_fail', { msg: friendlyError(err) }));
  }
  if (!credential) throw new Error(t('err_wa_reg_none'));

  const ext = credential.getClientExtensionResults?.() || {};
  const prfFirst = ext.prf?.results?.first;
  if (!prfFirst) {
    // 明确告知，绝不静默退化
    throw new Error(t('err_wa_no_prf'));
  }

  const transports = credential.response?.getTransports?.() || [];
  const stored = rememberCredential(credential.rawId, transports, attachment);
  const k3 = new Uint8Array(prfFirst).slice(0, K3_BYTES);
  return { credentialId: new Uint8Array(credential.rawId), credentialIdB64: stored.id, k3 };
}

/* ---------- 取密钥 ---------- */

/**
 * 用已有凭证 + prfSalt 取出密钥材料（需要用户指纹/PIN/触摸）。
 * @param {Uint8Array|string} credentialId
 * @param {Uint8Array} prfSalt
 */
export async function getPrfKey(credentialId, prfSalt) {
  if (!isWebAuthnAvailable()) throw new Error(t('err_wa_browser'));
  if (!isSecureContextOk()) throw new Error(t('err_wa_secure'));

  const rawId = typeof credentialId === 'string' ? unb64url(credentialId) : credentialId;
  const stored = loadCredentials().find((c) => c.id === b64url(rawId));

  const publicKey = {
    challenge: randomBytes(32),
    allowCredentials: [
      {
        id: rawId,
        type: 'public-key',
        transports: stored?.transports?.length ? stored.transports : ['usb', 'nfc', 'ble', 'internal', 'hybrid'],
      },
    ],
    userVerification: 'required',
    timeout: 120_000,
    extensions: { prf: { eval: { first: prfSalt } } },
  };

  let assertion;
  try {
    assertion = await navigator.credentials.get({ publicKey });
  } catch (err) {
    throw new Error(t('err_wa_get_fail', { msg: friendlyError(err) }));
  }
  if (!assertion) throw new Error(t('err_wa_get_none'));

  const ext = assertion.getClientExtensionResults?.() || {};
  const prfFirst = ext.prf?.results?.first;
  if (!prfFirst) {
    throw new Error(t('err_wa_no_prf_out'));
  }
  return new Uint8Array(prfFirst).slice(0, K3_BYTES);
}

/** 判断浏览器是否声称支持 PRF（仅用于 UI 提示，最终以实际返回为准） */
export async function probePrfSupport() {
  if (!isWebAuthnAvailable()) return { available: false, reason: '浏览器不支持 WebAuthn' };
  if (!isSecureContextOk()) return { available: false, reason: '非安全上下文（需 localhost 或 https）' };
  try {
    if (typeof PublicKeyCredential.getClientCapabilities === 'function') {
      const caps = await PublicKeyCredential.getClientCapabilities();
      if (caps && caps.prf === false) {
        return { available: false, reason: '浏览器报告不支持 PRF 扩展' };
      }
      if (caps && caps.prf === true) return { available: true, reason: '' };
    }
  } catch {
    /* 探测失败就当作未知，按可用处理，实际注册时再确认 */
  }
  return { available: true, reason: '' };
}
