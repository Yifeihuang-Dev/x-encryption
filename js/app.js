/**
 * XEncryption 界面逻辑
 *
 * 与安全相关的两条硬规则，改动时不要破坏：
 * 1. 任何解密失败都统一提示「密钥错误，或文件已被修改/损坏」，不区分原因，
 *    避免向攻击者泄露「口令对了但文件是坏的」这类信息。
 * 2. 口令、证书密钥、主密钥只在内存里短暂存在，用不上时立刻清零，
 *    并且永远不会出现在日志、URL 或网络请求里（本应用不发任何请求）。
 */

import * as C from './crypto.js';
import * as CF from './certfile.js';
import * as WA from './webauthn.js';
import * as CT from './container.js';
import * as IO from './file-io.js';
import { t, applyI18n, getLang, setLang } from './i18n.js';

const $ = (id) => document.getElementById(id);

const state = {
  enc: { file: null, certMode: 'new', existingCertKey: null, existingCertId: null },
  dec: { file: null, header: null, certKey: null, k3: null, k3From: null },
};

/* ---------------- 通用 ---------------- */

function setStatus(el, text, kind = '') {
  el.textContent = text;
  el.className = kind ? `status ${kind}` : 'status';
}

function show(el, yes = true) {
  el.hidden = !yes;
}

function kv(label, value) {
  return `<div class="kv"><span>${label}</span><strong>${value}</strong></div>`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function makeProgress(barEl, statusEl) {
  return (phase, cur, total) => {
    const n = total || 1;
    switch (phase) {
      case 'prepare':
        barEl.style.width = '0%';
        setStatus(statusEl, t('st_header'));
        return;
      case 'kdf':
        setStatus(statusEl, t('st_deriving'));
        return;
      case 'verify':
        setStatus(statusEl, t('st_verifying'));
        return;
      case 'meta':
        setStatus(statusEl, t('st_meta'));
        return;
      default:
        break;
    }
    const pct = n > 0 ? Math.round((cur / n) * 100) : 0;
    barEl.style.width = `${pct}%`;
    const verb = phase === 'encrypt' ? t('verb_encrypt') : t('verb_decrypt');
    setStatus(statusEl, t('st_chunks', { verb, cur, total: n, pct }));
  };
}

/* ---------------- 标签页与语言 ---------------- */

$('tabs').addEventListener('click', (e) => {
  const btn = e.target.closest('.tab');
  if (!btn) return;
  document.querySelectorAll('.tab').forEach((x) => x.classList.toggle('active', x === btn));
  document.querySelectorAll('.panel').forEach((p) => p.classList.toggle('active', p.id === `panel-${btn.dataset.tab}`));
});

function refreshLangBtn() {
  // 按钮上永远显示「另一种语言」的名字
  $('lang-btn').textContent = getLang() === 'en' ? t('lang_btn') : 'EN';
}

$('lang-btn').addEventListener('click', () => {
  setLang(getLang() === 'en' ? 'zh' : 'en');
  applyI18n();
  refreshLangBtn();
  renderCreds();
  estimateStrength($('enc-password').value);
  refreshEncryptButton();
});

/* ---------------- 环境检测 ---------------- */

async function initEnv() {
  const badge = $('badge-context');
  if (window.isSecureContext) {
    badge.textContent = t('ctx_ok');
    badge.className = 'badge ok';
  } else {
    badge.textContent = t('ctx_bad');
    badge.className = 'badge err';
  }

  const prf = await WA.probePrfSupport();
  const badgePrf = $('badge-prf');
  badgePrf.hidden = false;
  if (prf.available) {
    badgePrf.textContent = t('prf_ok');
    badgePrf.className = 'badge ok';
  } else {
    badgePrf.textContent = t('prf_bad', { reason: prf.reason });
    badgePrf.className = 'badge warn';
  }
  $('enc-prf-hint').textContent = prf.available ? t('prf_hint_ok') : t('prf_hint_bad', { reason: prf.reason });

  if (!IO.isFsAccessAvailable()) {
    const note = document.createElement('p');
    note.className = 'hint';
    note.textContent = t('fs_note');
    $('panel-encrypt').querySelector('.card').appendChild(note);
  }

  $('foot-note').textContent = IO.isFsAccessAvailable() ? t('foot_fs') : t('foot_plain');
}

/* ---------------- 加密面板 ---------------- */

function refreshEncryptButton() {
  const { file, certMode, existingCertKey } = state.enc;
  const pw = $('enc-password').value;
  const pw2 = $('enc-password2').value;
  const ok = !!file && pw.length > 0 && pw === pw2 && (certMode !== 'existing' || !!existingCertKey);
  $('enc-submit').disabled = !ok;
}

function estimateStrength(pw) {
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 14) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const level = score >= 5 ? 'strong' : score >= 3 ? 'medium' : 'weak';
  const label = t(`str_${level}`);
  const bars = [1, 2, 3, 4, 5].map((i) => `<i class="${i <= score ? 'on' : ''}"></i>`).join('');
  const extra = score < 3 ? t('str_weak_extra') : t('str_ok_extra');
  const el = $('enc-strength');
  el.className = `strength ${level}`;
  el.innerHTML = `${t('str_label', { level: label })}${extra}<div class="meter">${bars}</div>`;
}

$('enc-password').addEventListener('input', () => {
  estimateStrength($('enc-password').value);
  refreshEncryptButton();
});
$('enc-password2').addEventListener('input', refreshEncryptButton);
$('enc-toggle-pw').addEventListener('click', () => {
  const i = $('enc-password');
  const on = i.type === 'password';
  i.type = on ? 'text' : 'password';
  $('enc-password2').type = i.type;
  $('enc-toggle-pw').textContent = on ? t('enc_pw_hide') : t('enc_pw_show');
});

$('enc-certmode').addEventListener('change', (e) => {
  state.enc.certMode = e.target.value;
  show($('enc-existing-cert'), e.target.value === 'existing');
  refreshEncryptButton();
});

$('enc-use-webauthn').addEventListener('change', (e) => {
  show($('enc-webauthn-options'), e.target.checked);
});

IO.wireDropzone($('enc-drop'), $('enc-file'), (file) => {
  state.enc.file = file;
  $('enc-file-info').hidden = false;
  $('enc-file-info').innerHTML =
    kv(t('kv_name'), escapeHtml(file.name)) +
    kv(t('kv_size'), IO.formatSize(file.size)) +
    kv(t('kv_type'), escapeHtml(file.type || t('unknown')));
  refreshEncryptButton();
});

IO.wireDropzone($('enc-cert-drop'), $('enc-cert-file'), async (file) => {
  try {
    const parsed = await CF.parseCertificate(await file.text());
    state.enc.existingCertKey = parsed.certKey;
    state.enc.existingCertId = parsed.id;
    $('enc-cert-info').hidden = false;
    $('enc-cert-info').innerHTML =
      kv(t('kv_cert_id'), C.hex(parsed.id)) +
      kv(t('kv_integrity'), parsed.checksumOk === false ? t('kv_integrity_bad') : t('kv_integrity_ok')) +
      kv(t('kv_note'), escapeHtml(parsed.label || '—'));
    refreshEncryptButton();
  } catch (err) {
    state.enc.existingCertKey = null;
    $('enc-cert-info').hidden = false;
    $('enc-cert-info').textContent = `${t('st_failed', { msg: err.message })}`;
    refreshEncryptButton();
  }
});

$('enc-submit').addEventListener('click', runEncrypt);

async function runEncrypt() {
  const file = state.enc.file;
  if (!file) return;
  const password = $('enc-password').value;
  if (!password) return;
  if (password !== $('enc-password2').value) {
    setStatus($('enc-status'), t('pw_mismatch'), 'err');
    return;
  }

  const barEl = $('enc-bar');
  const statusEl = $('enc-status');
  show($('enc-progress'), true);
  show($('enc-result'), false);
  setStatus(statusEl, t('st_preparing'));
  $('enc-submit').disabled = true;

  let sink = null;
  let usedFsAccess = false;
  let certKey = null;
  let k3 = null;

  const abort = (msg) => {
    setStatus(statusEl, msg, 'err');
    show($('enc-progress'), false);
    $('enc-submit').disabled = false;
  };

  try {
    // 1) 因子二：证书 —— 必须先保存好再加密。
    //    否则会出现「密文在、证书没了」这种永远打不开的死局。
    let certText = null;
    let certIdHex = null;
    let certHow = null; // 'picker' | 'download' | 'existing'
    if (state.enc.certMode === 'new') {
      certKey = await CF.generateCertKey();
      certText = await CF.serializeCertificate(certKey, { label: `${file.name}` });
      certIdHex = C.hex(await CF.certId(certKey));

      setStatus(statusEl, t('st_step1'));
      const certName = `${file.name}.enc1cert`;
      if (IO.isFsAccessAvailable()) {
        try {
          await IO.saveTextWithPicker(certText, certName, { description: 'XEncryption certificate', accept: ['.enc1cert'] });
          certHow = 'picker';
        } catch (err) {
          if (err?.name === 'AbortError') {
            abort(t('st_cancel_nocert'));
            return;
          }
          certHow = null;
        }
      }
      if (!certHow) {
        IO.downloadText(certText, certName);
        certHow = 'download';
      }
    } else if (state.enc.certMode === 'existing') {
      certKey = state.enc.existingCertKey;
      certIdHex = C.hex(state.enc.existingCertId);
      certHow = 'existing';
    }

    // 2) 再确定密文的保存位置
    const outName = `${file.name}.enc1`;
    setStatus(statusEl, t('st_step2'));
    if (IO.isFsAccessAvailable()) {
      try {
        sink = await IO.createFileSink(outName, { description: 'XEncryption encrypted file', accept: ['.enc1'] });
        usedFsAccess = true;
      } catch (err) {
        if (err?.name === 'AbortError') {
          abort(t('st_cancel_certsaved', { name: `${file.name}.enc1cert` }));
          return;
        }
        sink = null;
      }
    }
    if (!sink) sink = IO.createMemorySink();

    // 3) 因子三：硬件密钥（需要用户交互，放在写盘之前但位置已确定之后）
    let credentialId = null;
    let recoveryText = null;
    let prfSalt = null;
    if ($('enc-use-webauthn').checked) {
      setStatus(statusEl, t('st_wa'));
      prfSalt = C.randomBytes(16);
      const res = await WA.createCredential(prfSalt, $('enc-attachment').value);
      credentialId = res.credentialId;
      k3 = res.k3;
      recoveryText = C.formatRecoveryCode(k3);
    }

    // 4) 加密
    const onProgress = makeProgress(barEl, statusEl);
    const result = await CT.encryptToSink({
      source: CT.fileSource(file),
      meta: {
        name: file.name,
        type: file.type || '',
        size: file.size,
        createdAt: new Date().toISOString(),
      },
      password,
      certKey,
      k3,
      credentialId,
      prfSalt,
      sink,
      onProgress,
    });

    if (!usedFsAccess) {
      IO.downloadBlob(sink.toBlob(), outName);
    } else {
      await sink.close();
    }
    sink = null;

    barEl.style.width = '100%';
    setStatus(statusEl, t('st_done_enc', { size: IO.formatSize(file.size) }), 'ok');

    // 5) 结果展示
    const certWhere =
      certHow === 'picker'
        ? t('cert_picker', { name: escapeHtml(`${file.name}.enc1cert`) })
        : certHow === 'download'
          ? t('cert_download', { name: escapeHtml(`${file.name}.enc1cert`) })
          : certHow === 'existing'
            ? t('cert_existing')
            : t('cert_none');

    let html =
      kv(t('kv_output'), escapeHtml(outName)) +
      kv(t('kv_cipher_size'), IO.formatSize(result.written)) +
      kv(t('kv_chunks'), result.header.totalChunks) +
      kv(t('kv_kdf'), `PBKDF2-SHA256 · ${result.header.iterations.toLocaleString()}`) +
      kv(t('kv_cert'), certWhere);

    if (certIdHex) {
      html += kv(t('kv_cert_id'), certIdHex) + `<p class="warn-inline">${t('cert_backup')}</p>`;
    }

    if (recoveryText) {
      html +=
        `<div class="recovery"><div class="rc-title">${t('rc_title')}</div>` +
        `<div class="code">${recoveryText}</div>` +
        `<p>${t('rc_body')}</p></div>`;
    }

    $('enc-result-body').innerHTML = html;
    show($('enc-result'), true);
  } catch (err) {
    setStatus(statusEl, t('st_failed', { msg: err.message }), 'err');
    if (sink && sink.close) {
      try {
        await sink.close();
      } catch {
        /* 忽略：写入失败时的清理 */
      }
    }
  } finally {
    // 只清零本次新生成的证书密钥：复用模式下清掉会破坏用户手上的证书文件
    if (certKey && state.enc.certMode === 'new') certKey.fill(0);
    if (k3) k3.fill(0);
    $('enc-submit').disabled = false;
  }
}

/* ---------------- 解密面板 ---------------- */

function refreshDecryptButton() {
  const { file, header, certKey, k3 } = state.dec;
  const pw = $('dec-password').value;
  const ok = !!file && !!header && pw.length > 0 && (!header.needCert || !!certKey) && (!header.needWebauthn || !!k3);
  $('dec-submit').disabled = !ok;
}

IO.wireDropzone($('dec-drop'), $('dec-file'), async (file) => {
  const info = $('dec-requirements');
  try {
    const header = await CT.readHeader(CT.fileSource(file));
    state.dec.file = file;
    state.dec.header = header;
    state.dec.certKey = null;
    state.dec.k3 = null;

    const factors = [t('fac_password')];
    if (header.needCert) factors.push(t('fac_cert', { id: C.hex(header.certIdBytes) }));
    if (header.needWebauthn) factors.push(t('fac_k3'));
    if (!header.needCert && !header.needWebauthn) factors.push(`<span class="flag">${t('fac_pw_only')}</span>`);

    info.hidden = false;
    info.className = 'file-info';
    info.innerHTML =
      kv(t('kv_need'), factors.join(' + ')) +
      kv(t('kv_chunks'), header.totalChunks) +
      kv(t('kv_kdf'), `${header.iterations.toLocaleString()}`) +
      kv(t('kv_cipher_size'), IO.formatSize(file.size));

    show($('dec-factors-card'), true);
    show($('dec-cert-field'), header.needCert);
    show($('dec-webauthn-field'), header.needWebauthn);
    $('dec-webauthn-state').textContent = t('wa_state_idle');
    $('dec-webauthn-state').className = 'state';
    refreshDecryptButton();
  } catch (err) {
    state.dec.file = null;
    state.dec.header = null;
    info.hidden = false;
    info.className = 'file-info';
    info.textContent = t('dec_unrecognized', { msg: err.message });
    show($('dec-factors-card'), false);
    refreshDecryptButton();
  }
});

$('dec-password').addEventListener('input', refreshDecryptButton);
$('dec-toggle-pw').addEventListener('click', () => {
  const i = $('dec-password');
  i.type = i.type === 'password' ? 'text' : 'password';
  $('dec-toggle-pw').textContent = i.type === 'password' ? t('enc_pw_show') : t('enc_pw_hide');
});

IO.wireDropzone($('dec-cert-drop'), $('dec-cert-file'), async (file) => {
  const box = $('dec-cert-info');
  try {
    const parsed = await CF.parseCertificate(await file.text());
    if (state.dec.header?.needCert) {
      const matches = C.timingSafeEqual(parsed.id, state.dec.header.certIdBytes);
      if (!matches) {
        state.dec.certKey = null;
        box.hidden = false;
        box.innerHTML = `<strong class="flag">${t('dec_cert_mismatch')}</strong>`;
        refreshDecryptButton();
        return;
      }
    }
    state.dec.certKey = parsed.certKey;
    box.hidden = false;
    box.innerHTML = kv(t('kv_cert_id'), C.hex(parsed.id)) + kv(t('kv_status'), t('dec_cert_match'));
    refreshDecryptButton();
  } catch (err) {
    state.dec.certKey = null;
    box.hidden = false;
    box.textContent = t('st_failed', { msg: err.message });
    refreshDecryptButton();
  }
});

$('dec-webauthn-btn').addEventListener('click', async () => {
  const { header } = state.dec;
  if (!header?.credentialId) return;
  const st = $('dec-webauthn-state');
  st.textContent = t('st_wa');
  st.className = 'state';
  try {
    const k3 = await WA.getPrfKey(header.credentialId, header.prfSalt);
    state.dec.k3 = k3;
    state.dec.k3From = 'webauthn';
    st.textContent = t('wa_state_ok');
    st.className = 'state ok';
  } catch (err) {
    st.textContent = err.message;
    st.className = 'state err';
  }
  refreshDecryptButton();
});

$('dec-recovery').addEventListener('input', (e) => {
  const hint = $('dec-recovery-hint');
  const raw = e.target.value.trim();
  if (!raw) {
    state.dec.k3 = null;
    state.dec.k3From = null;
    hint.className = 'hint';
    hint.textContent = '';
    refreshDecryptButton();
    return;
  }
  try {
    state.dec.k3 = CF.decodeRecoveryCode(raw);
    state.dec.k3From = 'recovery';
    hint.className = 'hint ok';
    hint.textContent = t('rc_ok');
  } catch (err) {
    state.dec.k3 = null;
    state.dec.k3From = null;
    hint.className = 'hint err';
    hint.textContent = err.message;
  }
  refreshDecryptButton();
});

$('dec-submit').addEventListener('click', runDecrypt);

async function runDecrypt() {
  const { file, header } = state.dec;
  if (!file || !header) return;
  const password = $('dec-password').value;
  const barEl = $('dec-bar');
  const statusEl = $('dec-status');
  show($('dec-progress'), true);
  setStatus(statusEl, t('st_preparing'));
  $('dec-submit').disabled = true;

  const baseName = file.name.replace(/\.enc1$/i, '') || 'decrypted';
  let sink = null;
  let usedFsAccess = false;

  try {
    // 解密前看不到真实文件名（它被加密了），先用 .enc1 的名字占位
    if (IO.isFsAccessAvailable()) {
      try {
        sink = await IO.createFileSink(baseName, { description: 'Decrypted file' });
        usedFsAccess = true;
      } catch (err) {
        if (err?.name === 'AbortError') {
          setStatus(statusEl, t('st_cancelled'));
          show($('dec-progress'), false);
          $('dec-submit').disabled = false;
          return;
        }
        sink = null;
      }
    }
    if (!sink) sink = IO.createMemorySink();

    const onProgress = makeProgress(barEl, statusEl);
    const { meta } = await CT.decryptToSink({
      source: CT.fileSource(file),
      password,
      certKey: state.dec.certKey,
      k3: state.dec.k3,
      sink,
      onProgress,
    });

    const displayName = meta.name || baseName;
    if (usedFsAccess) {
      await sink.close();
      setStatus(statusEl, t('st_done_dec', { name: displayName, size: IO.formatSize(meta.size ?? 0) }), 'ok');
    } else {
      const blob = sink.toBlob(meta.type || 'application/octet-stream');
      IO.downloadBlob(blob, displayName);
      setStatus(statusEl, t('st_done_dec_dl', { name: displayName, size: IO.formatSize(meta.size ?? 0) }), 'ok');
    }
    sink = null;
    barEl.style.width = '100%';
  } catch (err) {
    // 解密失败一律使用不区分原因的措辞，避免泄露「口令已正确」这类信息
    setStatus(statusEl, /^(Wrong key|This file|Certificate|File size|Unreasonable|Metadata|Not a valid|File is|File too)/.test(err.message) ? err.message : t('err_key_or_corrupt'), 'err');
    if (sink && sink.close) {
      try {
        await sink.close();
      } catch {
        /* 忽略 */
      }
    }
  } finally {
    $('dec-submit').disabled = false;
  }
}

/* ---------------- 工具面板 ---------------- */

$('tool-gen-cert').addEventListener('click', async () => {
  const key = await CF.generateCertKey();
  const id = await CF.certId(key);
  const text = await CF.serializeCertificate(key, { label: $('tool-cert-label').value || 'XEncryption' });
  IO.downloadText(text, `certificate-${C.hex(id).slice(0, 16)}.enc1cert`);
  const box = $('tool-cert-info');
  box.hidden = false;
  box.innerHTML = kv(t('kv_cert_id'), C.hex(id)) + kv(t('kv_downloaded'), `certificate-${C.hex(id).slice(0, 16)}.enc1cert`);
  key.fill(0);
});

IO.wireDropzone($('tool-cert-drop'), $('tool-cert-file'), async (file) => {
  const box = $('tool-cert-check');
  try {
    const p = await CF.parseCertificate(await file.text());
    box.hidden = false;
    box.innerHTML =
      kv(t('kv_cert_id'), C.hex(p.id)) +
      kv(t('kv_created'), escapeHtml(p.created || '—')) +
      kv(t('kv_note'), escapeHtml(p.label || '—')) +
      kv(t('kv_integrity'), p.checksumOk === false ? t('kv_integrity_bad') : t('kv_integrity_ok'));
  } catch (err) {
    box.hidden = false;
    box.textContent = t('st_failed', { msg: err.message });
  }
});

function renderCreds() {
  const list = WA.getStoredCredentials();
  const box = $('tool-cred-list');
  if (!list.length) {
    box.innerHTML = `<div>${t('cred_empty')}</div>`;
    return;
  }
  box.innerHTML = list
    .map((c, i) => `<div>#${i + 1}　${escapeHtml(c.id.slice(0, 28))}…　${escapeHtml(c.attachment || '')}</div>`)
    .join('');
}

$('tool-forget-creds').addEventListener('click', () => {
  WA.forgetStoredCredentials();
  renderCreds();
});

/* ---------------- 启动 ---------------- */

applyI18n();
refreshLangBtn();
renderCreds();
refreshEncryptButton();
refreshDecryptButton();
initEnv();
