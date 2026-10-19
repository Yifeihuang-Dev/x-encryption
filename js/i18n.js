/**
 * 双语字典与切换（默认英文）
 *
 * 用法：
 *   静态 HTML：元素加 data-i18n="key"（textContent）/ data-i18n-html="key"（innerHTML）
 *              / data-i18n-ph="key"（placeholder）
 *   动态文案：import { t } from './i18n.js';  t('key', { var: value })
 *
 * 语言选择存 localStorage；读取失败（如 Node 测试环境）静默回落英文。
 */

const STORE_KEY = 'xe.lang';

let lang = 'en';
try {
  lang = localStorage.getItem(STORE_KEY) === 'zh' ? 'zh' : 'en';
} catch {
  lang = 'en';
}

export function getLang() {
  return lang;
}

export function setLang(l) {
  lang = l === 'zh' ? 'zh' : 'en';
  try {
    localStorage.setItem(STORE_KEY, lang);
  } catch {
    /* 无 localStorage 时仅本次生效 */
  }
}

const dicts = {
  en: {
    doc_title: 'XEncryption · Local Encryption Vault',
    tagline: 'Three-factor local encryption · Runs in your browser · Zero network',
    ctx_ok: 'Secure context · Fully local',
    ctx_bad: 'Insecure context (open via localhost/https)',
    prf_ok: 'WebAuthn PRF available',
    prf_bad: 'Hardware key unavailable: {reason}',
    lang_btn: '中文',

    tab_encrypt: 'Encrypt',
    tab_decrypt: 'Decrypt',
    tab_tools: 'Certificates & Tools',
    tab_about: 'About',
    tab_encrypt_done: 'Encryption complete',
    dec_recovery_ph: 'XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX',

    enc_step1: 'Choose a file',
    enc_drop_main: 'Drag a file here, or <span class="link">click to choose</span>',
    enc_drop_hint: 'Any type works — PDF, video, archive, disk image… Chunked streaming keeps memory flat',
    enc_step2: 'Factor 1 · Password',
    enc_pw: 'Password',
    enc_pw_ph: 'Enter password',
    enc_pw_show: 'Show',
    enc_pw_hide: 'Hide',
    enc_pw2: 'Repeat',
    enc_pw2_ph: 'Confirm password',
    enc_step3: 'Factor 2 · Certificate file',
    enc_cert_new: 'Generate a new certificate (recommended)',
    enc_cert_existing: 'Use an existing certificate',
    enc_cert_none: 'None (password only — weaker)',
    enc_cert_drop: 'Drag a certificate here, or <span class="link">choose</span> a .enc1cert file',
    enc_cert_warn:
      'Losing the certificate file = the data can never be recovered. There is no back door. Keep at least two backups (USB stick, paper, password manager) and never store it next to the ciphertext.',
    enc_step4: 'Factor 3 · Hardware key (optional)',
    enc_wa_enable: 'Enable hardware key (Touch ID / Windows Hello / YubiKey)',
    enc_wa_type: 'Authenticator type',
    enc_wa_auto: 'Automatic (built-in or external)',
    enc_wa_platform: "This device's biometrics / platform authenticator",
    enc_wa_roaming: 'External security key (YubiKey etc.)',
    enc_wa_note:
      'A recovery code is generated together with the hardware key. It is equivalent to the key — for lost devices, re-enrolled fingerprints, or a new computer. Print it or write it down.',
    enc_src_title: 'About the original file',
    enc_src_p: 'The browser has no permission to delete your original file — you must delete it yourself. Two honest caveats:',
    enc_src_b1: 'On an SSD, "delete" does not mean "erase" — wear leveling can leave old data in places you cannot see.',
    enc_src_b2: 'For true unrecoverability rely on full-disk encryption (FileVault / BitLocker), not on deleting afterwards.',
    enc_submit: 'Encrypt',

    dec_step1: 'Choose an .enc1 file',
    dec_drop: 'Drag a .enc1 file here, or <span class="link">click to choose</span>',
    dec_step2: 'Provide the key factors',
    dec_pw: 'Password (factor 1)',
    dec_cert: 'Certificate file (factor 2)',
    dec_k3: 'Hardware key / recovery code (factor 3)',
    dec_wa_btn: 'Verify with hardware key',
    dec_wa_hint: 'No hardware key available (or the device is gone)? Use the recovery code instead:',
    dec_submit: 'Decrypt & open',

    tls_gen_title: 'Generate a standalone certificate',
    tls_gen_hint: 'Generate a certificate first, then reuse it for many files (choose "use an existing certificate" when encrypting).',
    tls_gen_label: 'Note (optional, written into the certificate)',
    tls_gen_ph: 'e.g. Main certificate · USB backup',
    tls_gen_btn: 'Generate & download',
    tls_chk_title: 'Inspect a certificate',
    tls_chk_hint1: 'Confirm a certificate file is intact and see its ID (to match the fingerprint recorded in the encrypted file header).',
    tls_chk_hint2:
      'Lost a certificate? It is named <code>originalfile.enc1cert</code>. Encryption asks where to save it first; if the browser downloaded it instead, look in the Downloads folder or on the Desktop. Drop it here to confirm which one it is.',
    tls_cred_title: 'Hardware key management',
    tls_cred_hint:
      'Security-key credential IDs recorded on this device (a credential ID is not a secret; it only identifies the key locally):',
    tls_cred_empty: 'No security-key credentials recorded on this device yet.',
    tls_cred_forget: 'Forget credentials on this device',

    ab_what: 'What it does',
    ab_w1: '<strong>AES-256-GCM</strong>, chunked streaming (1 MiB per chunk), every chunk with its own nonce and authentication tag.',
    ab_w2: '<strong>Password</strong> is derived with PBKDF2-HMAC-SHA256 (600k rounds, random salt) — never used as a key directly.',
    ab_w3:
      '<strong>Three factors merged</strong>: password ‖ certificate ‖ hardware key → HKDF-SHA256 → master key. Missing any one means no decryption, and an attacker cannot break them one by one.',
    ab_w4: '<strong>The whole file header is authenticated as AAD</strong>: any change to salt, KDF rounds or factor flags fails instantly — no downgrade attacks.',
    ab_w5: '<strong>Chunk index & total count go into the AAD</strong>: blocks cannot be reordered, truncated or rolled back.',
    ab_w6: '<strong>Verify first, decrypt later</strong>: only a 48-byte verification block is decrypted first — a wrong key is rejected immediately.',
    ab_w7: '<strong>Name, type and size are stored encrypted</strong>: without the key, not even the file name is visible.',
    ab_not: 'What it does NOT do',
    ab_n1: 'No network, no upload, no telemetry. Works offline; all CSS/JS are local files.',
    ab_n2: 'No MD5 / DES / ECB / home-made algorithms — nothing "invented by ourselves".',
    ab_n3: 'No back door: password forgotten + certificate lost = permanently locked out.',
    ab_n4: 'No promise that deleting the original is unrecoverable on an SSD.',
    ab_n5: 'No X.509 certificate chains, no self-extracting executables.',
    ab_f3: 'Two honest facts about the third factor',
    ab_f3a:
      '<strong>A fingerprint never becomes a key.</strong> Biometrics only unlock a key that already lives in secure hardware; fingerprint data never leaves the device and the browser never sees it.',
    ab_f3b:
      '<strong>No silent fallback.</strong> The mainstream FIDO2 algorithm ES256 produces randomized signatures, which cannot derive a stable key. So when a device lacks WebAuthn PRF this tool <strong>refuses</strong> to enable the hardware factor instead of quietly degrading. Use "password + certificate", or a PRF-capable key.',
    ab_fmt: 'File format',
    ab_fmt_hint: 'Output file extension <code>.enc1</code>, certificate file extension <code>.enc1cert</code>.',
    ab_format_code: '[header 88+N] [verify 48] [metaLen 2] [meta N] [chunk0 .. chunkN-1]\n\nheader: magic "ENC1" | version | flags | kdfId | iterations | salt(16)\n        certId(16) | credentialIdHash(16) | prfSalt(16) | nonceBase(7)\n        chunkSizeLog2 | totalChunks | credentialIdLen | credentialId',

    st_preparing: 'Preparing…',
    st_header: 'Building the file header…',
    st_deriving: 'Deriving the master key (deliberately slow — this is what makes brute force expensive)…',
    st_verifying: 'Verifying the key…',
    st_meta: 'Reading file info…',
    st_step1: 'Step 1/2: choose where to save the certificate file (it matters more than the ciphertext)…',
    st_step2: 'Step 2/2: choose where to save the encrypted file…',
    st_cancel_nocert: 'Cancelled: the certificate was not saved, so no ciphertext was produced (this avoids an unopenable file).',
    st_cancel_certsaved: 'Cancelled. The certificate is saved where you chose ({name}); you can use it to encrypt later.',
    st_wa: 'Confirm on your device (fingerprint / PIN / touch)…',
    st_done_enc: 'Done: {size} encrypted',
    st_done_dec: 'Done: {name} ({size}) written',
    st_done_dec_dl: 'Done: {name} ({size}) — download started',
    st_chunks: '{verb} {cur}/{total} chunks ({pct}%)',
    verb_encrypt: 'Encrypting',
    verb_decrypt: 'Decrypting',
    pw_mismatch: 'The two passwords do not match',
    st_failed: 'Failed: {msg}',
    st_cancelled: 'Cancelled',

    kv_output: 'Ciphertext',
    kv_cipher_size: 'Ciphertext size',
    kv_name: 'File name',
    kv_size: 'Size',
    kv_type: 'Type',
    kv_chunks: 'Chunks',
    kv_kdf: 'Password derivation',
    kv_cert: 'Certificate',
    kv_cert_id: 'Certificate ID',
    kv_integrity: 'Integrity',
    kv_integrity_bad: 'Checksum FAILED — file may be damaged or rewritten',
    kv_integrity_ok: 'OK ✓',
    kv_note: 'Note',
    kv_created: 'Created',
    kv_need: 'Requires',
    kv_status: 'Status',
    kv_downloaded: 'Downloaded',
    unknown: 'unknown',
    cert_picker: 'Saved to the location you chose ({name})',
    cert_download: '{name} — saved via browser download; check the Downloads folder (or Desktop)',
    cert_existing: 'Using an existing certificate',
    cert_none: 'Not used (password only)',
    cert_backup:
      'Copy the certificate somewhere else right now (USB stick / password manager / print it). Never keep it only next to the ciphertext — lost together means gone forever.',
    rc_title: 'Recovery code (equivalent to the hardware key)',
    rc_body:
      'A complete backup of the third factor: use it when the device is lost, fingerprints are re-enrolled, or you switch computers. Print or hand-copy it and store offline — like the certificate, once gone it is gone.',
    rc_ok: 'Recovery code format OK ✓',
    str_label: 'Strength: {level}',
    str_weak: 'Weak',
    str_medium: 'Medium',
    str_strong: 'Strong',
    str_weak_extra: '  The password is the one thing that cannot be recovered — make it longer and more random.',
    str_ok_extra: '  Even a mediocre password becomes far stronger with a certificate file.',
    fac_password: 'Password',
    fac_cert: 'Certificate file (ID {id})',
    fac_k3: 'Hardware key or recovery code',
    fac_pw_only: 'Password only',
    dec_unrecognized: 'Cannot recognize: {msg}',
    dec_cert_mismatch: 'Certificate mismatch: not the certificate this file was encrypted with',
    dec_cert_match: 'Match ✓',
    wa_state_idle: 'Not verified',
    wa_state_ok: 'Verified with hardware key ✓',

    fs_note: 'This browser cannot stream to disk; large files are assembled in memory before download — watch your memory.',
    foot_fs: 'Everything is computed on this machine · streaming to disk supported',
    foot_plain: 'Everything is computed on this machine',
    prf_hint_ok: 'During registration the device asks for fingerprint / PIN / touch. If it does not support PRF, registration fails outright — no silent downgrade.',
    prf_hint_bad: 'Not supported here: {reason}. You can still use the two-factor "password + certificate" mode.',
    cred_empty: 'No security-key credentials recorded on this device yet.',

    err_not_enc1: 'This is not an ENC1 encrypted file (bad magic)',
    err_bad_version: 'Unsupported format version v{v}',
    err_bad_kdf: 'Unsupported KDF id {id}',
    err_bad_rounds: 'Unreasonable KDF round count in the header — the file may be corrupted',
    err_bad_chunk: 'Unreasonable chunk size in the header — the file may be corrupted',
    err_too_short: 'File too short to be a valid ENC1 container',
    err_header_trunc: 'File header is truncated',
    err_incomplete: 'File is incomplete, or not a valid ENC1 container',
    err_cred_long: 'credentialId too long',
    err_need_cert: 'This file requires its certificate file (factor 2)',
    err_need_k3: 'This file requires the hardware key or recovery code (factor 3)',
    err_cert_mismatch: 'Certificate mismatch: this is not the certificate this file was encrypted with',
    err_missing_credid: 'The file is missing its hardware-key credential id',
    err_size_mismatch: 'File size does not match the header (the file may be truncated or corrupted)',
    err_key_or_corrupt: 'Wrong key, or the file has been modified/corrupted',
    err_meta_broken: 'Metadata cannot be parsed — the file may be corrupted',
    err_meta_long: 'Metadata too long',
    err_k3_no_cred: 'Enabling the hardware-key factor requires a credentialId',
    err_b32: 'The recovery code contains invalid characters',
    err_rc_len: 'Recovery code has the wrong length (should be {bytes} bytes / 32 characters)',
    err_cert_fmt: 'Not a valid ENC1 certificate file',
    err_cert_nodata: 'Certificate file is missing its key data',
    err_cert_key: 'Certificate key data cannot be decoded',
    err_cert_len: 'Wrong certificate key length (should be {bytes} bytes)',

    err_wa_browser: 'WebAuthn is not supported in this browser',
    err_wa_secure: 'WebAuthn needs a secure context — open via http://localhost',
    err_wa_reg_fail: 'Registration failed: {msg}',
    err_wa_reg_none: 'Registration failed: no credential returned',
    err_wa_no_prf:
      'This device/browser does not support WebAuthn PRF, so a key cannot be derived from it. (No unsafe fallback: the hardware factor is either fully supported or not enabled.)',
    err_wa_get_fail: 'Hardware-key verification failed: {msg}',
    err_wa_get_none: 'Hardware-key verification failed: no assertion returned',
    err_wa_no_prf_out: 'The device returned no PRF output — the key cannot be derived. Use the recovery code instead.',
    wa_notallowed: 'Cancelled or timed out (did you complete verification on the device?)',
    wa_invalidstate: 'This security key has already been registered',
    wa_notsupported: 'The device or browser does not support this operation',
    wa_security: 'This page is not a secure context; WebAuthn is unavailable (open via localhost)',
  },

  zh: {
    doc_title: 'XEncryption · 本地加密保险箱',
    tagline: '三因子本地加密 · 纯浏览器运行 · 不联网',
    ctx_ok: '安全上下文 · 纯本地',
    ctx_bad: '非安全上下文（需 localhost/https）',
    prf_ok: 'WebAuthn PRF 可用',
    prf_bad: '硬件密钥不可用：{reason}',
    lang_btn: 'EN',

    tab_encrypt: '加密',
    tab_decrypt: '解密',
    tab_tools: '证书与工具',
    tab_about: '关于',
    tab_encrypt_done: '加密完成',
    dec_recovery_ph: 'XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX',

    enc_step1: '选择文件',
    enc_drop_main: '把文件拖到这里，或 <span class="link">点击选择</span>',
    enc_drop_hint: '任意类型均可（PDF / 视频 / 压缩包 / 磁盘镜像…），分块流式处理，内存占用恒定',
    enc_step2: '因子一：口令',
    enc_pw: '口令',
    enc_pw_ph: '输入口令',
    enc_pw_show: '显示',
    enc_pw_hide: '隐藏',
    enc_pw2: '再次输入',
    enc_pw2_ph: '确认口令',
    enc_step3: '因子二：证书文件',
    enc_cert_new: '生成新证书（推荐）',
    enc_cert_existing: '使用已有证书',
    enc_cert_none: '不使用（仅口令，安全性下降）',
    enc_cert_drop: '拖入或 <span class="link">选择</span> .enc1cert 证书文件',
    enc_cert_warn:
      '证书文件丢失 = 数据永久无法恢复，没有任何后门。请备份到两处以上（U 盘、纸质、密码管理器），且不要与密文放在一起。',
    enc_step4: '因子三：硬件密钥（可选）',
    enc_wa_enable: '启用硬件密钥（Touch ID / Windows Hello / YubiKey）',
    enc_wa_type: '认证器类型',
    enc_wa_auto: '自动（本机或外接皆可）',
    enc_wa_platform: '本机生物识别 / 平台认证器',
    enc_wa_roaming: '外接安全密钥（YubiKey 等）',
    enc_wa_note:
      '启用后会同时生成一份恢复码，它与硬件密钥等价，用于设备丢失、指纹重录等情形。请打印或抄写保存。',
    enc_src_title: '关于原文件',
    enc_src_p: '浏览器没有权限删除你选中的原文件，需要你自己删除。这里说明两点实情：',
    enc_src_b1: '在 SSD 上「删除」不等于「彻底擦除」——磨损均衡会让旧数据残留在你看不见的地方。',
    enc_src_b2: '要真正做到不可恢复，请依赖 FileVault（macOS）/ BitLocker（Windows）全盘加密，而不是事后再删。',
    enc_submit: '开始加密',

    dec_step1: '选择 ENC1 文件',
    dec_drop: '把 .enc1 文件拖到这里，或 <span class="link">点击选择</span>',
    dec_step2: '提供密钥因子',
    dec_pw: '口令（因子一）',
    dec_cert: '证书文件（因子二）',
    dec_k3: '硬件密钥 / 恢复码（因子三）',
    dec_wa_btn: '用硬件密钥验证',
    dec_wa_hint: '没有硬件密钥或设备不可用时，改用恢复码：',
    dec_submit: '解密并打开文件',

    tls_gen_title: '生成独立的证书文件',
    tls_gen_hint: '可以先生成一份证书，之后在加密时反复选用它（「使用已有证书」）。',
    tls_gen_label: '备注（可选，会写进证书文件）',
    tls_gen_ph: '例如：主力证书 · U 盘备份',
    tls_gen_btn: '生成并下载证书',
    tls_chk_title: '检查证书文件',
    tls_chk_hint1: '确认一份证书文件完好、并查看它的 ID（用于和密文头部记录的指纹核对）。',
    tls_chk_hint2:
      '找不到证书？它叫 <code>原文件名.enc1cert</code>，加密时会先弹框让你选保存位置；若当时是浏览器直接下载的，去下载目录（「下载」或桌面）找。拖进来就能确认它是不是有效、是哪一份。',
    tls_cred_title: '硬件密钥管理',
    tls_cred_hint: '本机已注册的安全密钥凭证 ID（凭证 ID 不是秘密，仅用于在本机识别）：',
    tls_cred_empty: '本机还没有记录任何安全密钥凭证。',
    tls_cred_forget: '清除本机记录的凭证',

    ab_what: '它做了什么',
    ab_w1: '<strong>AES-256-GCM</strong>，分块（1 MiB/块）流式处理，每块独立 nonce 与认证标签。',
    ab_w2: '<strong>口令</strong>经 PBKDF2-HMAC-SHA256（60 万轮，随机盐）派生，绝不直接当密钥。',
    ab_w3: '<strong>三因子合并派生</strong>：口令 ‖ 证书文件 ‖ 硬件密钥 → HKDF-SHA256 得到主密钥。缺任何一个都解不开，且攻击者无法分头击破。',
    ab_w4: '<strong>文件头整体参与 AAD 认证</strong>：盐、KDF 轮数、因子开关一旦被改，立即认证失败，杜绝降级攻击。',
    ab_w5: '<strong>块序号与总块数进 AAD</strong>：防块重排、防截断回滚。',
    ab_w6: '<strong>先验证再解密全文</strong>：先只解 48 字节的验证块，密钥不对立刻拒绝，不浪费时间在整文件上。',
    ab_w7: '<strong>文件名、类型、大小加密后存放</strong>：没有密钥的人连文件名都看不到。',
    ab_not: '它不做什么',
    ab_n1: '不联网、不上传、不埋点。断网可正常运行，所有 CSS/JS 均为本地文件。',
    ab_n2: '不使用 MD5 / DES / ECB / 自研算法，不实现任何「自己发明的加密」。',
    ab_n3: '不提供后门：口令忘 + 证书丢 = 永久打不开。',
    ab_n4: '不承诺「删除原文件」在 SSD 上不可恢复。',
    ab_n5: '不使用 X.509 证书链，也不生成自解密可执行程序。',
    ab_f3: '关于第三因子的两个实话',
    ab_f3a: '<strong>指纹不会变成密钥。</strong>生物识别只负责「解锁硬件里已有的密钥」，指纹数据不出设备，浏览器也拿不到。',
    ab_f3b: '<strong>没有降级方案。</strong>FIDO2 主流算法 ES256 的签名含随机数、每次不同，无法稳定派生密钥，所以设备不支持 WebAuthn PRF 时<strong>直接拒绝启用</strong>硬件因子，而不是悄悄退化成不可靠方案。此时请用「口令 + 证书」两因子，或换一个支持 PRF 的密钥。',
    ab_fmt: '文件格式',
    ab_fmt_hint: '输出文件扩展名 <code>.enc1</code>，证书文件扩展名 <code>.enc1cert</code>。',
    ab_format_code: '[header 88+N] [verify 48] [metaLen 2] [meta N] [chunk0 .. chunkN-1]\n\nheader: magic "ENC1" | version | flags | kdfId | iterations | salt(16)\n        certId(16) | credentialIdHash(16) | prfSalt(16) | nonceBase(7)\n        chunkSizeLog2 | totalChunks | credentialIdLen | credentialId',

    st_preparing: '准备中…',
    st_header: '正在生成文件头…',
    st_deriving: '正在派生主密钥（这一步故意很慢，用于对抗暴力破解）…',
    st_verifying: '正在验证密钥…',
    st_meta: '正在读取文件信息…',
    st_step1: '第 1/2 步：请选择证书文件的保存位置（它比密文还重要）…',
    st_step2: '第 2/2 步：请选择密文文件的保存位置…',
    st_cancel_nocert: '已取消：证书没保存，所以没有生成密文（避免出现永远打不开的文件）',
    st_cancel_certsaved: '已取消。证书已保存在你选的位置（{name}），可以下次继续用它加密。',
    st_wa: '请在设备上完成验证（指纹 / PIN / 触摸）…',
    st_done_enc: '完成：{size} 已加密',
    st_done_dec: '完成：{name}（{size}）已写入',
    st_done_dec_dl: '完成：{name}（{size}）已开始下载',
    st_chunks: '{verb} {cur}/{total} 块（{pct}%）',
    verb_encrypt: '加密',
    verb_decrypt: '解密',
    pw_mismatch: '两次输入的口令不一致',
    st_failed: '失败：{msg}',
    st_cancelled: '已取消',

    kv_output: '密文',
    kv_cipher_size: '密文大小',
    kv_name: '文件名',
    kv_size: '大小',
    kv_type: '类型',
    kv_chunks: '分块数',
    kv_kdf: '口令派生',
    kv_cert: '证书',
    kv_cert_id: '证书 ID',
    kv_integrity: '完整性',
    kv_integrity_bad: '校验失败：可能已损坏或被改写',
    kv_integrity_ok: '正常 ✓',
    kv_note: '备注',
    kv_created: '创建时间',
    kv_need: '需要',
    kv_status: '状态',
    kv_downloaded: '已下载',
    unknown: '未知',
    cert_picker: '已保存到你选择的位置（{name}）',
    cert_download: '{name} —— 已通过浏览器下载保存，去浏览器的下载目录（通常是「下载」或桌面）找',
    cert_existing: '使用已有证书',
    cert_none: '未启用（仅口令保护）',
    cert_backup: '立刻把证书再复制一份到别处（U 盘 / 密码管理器 / 打印成纸）。绝对不要只和密文放在同一个目录 —— 一起丢就全没了，而且没有任何办法找回。',
    rc_title: '恢复码（与硬件密钥等价）',
    rc_body: '它是第三因子的完整备份：设备丢失、指纹重录、换电脑时用它顶上。请打印或抄写后离线保存 —— 它和证书文件一样，丢了就无法恢复。',
    rc_ok: '恢复码格式正确 ✓',
    str_label: '强度：{level}',
    str_weak: '弱',
    str_medium: '中',
    str_strong: '强',
    str_weak_extra: '　口令是唯一无法找回的东西，建议更长、更随机。',
    str_ok_extra: '　不过就算口令一般，配上证书文件也安全得多。',
    fac_password: '口令',
    fac_cert: '证书文件（ID {id}）',
    fac_k3: '硬件密钥或恢复码',
    fac_pw_only: '仅口令保护',
    dec_unrecognized: '无法识别：{msg}',
    dec_cert_mismatch: '证书不匹配：这份证书不是加密该文件时用的那一份。',
    dec_cert_match: '匹配 ✓',
    wa_state_idle: '未验证',
    wa_state_ok: '已通过硬件密钥 ✓',

    fs_note: '当前浏览器不支持流式写盘，大文件会先拼在内存里再下载，请注意内存占用。',
    foot_fs: '所有运算均在本机完成 · 支持流式写盘',
    foot_plain: '所有运算均在本机完成',
    prf_hint_ok: '注册时设备会要求指纹/PIN/触摸确认。若设备不支持 PRF，注册会直接失败而不会静默降级。',
    prf_hint_bad: '当前环境不支持：{reason}。可以只用「口令 + 证书文件」两因子。',
    cred_empty: '本机还没有记录任何安全密钥凭证。',

    err_not_enc1: '这不是 ENC1 加密文件（魔数不匹配）',
    err_bad_version: '不支持的格式版本 v{v}',
    err_bad_kdf: '不支持的 KDF 标识 {id}',
    err_bad_rounds: '文件头记录的 KDF 轮数不合理，文件可能已损坏',
    err_bad_chunk: '文件头记录的块大小不合理，文件可能已损坏',
    err_too_short: '文件过短，不是有效的 ENC1 容器',
    err_header_trunc: '文件头被截断',
    err_incomplete: '文件不完整，或不是有效的 ENC1 容器',
    err_cred_long: 'credentialId 过长',
    err_need_cert: '此文件需要证书文件（第二因子）',
    err_need_k3: '此文件需要硬件密钥或恢复码（第三因子）',
    err_cert_mismatch: '证书文件不匹配：它不是加密这个文件所用的那一份',
    err_missing_credid: '文件缺少硬件密钥凭证标识',
    err_size_mismatch: '文件大小与头部记录不一致（文件可能被截断或损坏）',
    err_key_or_corrupt: '密钥错误，或文件已被修改/损坏',
    err_meta_broken: '元数据无法解析，文件可能已损坏',
    err_meta_long: '元数据过长',
    err_k3_no_cred: '启用硬件密钥因子时必须提供 credentialId',
    err_b32: '恢复码含有无效字符',
    err_rc_len: '恢复码长度不对（应为 {bytes} 字节 / 32 个字符）',
    err_cert_fmt: '这不是有效的 ENC1 证书文件',
    err_cert_nodata: '证书文件缺少密钥数据',
    err_cert_key: '证书文件的密钥数据无法解码',
    err_cert_len: '证书密钥长度不对（应为 {bytes} 字节）',

    err_wa_browser: '此浏览器不支持 WebAuthn',
    err_wa_secure: 'WebAuthn 需要安全上下文，请通过 http://localhost 打开',
    err_wa_reg_fail: '注册失败：{msg}',
    err_wa_reg_none: '注册失败：未返回凭证',
    err_wa_no_prf: '此设备/浏览器不支持 WebAuthn PRF，无法用它派生密钥。（不会退化为不安全方案：硬件因子要么可用，要么不启用）',
    err_wa_get_fail: '硬件密钥验证失败：{msg}',
    err_wa_get_none: '硬件密钥验证失败：未返回断言',
    err_wa_no_prf_out: '该设备未返回 PRF 输出，无法派生密钥。请改用恢复码。',
    wa_notallowed: '操作被取消或超时（没有在设备上完成验证？）',
    wa_invalidstate: '该安全密钥已注册过',
    wa_notsupported: '设备或浏览器不支持此操作',
    wa_security: '当前页面不是安全上下文，WebAuthn 不可用（请用 localhost 打开）',
  },
};

export function t(key, vars) {
  let s = dicts[lang]?.[key] ?? dicts.en[key] ?? key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      s = s.replaceAll(`{${k}}`, String(v));
    }
  }
  return s;
}

/** 把字典应用到当前 DOM（语言切换或首次加载时调用） */
export function applyI18n() {
  document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
  document.title = t('doc_title');
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll('[data-i18n-html]').forEach((el) => {
    el.innerHTML = t(el.dataset.i18nHtml);
  });
  document.querySelectorAll('[data-i18n-ph]').forEach((el) => {
    el.placeholder = t(el.dataset.i18nPh);
  });
}
