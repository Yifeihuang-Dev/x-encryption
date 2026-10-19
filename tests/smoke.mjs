/**
 * 核心逻辑冒烟测试（Node 环境，不需要浏览器）
 * 运行：node tests/smoke.mjs
 *
 * 覆盖：正常往返、空文件、单因子、证书/恢复码往返，
 * 以及几类必须被拒绝的攻击：错口令、缺证书、错证书、篡改密文、截断、块重排。
 */

import { encryptToSink, decryptToSink, readHeader, memorySource, fileSource, VERIFY_BLOCK_LEN } from '../js/container.js';
import {
  generateCertKey,
  serializeCertificate,
  parseCertificate,
  certId,
  generateRecoveryCode,
  decodeRecoveryCode,
} from '../js/certfile.js';
import { randomBytes, hex, timingSafeEqual } from '../js/crypto.js';
import { createMemorySink } from '../js/file-io.js';
import { setLang } from '../js/i18n.js';

// 界面默认英文，但测试断言用的是中文错误文案 —— 切到中文，顺带验证 i18n 机制
setLang('zh');

let pass = 0;
let fail = 0;

function check(name, cond, extra = '') {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}${extra ? ` — ${extra}` : ''}`);
  }
}

async function expectReject(name, fn, keywords) {
  try {
    await fn();
    check(name, false, '本应失败却成功了');
  } catch (err) {
    const msg = err.message || String(err);
    const hit = keywords.some((k) => msg.includes(k));
    check(name, hit, `实际错误：${msg}`);
  }
}

const FAST_ITERATIONS = 1000; // 仅为加速测试，真实默认 600000

async function encryptBytes(plain, { password = 'pw', certKey = null, k3 = null, credentialId = null, iterations = FAST_ITERATIONS } = {}) {
  const sink = createMemorySink();
  const result = await encryptToSink({
    source: memorySource(plain),
    meta: { name: 'test.bin', type: 'application/octet-stream', size: plain.length },
    password,
    certKey,
    k3,
    credentialId,
    iterations,
    sink,
  });
  return { cipher: new Uint8Array(await sink.toBlob().arrayBuffer()), result };
}

async function decryptBytes(cipher, { password = 'pw', certKey = null, k3 = null } = {}) {
  const sink = createMemorySink();
  const { meta } = await decryptToSink({
    source: memorySource(cipher),
    password,
    certKey,
    k3,
    sink,
  });
  return { plain: new Uint8Array(await sink.toBlob().arrayBuffer()), meta };
}

console.log('\nENC1 核心逻辑冒烟测试\n');

/* ---------- 1. 基本往返（多块） ---------- */
console.log('[1] 三因子往返（3.5 MiB，跨 4 块）');
{
  const size = (1024 * 1024 * 3) + 555_555;
  const plain = randomBytes(size);
  const certKey = await generateCertKey();
  const { k3 } = generateRecoveryCode();
  const { cipher, result } = await encryptBytes(plain, { certKey, k3, credentialId: randomBytes(64) });

  check('分块数正确', result.header.totalChunks === 4, `实际 ${result.header.totalChunks}`);
  check('密文比明文大（含头部与标签）', cipher.length > plain.length);
  check('写入字节数与实际一致', result.written === cipher.length);

  const { plain: out, meta } = await decryptBytes(cipher, { certKey, k3 });
  check('解密结果与原文一致', timingSafeEqual(out, plain));
  check('元数据文件名正确', meta.name === 'test.bin');
  check('元数据大小正确', meta.size === size);
}

/* ---------- 2. 空文件 ---------- */
console.log('\n[2] 空文件');
{
  const plain = new Uint8Array(0);
  const certKey = await generateCertKey();
  const { cipher, result } = await encryptBytes(plain, { certKey });
  check('空文件分块数为 0', result.header.totalChunks === 0);
  const { plain: out } = await decryptBytes(cipher, { certKey });
  check('空文件可正常解回', out.length === 0);
}

/* ---------- 3. 仅口令 ---------- */
console.log('\n[3] 仅口令（单因子）');
{
  const plain = randomBytes(5000);
  const { cipher, result } = await encryptBytes(plain);
  check('未声明证书因子', !result.header.needCert);
  const { plain: out } = await decryptBytes(cipher);
  check('单因子可正常解回', timingSafeEqual(out, plain));
}

/* ---------- 4. 证书文件往返 ---------- */
console.log('\n[4] 证书文件序列化');
{
  const key = await generateCertKey();
  const text = await serializeCertificate(key, { label: '测试证书' });
  const parsed = await parseCertificate(text);
  check('证书密钥可还原', timingSafeEqual(parsed.certKey, key));
  check('证书 ID 一致', hex(parsed.id) === hex(await certId(key)));
  check('完整性校验通过', parsed.checksumOk === true);
  check('备注保留', parsed.label === '测试证书');

  const damaged = text.replace(/^[A-Za-z0-9+/=]{20}/m, 'AAAAAAAAAAAAAAAAAAAA');
  let checksumFailed = false;
  try {
    const p2 = await parseCertificate(damaged);
    checksumFailed = p2.checksumOk === false;
  } catch {
    checksumFailed = true;
  }
  check('被改写后校验不通过', checksumFailed);
}

/* ---------- 5. 恢复码往返 ---------- */
console.log('\n[5] 恢复码');
{
  const { k3, text } = generateRecoveryCode();
  const back = decodeRecoveryCode(text);
  check('恢复码可还原为 k3', timingSafeEqual(back, k3));
  check('恢复码长度为 32 字符（不含分隔符）', text.replace(/-/g, '').length === 32);
  check('小写与空格也能解析', timingSafeEqual(decodeRecoveryCode(text.toLowerCase().replace(/-/g, ' ')), k3));
}

/* ---------- 6. 必须被拒绝的情况 ---------- */
console.log('\n[6] 安全断言（这些必须失败）');
{
  // 至少 3 块，块重排测试才有可交换的块
  const plain = randomBytes((1024 * 1024 * 2) + 12345);
  const certKey = await generateCertKey();
  const { k3 } = generateRecoveryCode();
  const { cipher } = await encryptBytes(plain, { certKey, k3, credentialId: randomBytes(64) });

  await expectReject('错误口令', () => decryptBytes(cipher, { certKey, k3, password: 'wrong' }), ['密钥错误']);
  await expectReject('缺少证书文件', () => decryptBytes(cipher, { k3 }), ['需要证书']);
  await expectReject('缺少硬件密钥因子', () => decryptBytes(cipher, { certKey }), ['需要硬件密钥']);
  await expectReject(
    '错误的证书文件',
    async () => {
      const other = await generateCertKey();
      return decryptBytes(cipher, { certKey: other, k3 });
    },
    ['不匹配'],
  );
  await expectReject(
    '错误的恢复码',
    async () => {
      const { k3: bad } = generateRecoveryCode();
      return decryptBytes(cipher, { certKey, k3: bad });
    },
    ['密钥错误'],
  );

  // 篡改密文正文（最后一字节）
  const tampered = cipher.slice();
  tampered[tampered.length - 1] ^= 0x01;
  await expectReject('篡改密文', () => decryptBytes(tampered, { certKey, k3 }), ['密钥错误']);

  // 篡改文件头（KDF 轮数）—— 必须被 AAD 挡住，这是防降级攻击的关键
  const tamperedHeader = cipher.slice();
  tamperedHeader[7] ^= 0xff;
  await expectReject('篡改文件头（降级 KDF）', () => decryptBytes(tamperedHeader, { certKey, k3 }), ['密钥错误', '文件']);

  // 截断：砍掉最后 100 字节
  await expectReject('截断文件', () => decryptBytes(cipher.slice(0, cipher.length - 100), { certKey, k3 }), ['不一致', '密钥错误', '文件']);

  // 块重排：交换数据块 0 与块 1（每块 1MiB+16）
  {
    const header = await readHeader(memorySource(cipher));
    const blockStride = (1 << 20) + 16;
    const start = header.headerLen + VERIFY_BLOCK_LEN + 2;
    // 元数据长度未知，先从文件读出 metaLen 再定位数据区
    const metaLen = (cipher[start - 2] << 8) | cipher[start - 1];
    const dataStart = start + metaLen;
    if (cipher.length - dataStart >= blockStride * 2) {
      const swapped = cipher.slice();
      const a = dataStart;
      const b = dataStart + blockStride;
      for (let i = 0; i < blockStride; i++) {
        const t = swapped[a + i];
        swapped[a + i] = swapped[b + i];
        swapped[b + i] = t;
      }
      await expectReject('块重排', () => decryptBytes(swapped, { certKey, k3 }), ['密钥错误']);
    } else {
      console.log('  – 跳过块重排测试（数据不足两块）');
    }
  }
}

/* ---------- 7. File/Blob 数据源 ---------- */
console.log('\n[7] File / Blob 数据源');
{
  const plain = randomBytes(2_500_000);
  const file = new File([plain], 'photo.jpg', { type: 'image/jpeg' });
  const certKey = await generateCertKey();
  const sink = createMemorySink();
  await encryptToSink({
    source: fileSource(file),
    meta: { name: file.name, type: file.type, size: file.size },
    password: 'pw',
    certKey,
    iterations: FAST_ITERATIONS,
    sink,
  });
  const cipher = new Uint8Array(await sink.toBlob().arrayBuffer());
  const { plain: out, meta } = await decryptBytes(cipher, { certKey });
  check('File 源往返一致', timingSafeEqual(out, plain));
  check('文件名与类型保留', meta.name === 'photo.jpg' && meta.type === 'image/jpeg');
}

console.log(`\n结果：${pass} 通过，${fail} 失败\n`);
process.exit(fail === 0 ? 0 : 1);
