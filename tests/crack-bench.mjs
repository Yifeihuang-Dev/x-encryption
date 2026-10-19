/**
 * 暴力破解基准测试（仅用于测试你自己拥有的文件）
 *
 * 目的：量化「攻击者拿到密文（最坏情况下连证书一起拿到）后，用一台普通电脑
 *      能跑多快」，从而反推什么样的口令强度才够用。
 *
 * 关键点：破解走的是 container.js 的 verifyPasswordAt —— 与真实解密完全相同的
 *        派生链路（PBKDF2 → 三因子 HKDF 合并 → AES-GCM 解验证块），
 *        所以测出的速率就是真实攻击者的速率，不是近似估算。
 *
 * 用法：
 *   node tests/crack-bench.mjs --selftest
 *   node tests/crack-bench.mjs <file.enc1> [--cert x.enc1cert] [--mode dict|brute]
 *        [--charset digits|lower|alnum] [--len 6] [--seconds 30] [--workers 8]
 *
 * 想压满 CPU 请带上线程池环境变量：
 *   UV_THREADPOOL_SIZE=32 node tests/crack-bench.mjs ...
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';

import { readHeader, verifyPasswordAt, HEADER_FIXED_LEN, VERIFY_BLOCK_LEN } from '../js/container.js';
import { generateCertKey, parseCertificate } from '../js/certfile.js';
import { encryptToSink, memorySource } from '../js/container.js';
import { createMemorySink } from '../js/file-io.js';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

/* ============ 文件数据源（同步 fs，供 readHeader 使用） ============ */

function fsSource(filePath) {
  const fd = fs.openSync(filePath, 'r');
  const size = fs.fstatSync(fd).size;
  return {
    size,
    async read(offset, length) {
      const buf = Buffer.alloc(length);
      fs.readSync(fd, buf, 0, length, offset);
      return new Uint8Array(buf);
    },
    close() {
      fs.closeSync(fd);
    },
  };
}

/* ============ 候选口令生成器 ============ */

const CHARSETS = {
  digits: '0123456789',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  alnum: 'abcdefghijklmnopqrstuvwxyz0123456789',
};

function* bruteGen(charset, len, start = 0) {
  const n = charset.length;
  const total = n ** len;
  const idx = new Array(len).fill(0);
  for (let c = start; c < total; c++) {
    let x = c;
    for (let i = len - 1; i >= 0; i--) {
      idx[i] = x % n;
      x = Math.floor(x / n);
    }
    yield idx.map((i) => charset[i]).join('');
  }
}

// 高频弱口令样本（用于「最坏情况」演示：拿证书的人会先试这些）
const COMMON = [
  '123456', '12345678', '123456789', '1234567890', 'password', 'password1',
  'qwerty', 'abc123', '111111', '123123', 'admin', 'letmein', 'welcome',
  'monkey', 'dragon', 'iloveyou', 'sunshine', 'princess', 'football', 'baseball',
  'master', 'hello', 'freedom', 'whatever', 'qazwsx', 'trustno1', '000000',
  '1q2w3e4r', '654321', 'superman', 'asdfgh', 'zxcvbn', '1qaz2wsx', 'qwertyuiop',
  'password123', 'Passw0rd', 'Passw0rd!', 'Aa123456', 'a123456', '5201314',
  'woaini', 'wang', 'zhang', 'test', 'test123', 'root', 'toor', 'secret',
  'xhc2024', 'apple', 'iphone', '1234', '12345', '1234567', '88888888',
  'Aa12345678', 'Qwerty123', 'Summer2024', 'Winter2024', 'Spring2025',
];

/* ============ Worker 侧 ============ */

async function workerMain() {
  const { header, verifyCipher, certKey, k3 } = workerData;
  const CONC = 8; // 单 worker 内的并发度，用于压满 libuv 线程池

  parentPort.on('message', async (batch) => {
    let found = null;
    for (let i = 0; i < batch.length && !found; i += CONC) {
      const slice = batch.slice(i, i + CONC);
      const results = await Promise.all(
        slice.map(async (pwd) => ((await verifyPasswordAt(header, verifyCipher, { password: pwd, certKey, k3 })) ? pwd : null)),
      );
      found = results.find((r) => r !== null) || null;
    }
    parentPort.postMessage({ tried: batch.length, found });
  });
  parentPort.postMessage({ ready: true });
}

/* ============ 主进程侧 ============ */

function fmtDuration(sec) {
  if (!isFinite(sec)) return '永久';
  const units = [
    ['年', 365 * 24 * 3600],
    ['天', 24 * 3600],
    ['小时', 3600],
    ['分钟', 60],
    ['秒', 1],
  ];
  for (const [name, s] of units) {
    if (sec >= s) return `${(sec / s).toFixed(sec >= s * 100 ? 0 : 1)} ${name}`;
  }
  return `${sec.toFixed(2)} 秒`;
}

function fmtBig(n) {
  if (n >= 1e12) return `${(n / 1e12).toFixed(1)} 万亿`;
  if (n >= 1e8) return `${(n / 1e8).toFixed(1)} 亿`;
  if (n >= 1e4) return `${(n / 1e4).toFixed(1)} 万`;
  return String(n);
}

async function runAttack({ header, verifyCipher, certKey, k3, gen, seconds, workers, label }) {
  const payload = { header, verifyCipher, certKey, k3 };
  const pool = [];
  for (let i = 0; i < workers; i++) {
    const w = new Worker(fileURLToPath(import.meta.url), { workerData: payload });
    w.busy = false;
    w.on('message', () => {});
    pool.push(w);
  }

  let tried = 0;
  let found = null;
  const t0 = Date.now();
  let lastReport = t0;

  const results = new Map();
  pool.forEach((w) => {
    w.on('message', (msg) => {
      if (msg.ready) return;
      tried += msg.tried;
      if (msg.found) found = msg.found;
      results.set(w, msg);
      w.busy = false;
    });
  });

  await new Promise((resolveReady) => {
    let ready = 0;
    pool.forEach((w) => w.on('message', (m) => { if (m.ready && ++ready === pool.length) resolveReady(); }));
  });

  const stop = () => pool.forEach((w) => w.terminate());

  const BATCH = 16; // 小批量派发，保证 8 个核都有活干
  let exhausted = false;

  while (!found && Date.now() - t0 < seconds * 1000) {
    let dispatched = false;
    for (const w of pool) {
      if (w.busy) continue;
      const batch = [];
      for (let i = 0; i < BATCH; i++) {
        const next = gen.next();
        if (next.done) break;
        batch.push(next.value);
      }
      if (!batch.length) continue; // 这个 worker 暂时没活
      w.busy = true;
      w.postMessage(batch);
      dispatched = true;
    }
    if (!dispatched) {
      // 没有可派发的活，且所有 worker 都空闲 → 候选空间真的穷尽了
      if (pool.every((w) => !w.busy)) {
        exhausted = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 5));
    } else {
      await new Promise((r) => setTimeout(r, 0));
    }

    const now = Date.now();
    if (now - lastReport >= 5000) {
      const rate = tried / ((now - t0) / 1000);
      process.stdout.write(`   … 已试 ${fmtBig(tried)} 个，${rate.toFixed(1)} 次/秒\n`);
      lastReport = now;
    }
  }

  // 等最后一批回包
  while (pool.some((w) => w.busy) && !found) {
    await new Promise((r) => setTimeout(r, 50));
  }
  const elapsed = (Date.now() - t0) / 1000;
  const rate = tried / (elapsed || 1);
  stop();
  return { tried, found, rate, elapsed, exhausted, label };
}

function report(result, keyspaces) {
  console.log('\n──────── 结果 ────────');
  console.log(`场景            ${result.label}`);
  console.log(`耗时            ${result.elapsed.toFixed(1)} 秒`);
  console.log(`尝试次数        ${fmtBig(result.tried)}`);
  console.log(`破解速率        ${result.rate.toFixed(1)} 次/秒（全机满载）`);
  console.log(`结果            ${result.found ? `已破解！口令是 "${result.found}"` : result.exhausted ? '候选空间已穷尽，未命中' : '未命中'}`);

  if (keyspaces) {
    console.log('\n──── 按此速率外推：破开口令需要多久 ────');
    for (const [name, size] of keyspaces) {
      console.log(`  ${name.padEnd(24)} 密钥空间 ${String(size.toExponential(1)).padStart(9)}  →  ${fmtDuration(size / result.rate)}`);
    }
  }
}

/* ============ 自我校准：先证明脚本真的能破开 ============ */

async function selftest(seconds, workers) {
  console.log('【校准】生成一个已知口令的测试文件，再用本脚本去破它\n');
  const password = 'Xe-selftest-2026';
  const certKey = await generateCertKey();
  const sink = createMemorySink();
  const plain = new Uint8Array(2048).fill(7);

  await encryptToSink({
    source: memorySource(plain),
    meta: { name: 'selftest.bin', type: '', size: plain.length, createdAt: new Date().toISOString() },
    password,
    certKey,
    k3: null,
    credentialId: null,
    prfSalt: null,
    sink,
    onProgress: () => {},
  });
  const bytes = new Uint8Array(await sink.toBlob().arrayBuffer());
  const source = memorySource(bytes);
  const header = await readHeader(source);
  const verifyCipher = await source.read(header.headerLen, VERIFY_BLOCK_LEN);

  // 干扰项 800 条，真实口令放在正中第 401 位 —— 既验证能破，也留出足够样本测速率
  const filler = Array.from({ length: 800 }, (_, i) => `filler-pwd-${i}`);
  const dict = filler.slice(0, 400).concat([password], filler.slice(400));
  console.log(`  测试文件：${header.totalChunks} 块，需要证书=${header.needCert}，KDF ${header.iterations} 轮`);
  console.log(`  字典：${dict.length} 条（真实口令在第 401 位）\n`);

  const result = await runAttack({
    header,
    verifyCipher,
    certKey,
    k3: null,
    gen: dict[Symbol.iterator](),
    seconds,
    workers,
    label: '校准：已知口令在字典中',
  });
  report(result, null);
  return result.found === password;
}

/* ============ 入口 ============ */

async function main() {
  const args = process.argv.slice(2);
  const get = (k, d = null) => {
    const i = args.indexOf(k);
    return i >= 0 ? args[i + 1] : d;
  };
  const workers = Number(get('--workers', os.cpus().length));
  const seconds = Number(get('--seconds', 30));
  const mode = get('--mode', 'dict');
  const charsetName = get('--charset', 'digits');
  const len = Number(get('--len', 6));
  const certPath = get('--cert');
  const target = args.find((a) => !a.startsWith('--'));

  console.log('════════ XEncryption 暴力破解基准 ════════');
  console.log(`CPU        ${os.cpus()[0]?.model || '未知'}`);
  console.log(`核心数      ${os.cpus().length}（本次启用 ${workers} 个 worker）`);
  console.log(`线程池      UV_THREADPOOL_SIZE=${process.env.UV_THREADPOOL_SIZE || 4}（默认）`);

  if (args.includes('--selftest')) {
    const ok = await selftest(seconds, workers);
    if (!ok) {
      console.log('\n校准失败：脚本没能破开已知口令的文件，后面的速率不可信。');
      process.exit(1);
    }
    console.log('\n校准通过 —— 下面用同一套方法测真实文件。');
    return;
  }

  if (!target) {
    console.log('\n用法：node tests/crack-bench.mjs <file.enc1> [--cert x.enc1cert] [--mode dict|brute] [--seconds 30]');
    return;
  }

  const source = fsSource(target);
  const header = await readHeader(source);
  const verifyCipher = await source.read(header.headerLen, VERIFY_BLOCK_LEN);
  source.close();

  console.log(`\n目标文件    ${path.basename(target)}`);
  console.log(`KDF 轮数    ${header.iterations.toLocaleString()}`);
  console.log(`需要证书    ${header.needCert ? '是' : '否'}`);
  console.log(`需要硬件密钥 ${header.needWebauthn ? '是' : '否'}`);

  let certKey = null;
  if (header.needCert) {
    if (!certPath) {
      console.log('\n⚠ 此文件需要证书而你没提供。');
      console.log('  这正是「无证书 = 无法离线爆破」的体现：没有 k2，攻击者连验证猜测的靶子都没有。');
      console.log('  要测「最坏情况（证书也泄露）」，请用 --cert 指定证书文件。');
      return;
    }
    const parsed = await parseCertificate(fs.readFileSync(certPath, 'utf8'));
    certKey = parsed.certKey;
    console.log(`证书        ${path.basename(certPath)}（ID ${Buffer.from(parsed.id).toString('hex')}）`);
  }

  if (header.needWebauthn) {
    console.log('\n⚠ 此文件启用了硬件密钥因子（第三因子）。');
    console.log('  k3 存在安全硬件里，私钥永不出设备，离线环境无法模拟 —— 攻击者的爆破到这里就结束了。');
    console.log('  这正是第三因子的价值：即使口令弱、证书泄露，离线攻击依然不可行。');
    return;
  }

  const charset = CHARSETS[charsetName] || CHARSETS.digits;
  let gen;
  let keyspaces;
  let label;

  if (mode === 'brute') {
    const size = charset.length ** len;
    gen = bruteGen(charset, len);
    label = `穷举 ${len} 位（字符集 ${charsetName}，空间 ${fmtBig(size)}）`;
    keyspaces = [
      ['6 位纯数字', 10 ** 6],
      ['8 位纯数字', 10 ** 8],
      ['8 位小写字母', 26 ** 8],
      ['8 位字母+数字', 36 ** 8],
      ['10 位字母+数字', 36 ** 10],
      ['12 位大小写+数字+符号', 95 ** 12],
    ];
    console.log(`\n模式        穷举 ${len} 位，字符集 "${charsetName}"（${charset.length} 个字符，空间 ${fmtBig(size)}）`);
  } else {
    gen = COMMON[Symbol.iterator]();
    label = '常见弱口令字典（模拟已泄露证书的最坏情况）';
    keyspaces = [
      ['6 位纯数字', 10 ** 6],
      ['8 位纯数字', 10 ** 8],
      ['8 位小写字母', 26 ** 8],
      ['10 位字母+数字', 36 ** 10],
      ['12 位大小写+数字+符号', 95 ** 12],
    ];
    console.log(`\n模式        常见弱口令字典（${COMMON.length} 条）`);
  }

  console.log(`时长上限    ${seconds} 秒\n`);
  const result = await runAttack({ header, verifyCipher, certKey, k3: null, gen, seconds, workers, label });
  report(result, keyspaces);
}

if (isMainThread) main().catch((e) => { console.error(e); process.exit(1); });
else workerMain();
