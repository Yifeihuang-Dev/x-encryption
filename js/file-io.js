/**
 * 文件输入/输出适配
 *
 * 两条写入路径：
 *  - File System Access API（Chrome/Edge）：流式写盘，大文件不会撑爆内存
 *  - 退化路径：拼 Blob 再触发下载（Safari/Firefox），受内存限制
 * 读取始终是分块的，靠 Blob.slice 随机访问，不整文件载入。
 */

export function isFsAccessAvailable() {
  return typeof window !== 'undefined' && typeof window.showSaveFilePicker === 'function';
}

export function createMemorySink() {
  const parts = [];
  let size = 0;
  return {
    async write(bytes) {
      // 拷贝一份，避免调用方复用同一块缓冲区导致数据错乱
      parts.push(bytes.slice());
      size += bytes.length;
    },
    async close() {},
    get size() {
      return size;
    },
    toBlob(type = 'application/octet-stream') {
      return new Blob(parts, { type });
    },
  };
}

export async function createFileSink(suggestedName, { description = 'ENC1 文件', accept = [] } = {}) {
  const options = { suggestedName };
  // accept 为空时不传 types：否则浏览器会因空的接受类型集合而报错
  if (accept && accept.length) {
    options.types = [{ description, accept: { 'application/octet-stream': accept } }];
  }
  const handle = await window.showSaveFilePicker(options);
  const writable = await handle.createWritable();
  return {
    async write(bytes) {
      await writable.write(bytes);
    },
    async close() {
      await writable.close();
    },
    handle,
  };
}

export function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

export function downloadText(text, filename, type = 'text/plain;charset=utf-8') {
  downloadBlob(new Blob([text], { type }), filename);
}

/**
 * 用保存对话框写文本（证书文件走这条路径）。
 * 证书必须让用户自己选位置：它比密文还重要，用户必须确切知道它在哪。
 */
export async function saveTextWithPicker(text, suggestedName, { description = 'ENC1 证书文件', accept = [] } = {}) {
  const options = { suggestedName };
  if (accept && accept.length) {
    options.types = [{ description, accept: { 'text/plain': accept } }];
  }
  const handle = await window.showSaveFilePicker(options);
  const writable = await handle.createWritable();
  try {
    await writable.write(text);
  } finally {
    await writable.close();
  }
  return true;
}

export function formatSize(bytes) {
  if (!Number.isFinite(bytes)) return '—';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = bytes / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

/** 让拖放区同时支持点击选择与拖拽 */
export function wireDropzone(zone, input, onFile) {
  const openPicker = () => input.click();
  zone.addEventListener('click', (e) => {
    // e.target === input 时必须放行：input.click() 会冒泡回来，否则会无限递归
    if (e.target === input) return;
    if (e.target.closest('input, button, a')) return;
    openPicker();
  });
  zone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      openPicker();
    }
  });
  input.addEventListener('change', () => {
    if (input.files && input.files[0]) onFile(input.files[0]);
  });
  const stop = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };
  zone.addEventListener('dragenter', (e) => {
    stop(e);
    zone.classList.add('dragover');
  });
  zone.addEventListener('dragover', stop);
  zone.addEventListener('dragleave', (e) => {
    stop(e);
    zone.classList.remove('dragover');
  });
  zone.addEventListener('drop', (e) => {
    stop(e);
    zone.classList.remove('dragover');
    const f = e.dataTransfer?.files?.[0];
    if (f) onFile(f);
  });
}
