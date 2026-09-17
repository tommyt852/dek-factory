/**
 * DEK factory UI — browser-only operator tool.
 * Passphrases never go to URL / localStorage; fields cleared after use.
 */

import {
  DEK_BYTES,
  assertPassphraseStrength,
  generateDek,
  importDekKey,
  exportDekRaw,
  wrapDek,
  unwrapDek,
  createEmptyKeyring,
  createEmptyMessages,
  encryptHistory,
  decryptHistory,
  nextRevision,
  parseDekFileBytes,
  bufToB64,
} from './crypto.js';

/** @type {{
 *   dek: Uint8Array | null,
 *   keyring: object | null,
 *   enc: object | null,
 *   messagesText: string,
 * }} */
const state = {
  dek: null,
  keyring: null,
  enc: null,
  messagesText: JSON.stringify(createEmptyMessages(), null, 2),
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

function setStatus(msg, kind = 'info') {
  const el = $('#status');
  el.textContent = msg;
  el.className = `status status-${kind}`;
}

function refreshStatusBar() {
  const dekEl = $('#state-dek');
  const krEl = $('#state-keyring');
  const encEl = $('#state-enc');
  dekEl.textContent = state.dek ? `已載入（${DEK_BYTES} bytes）` : '未載入';
  dekEl.className = state.dek ? 'pill ok' : 'pill';
  const n = state.keyring?.users?.length ?? 0;
  krEl.textContent = state.keyring
    ? `已載入（${n} 位使用者）`
    : '未載入';
  krEl.className = state.keyring ? 'pill ok' : 'pill';
  const rev =
    state.enc && typeof state.enc.revision === 'number'
      ? state.enc.revision
      : null;
  encEl.textContent = state.enc
    ? `已載入（revision ${rev ?? '?'}）`
    : '未載入';
  encEl.className = state.enc ? 'pill ok' : 'pill';
  fillUserSelects();
}

function fillUserSelects() {
  const users = state.keyring?.users ?? [];
  for (const sel of ['#decrypt-user', '#unlock-user', '#rotate-user', '#remove-user']) {
    const el = $(sel);
    if (!el) continue;
    const prev = el.value;
    el.innerHTML = '';
    if (users.length === 0) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = '（無使用者）';
      el.appendChild(opt);
    } else {
      for (const u of users) {
        const opt = document.createElement('option');
        opt.value = u.id;
        opt.textContent = u.id;
        el.appendChild(opt);
      }
      if (prev && users.some((u) => u.id === prev)) el.value = prev;
    }
  }
}

function downloadBlob(filename, blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function downloadJson(filename, obj) {
  const text = JSON.stringify(obj, null, 2) + '\n';
  downloadBlob(filename, new Blob([text], { type: 'application/json' }));
}

function downloadText(filename, text, mime = 'application/json') {
  const body = text.endsWith('\n') ? text : text + '\n';
  downloadBlob(filename, new Blob([body], { type: mime }));
}

function clearPassphraseFields(...ids) {
  for (const id of ids) {
    const el = $(id);
    if (el) el.value = '';
  }
}

function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result));
    r.onerror = () => reject(r.error || new Error('讀取失敗'));
    r.readAsText(file);
  });
}

function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = () => reject(r.error || new Error('讀取失敗'));
    r.readAsArrayBuffer(file);
  });
}

async function ensureDekInMemory() {
  if (state.dek) return state.dek;
  throw new Error('記憶體中沒有 DEK。請先「初始化」、匯入 .dek，或以使用者口令解鎖。');
}

function requireKeyring() {
  if (!state.keyring) throw new Error('尚未載入 keyring.json');
  return state.keyring;
}

function requireEnc() {
  if (!state.enc) throw new Error('尚未載入 chat-history.enc');
  return state.enc;
}

/* ---------- Init ---------- */
async function onInit() {
  try {
    const dek = generateDek();
    const keyring = createEmptyKeyring();
    const messages = createEmptyMessages();
    const enc = await encryptHistory(dek, messages, 1);

    state.dek = dek;
    state.keyring = keyring;
    state.enc = enc;
    state.messagesText = JSON.stringify(messages, null, 2);
    $('#messages-editor').value = state.messagesText;

    downloadJson('keyring.json', keyring);
    downloadJson('chat-history.enc', enc);

    const alsoDek = $('#init-download-dek').checked;
    const dekFmt = $('#init-dek-format').value;
    if (alsoDek) {
      if (dekFmt === 'raw') {
        downloadBlob(
          'operator-local.dek',
          new Blob([dek], { type: 'application/octet-stream' }),
        );
      } else {
        downloadText('operator-local.dek.b64', bufToB64(dek), 'text/plain');
      }
    }

    refreshStatusBar();
    setStatus(
      '已初始化：產生新 DEK（僅在記憶體）、空 keyring、revision 1 的 chat-history.enc。' +
        (alsoDek
          ? ' 已下載 .dek — 此檔為【僅本機】機密，絕不可放到網路磁碟或 git。'
          : ' 未下載 .dek；可稍後匯入或從使用者解鎖。'),
      'ok',
    );
  } catch (e) {
    setStatus(e.message || String(e), 'err');
  }
}

/* ---------- Import ---------- */
async function onImport() {
  try {
    const krFile = $('#import-keyring').files?.[0];
    const encFile = $('#import-enc').files?.[0];
    const dekFile = $('#import-dek').files?.[0];

    if (!krFile && !encFile && !dekFile) {
      throw new Error('請至少選擇 keyring.json、chat-history.enc 或 .dek 之一');
    }

    if (krFile) {
      const text = await readFileAsText(krFile);
      const obj = JSON.parse(text);
      if (!obj || !Array.isArray(obj.users)) {
        throw new Error('keyring.json 格式無效（缺少 users 陣列）');
      }
      state.keyring = obj;
    }

    if (encFile) {
      const text = await readFileAsText(encFile);
      const obj = JSON.parse(text);
      if (!obj || typeof obj.ciphertext !== 'string') {
        throw new Error('chat-history.enc 格式無效');
      }
      state.enc = obj;
    }

    if (dekFile) {
      const buf = await readFileAsArrayBuffer(dekFile);
      state.dek = parseDekFileBytes(buf);
    }

    refreshStatusBar();
    setStatus('匯入完成。', 'ok');
  } catch (e) {
    setStatus(e.message || String(e), 'err');
  }
}

/* ---------- Unlock from user ---------- */
async function onUnlock() {
  try {
    const keyring = requireKeyring();
    const userId = $('#unlock-user').value;
    const pass = $('#unlock-pass').value;
    if (!userId) throw new Error('請選擇使用者');
    if (!pass) throw new Error('請輸入口令');
    const user = keyring.users.find((u) => u.id === userId);
    if (!user) throw new Error(`找不到使用者：${userId}`);
    const dek = await unwrapDek(user, pass, keyring.kdfIterations);
    state.dek = dek;
    clearPassphraseFields('#unlock-pass');
    refreshStatusBar();
    setStatus(`已從使用者「${userId}」解鎖 DEK 至記憶體。`, 'ok');
  } catch (e) {
    clearPassphraseFields('#unlock-pass');
    setStatus(e.message || String(e), 'err');
  }
}

/* ---------- Clear DEK from memory ---------- */
function onClearDek() {
  state.dek = null;
  refreshStatusBar();
  setStatus('已清除記憶體中的 DEK。', 'info');
}

/* ---------- Add user ---------- */
async function onAddUser() {
  try {
    const dek = await ensureDekInMemory();
    const keyring = state.keyring || createEmptyKeyring();
    if (!state.keyring) state.keyring = keyring;

    const userId = $('#add-user-id').value.trim();
    const p1 = $('#add-pass1').value;
    const p2 = $('#add-pass2').value;
    if (!userId) throw new Error('請輸入使用者 ID');
    if (p1 !== p2) throw new Error('兩次口令不一致');
    assertPassphraseStrength(p1);

    const wrapped = await wrapDek(dek, p1);
    const entry = { id: userId, ...wrapped };
    const idx = keyring.users.findIndex((u) => u.id === userId);
    if (idx >= 0) keyring.users[idx] = entry;
    else keyring.users.push(entry);

    clearPassphraseFields('#add-pass1', '#add-pass2');
    downloadJson('keyring.json', keyring);
    refreshStatusBar();
    setStatus(
      `已為「${userId}」包裝 DEK 並下載更新的 keyring.json。請口頭告知口令，勿寫入檔案。`,
      'ok',
    );
  } catch (e) {
    clearPassphraseFields('#add-pass1', '#add-pass2');
    setStatus(e.message || String(e), 'err');
  }
}

/* ---------- Remove user ---------- */
function onRemoveUser() {
  try {
    const keyring = requireKeyring();
    const userId = $('#remove-user').value;
    if (!userId) throw new Error('請選擇要移除的使用者');
    const before = keyring.users.length;
    keyring.users = keyring.users.filter((u) => u.id !== userId);
    if (keyring.users.length === before) {
      throw new Error(`找不到使用者：${userId}`);
    }
    downloadJson('keyring.json', keyring);
    refreshStatusBar();
    setStatus(
      `已移除「${userId}」。警告：舊 DEK 與剩餘包裝仍可解密密文。若該使用者或口令已洩漏，請立即執行「輪替 DEK」。`,
      'warn',
    );
  } catch (e) {
    setStatus(e.message || String(e), 'err');
  }
}

/* ---------- Encrypt ---------- */
async function onEncrypt() {
  try {
    const dek = await ensureDekInMemory();
    let text = $('#messages-editor').value;
    if (!text.trim()) {
      text = JSON.stringify(createEmptyMessages(), null, 2);
      $('#messages-editor').value = text;
    }
    // Validate JSON
    JSON.parse(text);
    const rev = nextRevision(state.enc);
    const enc = await encryptHistory(dek, text, rev);
    state.enc = enc;
    state.messagesText = text;
    downloadJson('chat-history.enc', enc);
    refreshStatusBar();
    setStatus(`已加密並下載 chat-history.enc（revision ${rev}）。`, 'ok');
  } catch (e) {
    setStatus(e.message || String(e), 'err');
  }
}

async function onLoadPlaintextFile() {
  try {
    const f = $('#encrypt-file').files?.[0];
    if (!f) throw new Error('請選擇明文 messages JSON 檔');
    const text = await readFileAsText(f);
    JSON.parse(text);
    $('#messages-editor').value = text;
    state.messagesText = text;
    setStatus(`已載入明文：${f.name}`, 'ok');
  } catch (e) {
    setStatus(e.message || String(e), 'err');
  }
}

/* ---------- Decrypt ---------- */
async function onDecrypt() {
  try {
    const enc = requireEnc();
    let dek = state.dek;
    const useMemory = $('#decrypt-use-memory').checked;

    if (!useMemory || !dek) {
      const keyring = requireKeyring();
      const userId = $('#decrypt-user').value;
      const pass = $('#decrypt-pass').value;
      if (!userId) throw new Error('請選擇使用者（或勾選使用記憶體 DEK）');
      if (!pass) throw new Error('請輸入口令');
      const user = keyring.users.find((u) => u.id === userId);
      if (!user) throw new Error(`找不到使用者：${userId}`);
      dek = await unwrapDek(user, pass, keyring.kdfIterations);
      clearPassphraseFields('#decrypt-pass');
    }

    const plaintext = await decryptHistory(dek, enc);
    JSON.parse(plaintext); // validate
    $('#messages-editor').value = plaintext;
    state.messagesText = plaintext;
    downloadText('messages.plaintext.json', plaintext);
    refreshStatusBar();
    setStatus('已解密並下載 messages.plaintext.json。', 'ok');
  } catch (e) {
    clearPassphraseFields('#decrypt-pass');
    setStatus(e.message || String(e), 'err');
  }
}

/* ---------- Rotate ---------- */
async function onRotate() {
  try {
    const enc = requireEnc();
    const keyring = requireKeyring();
    let oldDek = state.dek;
    const mode = $('input[name="rotate-mode"]:checked')?.value || 'memory';

    if (mode === 'user') {
      const userId = $('#rotate-user').value;
      const pass = $('#rotate-pass').value;
      if (!userId) throw new Error('請選擇使用者');
      if (!pass) throw new Error('請輸入口令');
      const user = keyring.users.find((u) => u.id === userId);
      if (!user) throw new Error(`找不到使用者：${userId}`);
      try {
        oldDek = await unwrapDek(user, pass, keyring.kdfIterations);
      } catch {
        throw new Error('口令錯誤（unwrap 失敗）— 未寫入任何變更');
      }
      clearPassphraseFields('#rotate-pass');
    } else {
      if (!oldDek) {
        throw new Error(
          '記憶體中沒有 DEK。請改用「使用者口令」模式，或先匯入 .dek / 解鎖。',
        );
      }
    }

    let plaintext;
    try {
      plaintext = await decryptHistory(oldDek, enc);
      JSON.parse(plaintext);
    } catch (err) {
      throw new Error(`無法以舊 DEK 解密歷史：${err.message} — 未寫入任何變更`);
    }

    const oldRevision =
      typeof enc.revision === 'number' && enc.revision >= 1 ? enc.revision : 1;
    const newRevision = oldRevision + 1;
    const clearedUsers = keyring.users.length;

    const newDek = generateDek();
    const newEnc = await encryptHistory(newDek, plaintext, newRevision);
    const newKeyring = {
      ...keyring,
      users: [],
    };

    state.dek = newDek;
    state.enc = newEnc;
    state.keyring = newKeyring;
    state.messagesText = plaintext;
    $('#messages-editor').value = plaintext;

    downloadJson('keyring.json', newKeyring);
    downloadJson('chat-history.enc', newEnc);

    const dekFmt = $('#rotate-dek-format').value;
    if (dekFmt === 'raw') {
      downloadBlob(
        'operator-local.dek',
        new Blob([newDek], { type: 'application/octet-stream' }),
      );
    } else if (dekFmt === 'b64') {
      downloadText('operator-local.dek.b64', bufToB64(newDek), 'text/plain');
    }

    refreshStatusBar();
    setStatus(
      `輪替完成：revision ${oldRevision} → ${newRevision}，已清除 ${clearedUsers} 位使用者。` +
        ' 請重新「新增使用者」包裝新 DEK。.dek 為【僅本機】機密，勿上傳網路磁碟。',
      'ok',
    );
  } catch (e) {
    clearPassphraseFields('#rotate-pass');
    setStatus(e.message || String(e), 'err');
  }
}

/* ---------- Download helpers ---------- */
function onDownloadKeyring() {
  try {
    const keyring = requireKeyring();
    downloadJson('keyring.json', keyring);
    setStatus('已下載 keyring.json', 'ok');
  } catch (e) {
    setStatus(e.message || String(e), 'err');
  }
}

function onDownloadEnc() {
  try {
    const enc = requireEnc();
    downloadJson('chat-history.enc', enc);
    setStatus('已下載 chat-history.enc', 'ok');
  } catch (e) {
    setStatus(e.message || String(e), 'err');
  }
}

function onDownloadDek() {
  try {
    if (!state.dek) throw new Error('記憶體中沒有 DEK');
    const fmt = $('#download-dek-format').value;
    if (fmt === 'raw') {
      downloadBlob(
        'operator-local.dek',
        new Blob([state.dek], { type: 'application/octet-stream' }),
      );
    } else {
      downloadText('operator-local.dek.b64', bufToB64(state.dek), 'text/plain');
    }
    setStatus(
      '已下載 .dek — 【僅本機】機密，絕不可放到網路磁碟、git、聊天或郵件。',
      'warn',
    );
  } catch (e) {
    setStatus(e.message || String(e), 'err');
  }
}

/* ---------- Tabs ---------- */
function initTabs() {
  $$('.tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      const id = btn.dataset.tab;
      $$('.tab').forEach((b) => b.classList.toggle('active', b === btn));
      $$('.panel').forEach((p) =>
        p.classList.toggle('active', p.id === `panel-${id}`),
      );
    });
  });
}

function init() {
  if (!window.crypto?.subtle) {
    setStatus(
      '此瀏覽器不支援 Web Crypto（需要安全環境：https 或 localhost，部分瀏覽器 file:// 也可用）。',
      'err',
    );
  }

  initTabs();
  $('#btn-init').addEventListener('click', onInit);
  $('#btn-import').addEventListener('click', onImport);
  $('#btn-unlock').addEventListener('click', onUnlock);
  $('#btn-clear-dek').addEventListener('click', onClearDek);
  $('#btn-add-user').addEventListener('click', onAddUser);
  $('#btn-remove-user').addEventListener('click', onRemoveUser);
  $('#btn-encrypt').addEventListener('click', onEncrypt);
  $('#btn-load-plain').addEventListener('click', onLoadPlaintextFile);
  $('#btn-decrypt').addEventListener('click', onDecrypt);
  $('#btn-rotate').addEventListener('click', onRotate);
  $('#btn-dl-keyring').addEventListener('click', onDownloadKeyring);
  $('#btn-dl-enc').addEventListener('click', onDownloadEnc);
  $('#btn-dl-dek').addEventListener('click', onDownloadDek);

  $('#messages-editor').value = state.messagesText;
  refreshStatusBar();
  setStatus('就緒。所有運算在本機瀏覽器完成，無伺服器。', 'info');
}

init();
