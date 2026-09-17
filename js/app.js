/**
 * DEK factory UI — browser-only operator tool.
 * Primary flow: 開始 → 用戶 → 輪替. Advanced tools collapsed.
 * Passphrases never go to URL / localStorage; fields cleared after use.
 */

import {
  DEK_BYTES,
  assertPassphraseStrength,
  generateDek,
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
  krEl.textContent = state.keyring ? `已載入（${n} 位用戶）` : '未載入';
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
  renderUserList();
  updateUsersBanner();
}

function updateUsersBanner() {
  const banner = $('#users-dek-banner');
  if (!banner) return;
  banner.classList.toggle('hidden', !!state.dek);
}

function renderUserList() {
  const list = $('#user-list');
  if (!list) return;
  list.innerHTML = '';
  if (!state.keyring) {
    const li = document.createElement('li');
    li.className = 'muted';
    li.textContent = '（未載入 keyring）';
    list.appendChild(li);
    return;
  }
  const users = state.keyring.users ?? [];
  if (users.length === 0) {
    const li = document.createElement('li');
    li.className = 'muted';
    li.textContent = '（未有用戶 — 請新增）';
    list.appendChild(li);
    return;
  }
  for (const u of users) {
    const li = document.createElement('li');
    li.textContent = u.id;
    list.appendChild(li);
  }
}

function fillUserSelects() {
  const users = state.keyring?.users ?? [];
  for (const sel of [
    '#decrypt-user',
    '#unlock-user',
    '#rotate-user',
    '#remove-user',
  ]) {
    const el = $(sel);
    if (!el) continue;
    const prev = el.value;
    el.innerHTML = '';
    if (users.length === 0) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = '（無用戶）';
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
  throw new Error(
    '記憶體中沒有 DEK。請先去「開始」建立工廠，或載入檔案後用口傳 passphrase 解鎖。',
  );
}

function requireKeyring() {
  if (!state.keyring) throw new Error('尚未載入 keyring.json');
  return state.keyring;
}

function requireEnc() {
  if (!state.enc) throw new Error('尚未載入 chat-history.enc');
  return state.enc;
}

/* ---------- Init（第一次建立） ---------- */
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
    const editor = $('#messages-editor');
    if (editor) editor.value = state.messagesText;

    downloadJson('keyring.json', keyring);
    downloadJson('chat-history.enc', enc);

    const alsoDek = $('#init-download-dek')?.checked;
    const dekFmt = $('#init-dek-format')?.value || 'raw';
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
      '已建立新工廠：DEK 在記憶體、空 keyring、revision 1 的 enc 已下載。' +
        (alsoDek
          ? ' 已下載 .dek — 只係本機後備，絕不可放 network drive。'
          : ' 未下載 .dek（預設）。下一步去「用戶」新增用戶。'),
      'ok',
    );
  } catch (e) {
    setStatus(e.message || String(e), 'err');
  }
}

/* ---------- Import keyring + enc（主路徑） ---------- */
async function onImport() {
  try {
    const krFile = $('#import-keyring').files?.[0];
    const encFile = $('#import-enc').files?.[0];

    if (!krFile || !encFile) {
      throw new Error('請同時揀 keyring.json 同 chat-history.enc');
    }

    const krText = await readFileAsText(krFile);
    const krObj = JSON.parse(krText);
    if (!krObj || !Array.isArray(krObj.users)) {
      throw new Error('keyring.json 格式無效（缺少 users 陣列）');
    }

    const encText = await readFileAsText(encFile);
    const encObj = JSON.parse(encText);
    if (!encObj || typeof encObj.ciphertext !== 'string') {
      throw new Error('chat-history.enc 格式無效');
    }

    state.keyring = krObj;
    state.enc = encObj;

    refreshStatusBar();
    const n = krObj.users.length;
    setStatus(
      `已載入 keyring（${n} 位用戶）同 enc（revision ${encObj.revision ?? '?'}）。` +
        (n > 0
          ? ' 請用口傳 passphrase 解鎖。'
          : ' keyring 未有用戶；若記憶體無 DEK，請用進階匯入 .dek 或重新建立。'),
      'ok',
    );
  } catch (e) {
    setStatus(e.message || String(e), 'err');
  }
}

/* ---------- Unlock from user passphrase ---------- */
async function onUnlock() {
  try {
    const keyring = requireKeyring();
    const userId = $('#unlock-user').value;
    const pass = $('#unlock-pass').value;
    if (!userId) throw new Error('請選擇用戶');
    if (!pass) throw new Error('請輸入口傳 passphrase');
    const user = keyring.users.find((u) => u.id === userId);
    if (!user) throw new Error(`找不到用戶：${userId}`);
    const dek = await unwrapDek(user, pass, keyring.kdfIterations);
    state.dek = dek;
    clearPassphraseFields('#unlock-pass');
    refreshStatusBar();
    setStatus(`已用「${userId}」嘅口傳 passphrase 解鎖 DEK 到記憶體。`, 'ok');
  } catch (e) {
    clearPassphraseFields('#unlock-pass');
    setStatus(e.message || String(e), 'err');
  }
}

function onClearDek() {
  state.dek = null;
  refreshStatusBar();
  setStatus('已清除記憶體中的 DEK。', 'info');
}

/* ---------- Advanced: import .dek only ---------- */
async function onImportDek() {
  try {
    const dekFile = $('#import-dek').files?.[0];
    if (!dekFile) throw new Error('請選擇 .dek 檔');
    const buf = await readFileAsArrayBuffer(dekFile);
    state.dek = parseDekFileBytes(buf);
    refreshStatusBar();
    setStatus('已匯入 .dek 到記憶體（僅本機後備路徑）。', 'ok');
  } catch (e) {
    setStatus(e.message || String(e), 'err');
  }
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
    if (!userId) throw new Error('請輸入用戶 ID');
    if (p1 !== p2) throw new Error('兩次口傳 passphrase 不一致');
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
      `已為「${userId}」包裝並下載 keyring.json。請口頭傳 passphrase；覆蓋到 network drive。`,
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
    if (!userId) throw new Error('請選擇要移除的用戶');
    const before = keyring.users.length;
    keyring.users = keyring.users.filter((u) => u.id !== userId);
    if (keyring.users.length === before) {
      throw new Error(`找不到用戶：${userId}`);
    }
    downloadJson('keyring.json', keyring);
    refreshStatusBar();
    setStatus(
      `已移除「${userId}」並下載 keyring。若口傳 passphrase 可能已洩漏，請去「輪替」。`,
      'warn',
    );
  } catch (e) {
    setStatus(e.message || String(e), 'err');
  }
}

/* ---------- Encrypt / decrypt（進階） ---------- */
async function onEncrypt() {
  try {
    const dek = await ensureDekInMemory();
    let text = $('#messages-editor').value;
    if (!text.trim()) {
      text = JSON.stringify(createEmptyMessages(), null, 2);
      $('#messages-editor').value = text;
    }
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

async function onDecrypt() {
  try {
    const enc = requireEnc();
    let dek = state.dek;
    const useMemory = $('#decrypt-use-memory').checked;

    if (!useMemory || !dek) {
      const keyring = requireKeyring();
      const userId = $('#decrypt-user').value;
      const pass = $('#decrypt-pass').value;
      if (!userId) throw new Error('請選擇用戶（或勾選使用記憶體 DEK）');
      if (!pass) throw new Error('請輸入口傳 passphrase');
      const user = keyring.users.find((u) => u.id === userId);
      if (!user) throw new Error(`找不到用戶：${userId}`);
      dek = await unwrapDek(user, pass, keyring.kdfIterations);
      clearPassphraseFields('#decrypt-pass');
    }

    const plaintext = await decryptHistory(dek, enc);
    JSON.parse(plaintext);
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
    const mode = $('input[name="rotate-mode"]:checked')?.value || 'user';

    if (mode === 'user') {
      const userId = $('#rotate-user').value;
      const pass = $('#rotate-pass').value;
      if (!userId) throw new Error('請選擇用戶');
      if (!pass) throw new Error('請輸入口傳 passphrase');
      const user = keyring.users.find((u) => u.id === userId);
      if (!user) throw new Error(`找不到用戶：${userId}`);
      try {
        oldDek = await unwrapDek(user, pass, keyring.kdfIterations);
      } catch {
        throw new Error('口傳 passphrase 錯誤 — 未寫入任何變更');
      }
      clearPassphraseFields('#rotate-pass');
    } else {
      if (!oldDek) {
        throw new Error(
          '記憶體中沒有 DEK。請改用口傳 passphrase，或先解鎖／匯入 .dek。',
        );
      }
    }

    let plaintext;
    try {
      plaintext = await decryptHistory(oldDek, enc);
      JSON.parse(plaintext);
    } catch (err) {
      throw new Error(
        `無法以舊 DEK 解密歷史：${err.message} — 未寫入任何變更`,
      );
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
    const editor = $('#messages-editor');
    if (editor) editor.value = plaintext;

    downloadJson('keyring.json', newKeyring);
    downloadJson('chat-history.enc', newEnc);

    const dekFmt = $('#rotate-dek-format')?.value || 'none';
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
      `輪替完成：revision ${oldRevision} → ${newRevision}，已清除 ${clearedUsers} 位用戶。` +
        ' 請去「用戶」重新加入。新 keyring + enc 已下載；覆蓋到 network drive。',
      'ok',
    );
  } catch (e) {
    clearPassphraseFields('#rotate-pass');
    setStatus(e.message || String(e), 'err');
  }
}

function updateRotatePassVisibility() {
  const mode = $('input[name="rotate-mode"]:checked')?.value || 'user';
  const block = $('#rotate-pass-block');
  if (block) block.style.display = mode === 'user' ? '' : 'none';
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
      '已下載 .dek — 只係本機後備，絕不可放 network drive / git / 聊天。',
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
      $$('.tab').forEach((b) => {
        const on = b === btn;
        b.classList.toggle('active', on);
        b.setAttribute('aria-selected', on ? 'true' : 'false');
      });
      $$('.panel').forEach((p) =>
        p.classList.toggle('active', p.id === `panel-${id}`),
      );
      if (id === 'users') updateUsersBanner();
    });
  });
}

function init() {
  if (!window.crypto?.subtle) {
    setStatus(
      '此瀏覽器不支援 Web Crypto（需要 https 或 localhost）。',
      'err',
    );
  }

  initTabs();
  $('#btn-init').addEventListener('click', onInit);
  $('#btn-import').addEventListener('click', onImport);
  $('#btn-unlock').addEventListener('click', onUnlock);
  $('#btn-clear-dek').addEventListener('click', onClearDek);
  $('#btn-import-dek').addEventListener('click', onImportDek);
  $('#btn-add-user').addEventListener('click', onAddUser);
  $('#btn-remove-user').addEventListener('click', onRemoveUser);
  $('#btn-encrypt').addEventListener('click', onEncrypt);
  $('#btn-load-plain').addEventListener('click', onLoadPlaintextFile);
  $('#btn-decrypt').addEventListener('click', onDecrypt);
  $('#btn-rotate').addEventListener('click', onRotate);
  $('#btn-dl-keyring').addEventListener('click', onDownloadKeyring);
  $('#btn-dl-enc').addEventListener('click', onDownloadEnc);
  $('#btn-dl-dek').addEventListener('click', onDownloadDek);

  $$('input[name="rotate-mode"]').forEach((r) => {
    r.addEventListener('change', updateRotatePassVisibility);
  });
  updateRotatePassVisibility();

  const editor = $('#messages-editor');
  if (editor) editor.value = state.messagesText;
  refreshStatusBar();
  setStatus(
    '就緒。日常：開始（建立或載入+解鎖）→ 用戶 → 只放 keyring+enc 到 network drive。',
    'info',
  );
}

init();
