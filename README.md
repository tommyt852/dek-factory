# dek-factory

私有 **DEK 工廠 / 金鑰包裝工具** — **純瀏覽器靜態站**，無 Node.js、無 npm、無建置步驟、無伺服器。

註冊與包裝在此完成。Chatroom 消費本文件所述固定產物格式（與舊版 Node CLI 相容）。

**本倉庫為 private，請保持私有。**

## 如何開啟

1. 複製整個資料夾到本機。
2. **雙擊** `index.html`，或用任意靜態伺服器開啟，例如：

```bash
# Python 3
python3 -m http.server 8080
# 然後瀏覽 http://localhost:8080/
```

> 部分瀏覽器對 `file://` 的 ES modules 有 CORS 限制；若雙擊無法載入腳本，請改用本機靜態伺服器（或 Chrome 的「允許本機檔案」進階設定）。Web Crypto 在 `https` / `localhost` 一定可用。

**無 CDN、無外部腳本或字型** — 全部為本機檔案。

## 安全模型（請先讀）

- 一把 **資料加密金鑰（DEK）** 加密 `chat-history.enc`。
- 每位使用者在 `keyring.json` 中有一份 **經口令包裝** 的 DEK（PBKDF2-SHA-256 → AES-256-GCM）。
- 原始 DEK **只**存在於：
  - 瀏覽器 **JavaScript 記憶體**（關閉分頁即消失）
  - 可選下載的 `.dek` 操作者離線備份（**LOCAL ONLY**）
- **網路磁碟 / 共享儲存只應放：**
  - `keyring.json`
  - `chat-history.enc`
- **絕對不要**把 `.dek` 放到網路磁碟、git、聊天、郵件或會離開操作者機器的備份。
- 口令 **口頭 / 帶外** 傳遞。永不寫入口令到 URL、localStorage、或與產物同目錄的檔案。
- 使用後 UI 會清空口令欄位。

## 操作流程

### 1. 初始化

開啟「初始化」→ 產生隨機 32-byte DEK（記憶體）、空 `keyring.json`、revision `1` 的空訊息 `chat-history.enc`，並下載。可選下載 `.dek`（原始二進位或 base64）作為操作者備份。

### 2. 新增使用者

需記憶體中已有 DEK（初始化、匯入 `.dek`、或以既有使用者解鎖）。輸入使用者 ID 與口令兩次（≥12 字元 + 拒絕清單），下載更新的 `keyring.json`。

### 3. 發佈到網路磁碟

只複製：

```text
keyring.json
chat-history.enc
```

留下 `.dek`（若有）在操作者本機。

### 4. 加密訊息

上傳或編輯明文 messages JSON → 用記憶體 DEK 加密 → 下載 `chat-history.enc`（若已匯入舊 enc 則 `revision` +1）。

### 5. 解密訊息

選使用者 + 口令（或勾選使用記憶體 DEK）→ 下載明文 JSON。**不需要** `.dek`。

### 6. 移除使用者

從 keyring 刪除條目並下載。**警告：** 舊 DEK 與剩餘包裝仍可解密；若已洩漏請立刻輪替。

### 7. 輪替 DEK

- **記憶體 DEK**，或
- **使用者 + 口令** unwrap（無 `.dek` 時）

然後：解密歷史 → 新 DEK → 重加密（revision +1）→ **清空所有使用者** → 下載新產物與可選 `.dek`。之後須重新「新增使用者」。

錯誤口令在寫入前失敗，不破壞既有狀態。

## 產物格式（與 chatroom 完全一致）

### 密碼學參數

| 參數 | 值 |
|------|-----|
| 資料密碼 | AES-256-GCM |
| 金鑰包裝 | AES-256-GCM |
| KDF | PBKDF2-SHA-256 |
| KDF 迭代 | 600000 |
| DEK | 32 bytes |
| KEK | 32 bytes（來自 PBKDF2） |
| Salt | 每位使用者 16 隨機 bytes |
| IV | 每次加密 12 隨機 bytes |
| Auth tag | 16 bytes（GCM），**獨立欄位** |

JSON 中所有二進位欄位為 **標準 Base64**（與 Web Crypto / Node `Buffer` 相容）。

### `keyring.json`

```json
{
  "version": 1,
  "cipher": "AES-256-GCM",
  "kdf": "PBKDF2-SHA-256",
  "kdfIterations": 600000,
  "wrap": "AES-256-GCM",
  "users": [
    {
      "id": "alice",
      "salt": "<base64 16 bytes>",
      "iv": "<base64 12 bytes>",
      "tag": "<base64 16 bytes>",
      "wrappedKey": "<base64 ciphertext only — DEK 為 32 bytes>"
    }
  ]
}
```

**包裝程序**

1. DEK = 32 隨機 bytes（工廠初始化一次）。
2. 每位使用者口令：
   - `salt` = 16 隨機 bytes
   - `KEK = PBKDF2-SHA-256(passphrase, salt, 600000, 32)`
   - `iv` = 12 隨機 bytes
   - AES-256-GCM 以 KEK 加密 DEK
   - **`tag` 獨立存放**（16-byte auth tag）
   - **`wrappedKey` 僅為密文**（勿把 tag 接在後面）

### `chat-history.enc`

雖為 `.enc` 副檔名，內容是 JSON：

```json
{
  "version": 1,
  "cipher": "AES-256-GCM",
  "revision": 1,
  "iv": "<base64 12>",
  "tag": "<base64 16>",
  "ciphertext": "<base64>"
}
```

- `revision`：樂觀並發計數；初始化為 `1`；每次成功重加密 +1。
- 讀取時若缺 `revision` 視為 `1`。

**明文（加密前）** UTF-8 JSON：

```json
{
  "version": 1,
  "messages": [
    {
      "id": "...",
      "author": "...",
      "body": "...",
      "createdAt": "ISO-8601"
    }
  ]
}
```

### `.dek`（僅本機）

- 原始 **32-byte 二進位**，或同等 base64 文字檔（匯入時兩者皆可）。
- **永不**放到網路磁碟或 git。
- 解密一般使用者路徑 **不需要** `.dek`。

## 目錄結構

```text
index.html      # 繁中 UI
styles.css      # 本機樣式（無外部字型）
js/crypto.js    # Web Crypto：wrap / unwrap / encrypt / decrypt
js/app.js       # UI 邏輯與下載
README.md       # 本說明（含 schema）
.gitignore      # .dek、.DS_Store 等
```

無 `package.json`、無 `node_modules`、無建置。

## 口令強度

新增使用者時拒絕：

- 少於 **12** 字元
- 命中拒絕清單（`password`、`passphrase`、`demo-pass-only` 等，不分大小寫）

## 授權

UNLICENSED — 僅供私有使用。
