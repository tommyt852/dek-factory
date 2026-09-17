# dek-factory

私有 **DEK 工廠 / 金鑰包裝工具** — **純瀏覽器靜態站**，無 Node.js、無 npm、無建置步驟、無伺服器。

註冊與包裝在此完成。Chatroom 負責日常傾偈加密；本工具只做工廠操作（建立、用戶、輪替）。

**本倉庫為 private，請保持私有。**

## 如何開啟

1. 複製整個資料夾到本機。
2. **雙擊** `index.html`，或用任意靜態伺服器開啟，例如：

```bash
# Python 3
python3 -m http.server 8080
# 然後瀏覽 http://localhost:8080/
```

> 部分瀏覽器對 `file://` 的 ES modules 有 CORS 限制；若雙擊無法載入腳本，請改用本機靜態伺服器。Web Crypto 在 `https` / `localhost` 一定可用。

**無 CDN、無外部腳本或字型** — 全部為本機檔案。

## 安全模型（請先讀）

- 一把 **資料加密金鑰（DEK）** 加密 `chat-history.enc`。
- 每位用戶在 `keyring.json` 中有一份 **經口傳 passphrase 包裝** 的 DEK（PBKDF2-SHA-256 → AES-256-GCM）。
- 原始 DEK **只**存在於：
  - 瀏覽器 **JavaScript 記憶體**（關閉分頁即消失）
  - 可選下載的 `.dek` 操作者離線備份（**LOCAL ONLY**，少用）
- **網路磁碟 / 共享儲存只應放：**
  - `keyring.json`
  - `chat-history.enc`
- **絕對不要**把 `.dek` 放到網路磁碟、git、聊天、郵件。
- Passphrase **口頭 / 帶外** 傳遞。永不寫入 URL、localStorage、或與產物同目錄的檔案。

## 操作流程（對應 UI 三個分頁）

### 1. 開始

兩個路徑擇一：

- **第一次建立**：一掣產生記憶體 DEK、空 keyring、revision 1 的空 enc，並下載 `keyring.json` + `chat-history.enc`。預設 **不下載** `.dek`（進階可勾選）。
- **載入已有檔案**：選 `keyring.json` + `chat-history.enc` → 載入 → 用口傳 passphrase 解鎖 DEK 到記憶體（主路徑唔使 `.dek`）。

步驟口訣：載入或建立 → 管理用戶 → 只把 keyring+enc 放到 network drive。

### 2. 用戶

需要記憶體已有 DEK。新增／移除用戶後會下載新 `keyring.json`；覆蓋到 network drive。enc 通常唔使動，除非輪替。

### 3. 輪替

預設用口傳 passphrase 解鎖舊 DEK（亦可改用記憶體 DEK）。解密歷史 → 新 DEK → 重加密（revision +1）→ **清空所有用戶** → 下載新 keyring + enc。`.dek` 下載為進階、預設唔下載。之後要重新「新增用戶」。

錯誤 passphrase 會在寫入前失敗，不破壞既有狀態。

### 進階（摺疊，少用）

- 下載／匯入 `.dek`（僅本機後備）
- 明文 JSON 加密／解密（管理員救資料；日常傾偈用 chatroom）
- 重新下載目前記憶體中的 keyring / enc

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
| Salt | 每位用戶 16 隨機 bytes |
| IV | 每次加密 12 隨機 bytes |
| Auth tag | 16 bytes（GCM），**獨立欄位** |

JSON 中所有二進位欄位為 **標準 Base64**。

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
2. 每位用戶口傳 passphrase：
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

### `.dek`（僅本機，少用）

- 原始 **32-byte 二進位**，或同等 base64 文字檔。
- **永不**放到網路磁碟或 git。
- 解鎖／日常路徑 **不需要** `.dek`。

## 目錄結構

```text
index.html      # 繁中 UI（開始 / 用戶 / 輪替）
styles.css      # 本機樣式（無外部字型）
js/crypto.js    # Web Crypto：wrap / unwrap / encrypt / decrypt
js/app.js       # UI 邏輯與下載
README.md       # 本說明（含 schema）
.gitignore      # .dek、.DS_Store 等
```

無 `package.json`、無 `node_modules`、無建置。

## 口令強度

新增用戶時拒絕：

- 少於 **12** 字元
- 命中拒絕清單（`password`、`passphrase`、`demo-pass-only` 等，不分大小寫）

## 授權

UNLICENSED — 僅供私有使用。
