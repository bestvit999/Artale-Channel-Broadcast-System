# Artale Channel Broadcast System（公共頻道外接系統）

🎮 用於楓之谷 Artale 伺服器的公共聊天訊息外接系統。透過封包分析，自動解析 TCP 封包中的頻道、暱稱、訊息等資訊，並以 WebSocket 推播給網頁前端顯示。可用於自動顯示聊天、建立好友、整合直播視覺化。

---

## ✅ 功能特色

- 📦 即時封包監聽（TCP port `32800`）
- 🔍 精準解析欄位：`Channel`、`Nickname`、`UserId`、`Text`、`ProfileCode`
- 🧠 自動產生好友標籤格式：`Nickname#UserId`
- 🕒 附加時間戳（`[YYYY-MM-DD HH:MM:SS]`）
- 🌐 透過 WebSocket 推播至前端網頁
- ✨ 支援複製好友資訊、彈性美化 UI
---

## 打包
pyinstaller --name "ArtaleChat" --onefile --windowed --add-data "templates;templates" --add-data "static;static" control_panel.py