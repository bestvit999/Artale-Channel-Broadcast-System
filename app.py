import re
import struct
import sys
import os
import time
import threading
import json
from pathlib import Path
from collections import deque
from flask import Flask, render_template, request, Response, jsonify

# ======== 基本設定 ========
LIVE_CAPTURE = True
PORT = 32800
BPF_FILTER = f"tcp port {PORT}"

# --- Flask & 全域變數 ---
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

template_dir = resource_path('templates')
static_dir = resource_path('static')
app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
# 使用雙端佇列 (deque) 來儲存訊息，並設定最大長度以防止記憶體無限增長
# 每個元素將會是 (timestamp, parsed_dict)
MAX_MESSAGES = 500
main_chat_messages = deque(maxlen=MAX_MESSAGES)

# 儲存關鍵字聊天室的資料
# 結構: { "room_id_1": {"keywords": {"kw1", "kw2"}, "messages": deque()}, ... }
keyword_rooms = {}
data_lock = threading.Lock() # 確保多執行緒安全地存取全域變數

if LIVE_CAPTURE:
    try:
        from scapy.all import AsyncSniffer, TCP
    except ImportError:
        sys.exit("❌ 尚未安裝 scapy，請先 pip install scapy")

# ======== 解析核心 (與原版相同) ========
class ChatParser:
    KNOWN = {"Nickname", "Channel", "Text", "Type", "ProfileCode", "UserId"}

    @staticmethod
    def _parse_struct(data: bytes) -> dict:
        out, colors = {}, []
        i, L = 0, len(data)
        MAX_VAL_LEN = 256

        while i + 4 <= L:
            name_len = int.from_bytes(data[i:i+4], "little")
            if not 0 < name_len <= 64 or i + 4 + name_len + 6 > L:
                i += 1
                continue
            try:
                name = data[i+4:i+4+name_len].decode("ascii")
            except UnicodeDecodeError:
                i += 1
                continue
            cur = i + 4 + name_len
            type_tag = int.from_bytes(data[cur:cur+2], "little")
            val_len = int.from_bytes(data[cur+2:cur+6], "little")
            v_start, v_end = cur + 6, cur + 6 + val_len
            if v_end > L or val_len > MAX_VAL_LEN:
                i += 1
                continue
            if name != "Channel":
                if name in ChatParser.KNOWN:
                    if type_tag == 4:
                        try:
                            out[name] = data[v_start:v_end].decode("utf-8", "replace")
                        except Exception:
                            out[name] = f"[INVALID UTF8]"
                elif name.startswith("#") and name_len == 7:
                    colors.append(name)
            i = v_end

        j = 0
        while j + 4 <= L:
            name_len = int.from_bytes(data[j:j+4], "little")
            if not 0 < name_len <= 64 or j + 4 + name_len + 5 > L:
                j += 1
                continue
            try:
                name = data[j+4:j+4+name_len].decode("ascii")
            except UnicodeDecodeError:
                j += 1
                continue
            if name == "Channel":
                cur = j + 4 + name_len
                type_tag = data[cur]
                val_len = int.from_bytes(data[cur+1:cur+5], "little")
                if type_tag == 2 and 0 < val_len < 9999:
                    out["Channel"] = f"CH{val_len}"
                    break
            j += 1

        if colors: out["color1"] = colors[0]
        if len(colors) > 1: out["color2"] = colors[1]
        
        floats = []
        k = max(i, j)
        while k + 4 <= L:
            floats.append(struct.unpack_from("<f", data, k)[0])
            k += 4
        out["floats"] = floats
        return out

    @classmethod
    def parse_packet_bytes(cls, blob: bytes) -> dict:
        return cls._parse_struct(blob[8:])

    @staticmethod
    def bytes_from_hex_file(path_or_stream) -> bytes:
        if isinstance(path_or_stream, (str, Path)):
            txt = Path(path_or_stream).read_text(encoding="utf-8", errors="ignore")
        else: # for uploaded file stream
            txt = path_or_stream.read().decode("utf-8", "ignore")
        return bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", txt))

# ======== 背景 Sniffer 執行緒 ========

class SnifferThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.buffer = b""
        self.sniffer = None
        self.running = True

    def _on_packet(self, pkt):
        if TCP in pkt and self.running:
            with data_lock:
                self.buffer += bytes(pkt[TCP].payload)
    
    def _process_buffer(self):
        with data_lock:
            buf = self.buffer
            idx = buf.find(b"TOZ ")
            while idx >= 0 and idx + 8 <= len(buf):
                size = int.from_bytes(buf[idx+4:idx+8], "little")
                if idx + 8 + size > len(buf): break
                blob = buf[idx:idx+8+size]
                self.buffer = buf = buf[idx+8+size:]
                self._handle_packet(blob)
                idx = buf.find(b"TOZ ")
            self.buffer = buf

    def _handle_packet(self, blob: bytes):
        try:
            parsed = ChatParser.parse_packet_bytes(blob)
            if not (parsed.get("Nickname") or parsed.get("Text")):
                return

            ts = time.strftime('%H:%M:%S')
            
            # 將訊息加入主聊天室
            main_chat_messages.append((ts, parsed))

            # 檢查是否符合任何關鍵字聊天室
            message_text = parsed.get("Text", "").lower()
            if message_text:
                for room_id, room_data in keyword_rooms.items():
                    # 使用 .any() 檢查是否有任何一個關鍵字出現在訊息中
                    if any(kw in message_text for kw in room_data["keywords"]):
                        room_data["messages"].append((ts, parsed))

        except Exception as e:
            print(f"❌ 解析失敗：{e}")

    def run(self):
        print(f"🟢 已啟動 Sniffer ({BPF_FILTER})")
        self.sniffer = AsyncSniffer(filter=BPF_FILTER, prn=self._on_packet, store=False)
        self.sniffer.start()
        while self.running:
            if self.buffer:
                self._process_buffer()
            time.sleep(0.1) # 避免 CPU 空轉

    def stop(self):
        self.running = False
        if self.sniffer:
            self.sniffer.stop()

# ======== Flask 路由 ========

@app.route('/')
def index():
    """渲染主頁面"""
    return render_template('index.html')

@app.route('/stream')
def stream():
    """使用 Server-Sent Events (SSE) 推送新訊息"""
    def event_stream():
        # 紀錄每個聊天室已發送的訊息數量，避免重複發送
        sent_counts = {"main": 0}
        
        while True:
            with data_lock:
                # 檢查主聊天室的新訊息
                if len(main_chat_messages) > sent_counts["main"]:
                    new_messages = list(main_chat_messages)[sent_counts["main"]:]
                    for ts, parsed in new_messages:
                        data = {"room": "main", "ts": ts, "message": parsed}
                        yield f"data: {json.dumps(data)}\n\n"
                    sent_counts["main"] = len(main_chat_messages)

                # 檢查關鍵字聊天室的新訊息
                for room_id, room_data in keyword_rooms.items():
                    if room_id not in sent_counts:
                        sent_counts[room_id] = 0
                    if len(room_data["messages"]) > sent_counts[room_id]:
                        new_messages = list(room_data["messages"])[sent_counts[room_id]:]
                        for ts, parsed in new_messages:
                            data = {"room": room_id, "ts": ts, "message": parsed}
                            yield f"data: {json.dumps(data)}\n\n"
                        sent_counts[room_id] = len(room_data["messages"])

            time.sleep(0.5) # 每 0.5 秒檢查一次

    return Response(event_stream(), mimetype='text/event-stream')

@app.route('/add_keyword_room', methods=['POST'])
def add_keyword_room():
    """新增一個關鍵字聊天室"""
    with data_lock:
        # 使用時間戳生成唯一的 room_id
        room_id = f"kw_room_{int(time.time() * 1000)}"
        keyword_rooms[room_id] = {"keywords": set(), "messages": deque(maxlen=MAX_MESSAGES)}
    return jsonify({"success": True, "roomId": room_id})

@app.route('/update_keywords', methods=['POST'])
def update_keywords():
    """更新指定聊天室的關鍵字"""
    data = request.json
    room_id = data.get("roomId")
    keywords_str = data.get("keywords", "").lower()
    
    # 將使用者輸入的字串（用空格、逗號分隔）轉為關鍵字集合
    keywords = set(re.split(r'[\s,]+', keywords_str))
    keywords.discard('') # 去除空字串

    with data_lock:
        if room_id in keyword_rooms:
            keyword_rooms[room_id]["keywords"] = keywords
            print(f"Updated keywords for {room_id}: {keywords}")
            return jsonify({"success": True})
    return jsonify({"success": False, "error": "Room not found"}), 404

# 新增這個路由
@app.route('/delete_keyword_room', methods=['POST'])
def delete_keyword_room():
    """刪除一個關鍵字聊天室"""
    data = request.json
    room_id = data.get("roomId")
    if not room_id:
        return jsonify({"success": False, "error": "Room ID is required"}), 400

    with data_lock:
        if room_id in keyword_rooms:
            del keyword_rooms[room_id]
            print(f"Deleted keyword room: {room_id}")
            return jsonify({"success": True})
        else:
            # 即使找不到也回傳成功，因為前端的目標是讓它消失
            print(f"Attempted to delete a non-existent room: {room_id}")
            return jsonify({"success": True, "message": "Room not found on server, but request is considered successful."})

@app.route('/upload', methods=['POST'])
def upload_file():
    """處理離線檔案上傳"""
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "No selected file"}), 400
    if file:
        try:
            raw_bytes = ChatParser.bytes_from_hex_file(file.stream)
            # 建立一個臨時的 SnifferThread 實例來處理這些 bytes
            temp_processor = SnifferThread()
            temp_processor.buffer = raw_bytes
            temp_processor._process_buffer() # 這會將解析的訊息放入全域佇列中
            return jsonify({"success": True, "message": f"File {file.filename} processed."})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

def start_flask_app():
    if LIVE_CAPTURE:
        sniffer_thread = SnifferThread()
        sniffer_thread.start()
    app.run(host='0.0.0.0', port=5000, threaded=True, use_reloader=False)

if __name__ == '__main__':
    start_flask_app()