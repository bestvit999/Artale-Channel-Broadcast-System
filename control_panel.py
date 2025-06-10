import tkinter as tk
from tkinter import ttk, messagebox
import multiprocessing
import time
import webbrowser
import sys
import os

# --- 導入您原有的應用邏輯 ---
# 假設您的 Flask 應用和 WebSocket 服務可以像這樣導入並啟動
# 確保這些檔案中的啟動邏輯被包裝在函數內
from app import start_flask_app  # 假設 app.py 有一個 run_flask_app() 函數
from main_chat_ws import start_websocket_server # 假設 ws 腳本有這個函數

# --- 定義行程任務 ---
def run_flask_process():
    """運行 Flask 應用的行程目標函數"""
    print("Flask 伺服器啟動中...")
    start_flask_app()

def run_ws_process():
    """運行 WebSocket 服務的行程目標函數"""
    print("WebSocket 伺服器啟動中...")
    start_websocket_server()

# --- Tkinter 控制面板應用 ---
class ControlPanel(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ArtaleChat 控制面板")
        self.geometry("350x200")
        self.resizable(False, False)

        self.processes = []  # 用來存放子行程
        self.service_running = False

        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.on_closing) # 攔截關閉視窗事件

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 狀態標籤
        self.status_label = ttk.Label(main_frame, text="服務狀態：已停止", font=("Microsoft JhengHei", 12))
        self.status_label.pack(pady=(0, 10))

        # 啟動按鈕
        self.start_button = ttk.Button(main_frame, text="🚀 啟動服務", command=self.start_services)
        self.start_button.pack(fill=tk.X, pady=5)

        # 關閉按鈕
        self.stop_button = ttk.Button(main_frame, text="🛑 關閉服務", command=self.stop_services, state=tk.DISABLED)
        self.stop_button.pack(fill=tk.X, pady=5)

    def start_services(self):
        if self.service_running:
            messagebox.showinfo("提示", "服務已經在運行中！")
            return

        print("正在啟動服務...")
        try:
            # 建立並啟動子行程
            flask_p = multiprocessing.Process(target=run_flask_process, daemon=True)
            ws_p = multiprocessing.Process(target=run_ws_process, daemon=True)
            
            self.processes = [flask_p, ws_p]
            
            for p in self.processes:
                p.start()
            
            self.service_running = True
            self.update_ui_state()

            # 等待一小段時間後自動打開瀏覽器
            self.after(3000, self.open_browser)

        except Exception as e:
            messagebox.showerror("啟動失敗", f"無法啟動服務：\n{e}")
            self.service_running = False
            self.update_ui_state()

    def stop_services(self):
        if not self.service_running:
            return

        print("正在停止服務...")
        for p in self.processes:
            if p.is_alive():
                p.terminate() # 強制終止
                p.join()      # 等待行程結束
        
        self.processes = []
        self.service_running = False
        self.update_ui_state()
        print("服務已停止。")

    def update_ui_state(self):
        if self.service_running:
            self.status_label.config(text="服務狀態：運行中", foreground="green")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
        else:
            self.status_label.config(text="服務狀態：已停止", foreground="red")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def open_browser(self):
        webbrowser.open("http://127.0.0.1:5000")

    def on_closing(self):
        if self.service_running:
            if messagebox.askyesno("確認", "服務仍在運行中，確定要關閉嗎？"):
                self.stop_services()
                self.destroy()
        else:
            self.destroy()

# --- 主啟動邏輯 ---
if __name__ == '__main__':
    # 針對 PyInstaller 和 Windows 的 multiprocessing
    multiprocessing.freeze_support()
    
    # 確保在打包後的環境也能找到 Scapy 的 npcap
    # 這段在某些 Windows 環境下是必要的
    if sys.platform == 'win32':
        os.environ['PATH'] = f"{sys._MEIPASS};{os.environ['PATH']}" if getattr(sys, 'frozen', False) else os.environ['PATH']

    app = ControlPanel()
    app.mainloop()