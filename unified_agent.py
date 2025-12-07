# unified_agent.py

import sys
import socket
import json
import threading
import time
import requests
import os
import pyperclip
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

# Kütüphaneden gerekli fonksiyonları al (Aynen korunuyor)
from YOUR_DLP_LIB import (
    scan_content, read_file_content, quarantine_file,
    get_usb_mount_points, QUARANTINE_DIR, ALLOWED_EXT,
    MAX_FILE_SIZE
)

# ============================================================
# KONFİGÜRASYON
# ============================================================
SERVER_URL = "http://127.0.0.1:5000"
GATEWAY_IP = "127.0.0.1"
GATEWAY_PORT = 9101
SIM_USB_DIR = "SIM_USB_SURUCU"
STYLE_FILE = "styles.qss"

os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(SIM_USB_DIR, exist_ok=True)


# ============================================================
# YARDIMCI FONKSİYONLAR
# ============================================================
def load_stylesheet():
    """styles.qss dosyasını okur."""
    if os.path.exists(STYLE_FILE):
        try:
            with open(STYLE_FILE, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return ""
    return ""

def post_incident_to_server(user_id, event_type, data_type, action, details):
    payload = {
        "event_type": event_type, 
        "data_type": data_type, 
        "action": action,
        "details": details, 
        "user_id": user_id, 
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
    }
    try: 
        requests.post(f"{SERVER_URL}/log_incident", json=payload, timeout=2)
    except: 
        pass


# ============================================================
# WORKER THREADS (LOGIC)
# ============================================================
class ClipboardWorker(QThread):
    signal_incident = pyqtSignal(str)

    def __init__(self, vm_id, policy):
        super().__init__()
        self.vm_id = vm_id
        self.policy = policy
        self.running = True

    def update_policy(self, new_policy):
        self.policy = new_policy

    def run(self):
        last_content = ""
        while self.running:
            try:
                clip_policy = self.policy.get("clipboard", {})
                if not clip_policy:
                    time.sleep(2)
                    continue

                content = pyperclip.paste() or ""
                if content != last_content and content:
                    keywords = clip_policy.get("Keywords", [])
                    incidents = scan_content(str(content), keywords)
                    blocked = []
                    match_txt = ""

                    for inc in incidents:
                        dt = inc["data_type"]
                        if dt == "KEYWORD_MATCH" and keywords:
                            blocked.append("ANAHTAR_KELİME")
                        if clip_policy.get(dt, False):
                            blocked.append(dt)
                            match_txt = inc.get("masked_match", "")

                    if blocked:
                        typ = ", ".join(set(blocked))
                        clean = f"🚫 [DLP ENGELİ] {typ} tespit edildi."
                        pyperclip.copy(clean)
                        last_content = clean
                        post_incident_to_server(self.vm_id, "Pano", typ, "ENGEL", match_txt)
                        self.signal_incident.emit(f"📋 PANO ENGELİ: {typ}")
                    else:
                        last_content = content
                time.sleep(1)
            except:
                time.sleep(1)

    def stop(self):
        self.running = False
        self.wait()


class USBWorker(QThread):
    signal_incident = pyqtSignal(str)

    def __init__(self, vm_id, policy):
        super().__init__()
        self.vm_id = vm_id
        self.policy = policy
        self.running = True
        self.observers = {}
        self.known_mounts = set()

    def update_policy(self, new_policy):
        self.policy = new_policy

    def run(self):
        if os.path.exists(SIM_USB_DIR):
            self.start_obs(SIM_USB_DIR)
            self.known_mounts.add(SIM_USB_DIR)

        while self.running:
            try:
                curr = set(get_usb_mount_points(SIM_USB_DIR))
                
                # Yeni Takılanlar
                for m in (curr - self.known_mounts):
                    self.start_obs(m)
                    self.known_mounts.add(m)
                    self.signal_incident.emit(f"🔌 USB Takıldı: {m}")

                # Çıkarılanlar
                for m in (self.known_mounts - curr):
                    self.stop_obs(m)
                    self.known_mounts.discard(m)
                    self.signal_incident.emit(f"🔌 USB Çıkarıldı: {m}")

                time.sleep(2)
            except:
                time.sleep(2)

    def start_obs(self, path):
        if path in self.observers: return
        h = USBHandler(self.vm_id, self.policy, self.signal_incident)
        o = Observer()
        o.schedule(h, path, recursive=True)
        o.start()
        self.observers[path] = (o, h)
        self.scan_existing(path, h)

    def stop_obs(self, path):
        if path in self.observers:
            self.observers[path][0].stop()
            self.observers[path][0].join()
            del self.observers[path]

    def scan_existing(self, path, h):
        for r, _, f in os.walk(path):
            for fi in f:
                h.process(os.path.join(r, fi))

    def stop(self):
        self.running = False
        for p in list(self.observers.keys()):
            self.stop_obs(p)
        self.wait()


class USBHandler(FileSystemEventHandler):
    def __init__(self, vm_id, policy, signal):
        self.vm_id = vm_id
        self.policy = policy
        self.signal = signal

    def process(self, path):
        p = self.policy.get("usb", {})
        if not p: return
        try:
            if not os.path.isfile(path): return
            name = os.path.basename(path)
            if name.startswith(".") or name.startswith("~$"): return
            if os.path.splitext(name)[1].lower() not in ALLOWED_EXT: return

            content = read_file_content(path)
            if not content: return

            kws = p.get("Keywords", [])
            incs = scan_content(content, kws)
            blocked = []

            for i in incs:
                dt = i["data_type"]
                if dt == "KEYWORD_MATCH" and kws:
                    blocked.append("ANAHTAR_KELİME")
                if p.get(dt, False):
                    blocked.append(dt)

            if blocked:
                typ = ", ".join(set(blocked))
                quarantine_file(path)
                post_incident_to_server(self.vm_id, "USB Transfer", typ, "ENGEL", f"{name} -> Karantina")
                self.signal.emit(f"💾 USB ENGELİ: {name} ({typ}) -> Karantinaya alındı.")
        except:
            pass

    def on_created(self, e):
        if not e.is_directory:
            time.sleep(0.5)
            self.process(e.src_path)

    def on_modified(self, e):
        if not e.is_directory:
            time.sleep(0.5)
            self.process(e.src_path)


# ============================================================
# CORE ENGINE (NETWORK GÜNCELLEMESİ)
# ============================================================
class UnifiedAgentCore(QObject):
    # (Mesaj, Benim_Mesajim_Mi, Hata_Var_Mi)
    sig_chat_msg = pyqtSignal(str, bool, bool) 
    sig_dlp_log = pyqtSignal(str)
    sig_net_status = pyqtSignal(bool)

    def __init__(self, vm_id):
        super().__init__()
        self.vm_id = vm_id
        self.sock = None
        self.running = True
        self.policy = {}

        self.refresh_policy()
        
        self.clip = ClipboardWorker(vm_id, self.policy)
        self.clip.signal_incident.connect(self.sig_dlp_log.emit)
        self.clip.start()

        self.usb = USBWorker(vm_id, self.policy)
        self.usb.signal_incident.connect(self.sig_dlp_log.emit)
        self.usb.start()

        self.net = threading.Thread(target=self.net_loop, daemon=True)
        self.net.start()

    def refresh_policy(self):
        try:
            r = requests.get(f"{SERVER_URL}/policies/{self.vm_id}", timeout=2)
            if r.status_code == 200:
                self.policy = r.json()
                self.clip.update_policy(self.policy)
                self.usb.update_policy(self.policy)
        except:
            pass

    def connect(self):
        if self.sock:
            self.sock.close()
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((GATEWAY_IP, GATEWAY_PORT))
            self.sock.sendall(f"HELLO:{self.vm_id}\n".encode("utf-8"))
            f = self.sock.makefile("r", encoding="utf-8")
            
            # Sunucudan WELCOME bekliyoruz
            resp = f.readline()
            if "WELCOME" in resp:
                self.sig_net_status.emit(True)
                return f
            else:
                return None
        except:
            self.sock = None
            self.sig_net_status.emit(False)
            return None

    def net_loop(self):
        f = None
        while self.running:
            if not self.sock:
                f = self.connect()
                if not f:
                    time.sleep(3)
                    continue
            try:
                line = f.readline()
                if not line: raise Exception
                raw = line.strip()

                # 1. Başka kullanıcıdan normal mesaj geldi
                # Format: MSG:gonderen:icerik
                if raw.startswith("MSG:"):
                    parts = raw.split(":", 2)
                    sender = parts[1]
                    content = parts[2]
                    self.sig_chat_msg.emit(f"<b>{sender}:</b> {content}", False, False)

                # 2. Server benim mesajımı onayladı (ACK)
                # Format: ACK:alici:icerik
                elif raw.startswith("ACK:"):
                    parts = raw.split(":", 2)
                    target = parts[1]
                    content = parts[2]
                    # true, true -> Benim mesajım, Hata yok
                    self.sig_chat_msg.emit(f"<b>BEN -> {target}:</b> {content}", True, False)

                # 3. Server mesajımı engelledi veya hata döndü (ERR)
                # Format: ERR:alici:hata_kodu
                elif raw.startswith("ERR:"):
                    parts = raw.split(":", 2)
                    target = parts[1]
                    err_code = parts[2]
                    
                    if "BLOCKED" in err_code:
                        reason = err_code.split(":")[1] if ":" in err_code else "Yasaklı İçerik"
                        error_msg = f"🚫 <b>İLETİLEMEDİ ({target}):</b> Mesajınız '{reason}' sebebiyle engellendi."
                        self.sig_chat_msg.emit(error_msg, True, True) # True, True -> Benim mesajım, Hata VAR
                        self.sig_dlp_log.emit(f"Ağ Engeli: {target}'a gönderim '{reason}' nedeniyle bloklandı.")
                    
                    elif "OFFLINE" in err_code:
                        self.sig_chat_msg.emit(f"⚠️ <b>HATA:</b> {target} çevrimdışı.", True, True)
                    
                    else:
                        self.sig_chat_msg.emit(f"⚠️ <b>HATA:</b> Gönderim başarısız.", True, True)

                # Eski format desteği (ne olur ne olmaz)
                elif raw.startswith("[DLP]"):
                    self.sig_dlp_log.emit(raw)
                    
            except:
                self.sock = None
                self.sig_net_status.emit(False)
                time.sleep(3)

    def send(self, target, msg):
        if not self.sock:
            self.sig_dlp_log.emit("⚠️ Mesaj gönderilemedi: Gateway kapalı.")
            return
        try:
            # Sadece gönderiyoruz, ekrana basmıyoruz. Ekrana basma işi ACK gelince olacak.
            self.sock.sendall((json.dumps({"dst": target, "channel": "chat", "payload": msg}) + "\n").encode("utf-8"))
        except:
            self.sock = None
            self.sig_dlp_log.emit("⚠️ Gönderim hatası.")

    def stop(self):
        self.running = False
        self.clip.stop()
        self.usb.stop()
        if self.sock:
            self.sock.close()


# ============================================================
# GUI CLASSES
# ============================================================
class PolicyViewerDialog(QDialog):
    def __init__(self, policy_data):
        super().__init__()
        self.setWindowTitle("Güvenlik Politikası Detayları")
        self.setMinimumSize(700, 500)

        layout = QVBoxLayout()
        header = QFrame()
        hl = QHBoxLayout(header)
        hl.addWidget(QLabel("🛡️ <b>Aktif DLP Kuralları</b>"))
        hl.addStretch()
        layout.addWidget(header)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_table(policy_data.get("clipboard", {})), "📋 Pano")
        self.tabs.addTab(self.create_table(policy_data.get("usb", {})), "💾 USB")
        self.tabs.addTab(self.create_network_tree(policy_data.get("network", {})), "🌐 Ağ")
        layout.addWidget(self.tabs)

        btn = QPushButton("Kapat")
        btn.clicked.connect(self.close)
        btn.setStyleSheet("background-color: #666;")
        layout.addWidget(btn)
        self.setLayout(layout)

    def create_table(self, rules):
        t = QTableWidget()
        t.setColumnCount(2)
        t.setHorizontalHeaderLabels(["Veri Tipi", "Durum"])
        t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        t.verticalHeader().setVisible(False)
        r = 0
        for k, v in rules.items():
            t.insertRow(r)
            t.setItem(r, 0, QTableWidgetItem(k))
            if k == "Keywords":
                it = QTableWidgetItem(", ".join(v) if v else "-")
                it.setForeground(QColor("blue"))
            else:
                it = QTableWidgetItem("⛔ YASAK" if v else "✅ İZİN")
                it.setBackground(QColor("#ffcdd2" if v else "#c8e6c9"))
                it.setForeground(QColor("#b71c1c" if v else "#1b5e20"))
                it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            t.setItem(r, 1, it)
            r += 1
        return t

    def create_network_tree(self, net):
        t = QTreeWidget()
        t.setHeaderLabels(["Hedef / Kural", "Durum"])
        t.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for user, rules in net.items():
            root = QTreeWidgetItem(t)
            root.setText(0, f"👤 {user}")
            root.setBackground(0, QColor("#e3f2fd"))
            root.setExpanded(True)
            for k, v in rules.items():
                ch = QTreeWidgetItem(root)
                ch.setText(0, k)
                if k == "Keywords":
                    ch.setText(1, ", ".join(v) if v else "-")
                    ch.setForeground(1, QColor("blue"))
                else:
                    ch.setText(1, "⛔ YASAK" if v else "✅ İZİN")
                    ch.setForeground(1, QColor("red" if v else "green"))
        return t

def get_registered_users():
    """ Sunucudan kayıtlı kullanıcı listesini çeker. """
    try:
        r = requests.get(f"{SERVER_URL}/users", timeout=2)
        if r.status_code == 200:
            return r.json().get("users", [])
    except:
        pass
    return []


class UnifiedWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DLP Unified Agent - Enterprise Edition")
        self.setMinimumSize(1000, 750)

        # --- KULLANICI ADI KONTROL DÖNGÜSÜ ---
        valid_users = get_registered_users()
        self.vm_id = None

        while not self.vm_id:
            # Kullanıcıdan VM ID'sini iste
            vm_id, ok = QInputDialog.getText(self, "Giriş", "VM ID Giriniz (örn: vm_user_1):")
            
            # 1. Çıkış / İptal Kontrolü
            if not ok: 
                sys.exit()

            # 2. Geçerli Kullanıcı Kontrolü
            vm_id = vm_id.strip()
            # Sunucu kapalıysa veya liste boşsa her türlü girişe izin ver (Test amaçlı)
            if not valid_users:
                if vm_id: self.vm_id = vm_id
            else:
                if vm_id in valid_users:
                    self.vm_id = vm_id 
                elif not vm_id:
                    QMessageBox.critical(self, "Hata", "Kullanıcı adı boş bırakılamaz.")
                else:
                    QMessageBox.critical(self, "Hata", f"'{vm_id}' kaydedilmemiş bir kullanıcı adıdır.")

        self.core = UnifiedAgentCore(self.vm_id)
        self.core.sig_chat_msg.connect(self.on_chat_msg)
        self.core.sig_dlp_log.connect(self.on_dlp_log)
        self.core.sig_net_status.connect(self.on_net_status)

        main = QVBoxLayout()
        main.setContentsMargins(15, 15, 15, 15)
        main.setSpacing(15)

        main.addWidget(self.build_fancy_header())

        self.tabs = QTabWidget()
        self.tabs.addTab(self.build_chat_tab(), "💬 Güvenli Sohbet")
        self.tabs.addTab(self.build_log_tab(), "🛡️ DLP Olay Günlüğü")
        main.addWidget(self.tabs)
        self.setLayout(main)

        self.timer = QTimer()
        self.timer.timeout.connect(self.core.refresh_policy)
        self.timer.start(10000)

        self.on_dlp_log("✅ Sistem Başlatıldı. Koruma Aktif.")
        self.on_dlp_log(f"👤 Kullanıcı: {self.vm_id}")

    def build_fancy_header(self):
        f = QFrame()
        l = QHBoxLayout(f)
        l.setContentsMargins(20, 15, 20, 15)

        info = QVBoxLayout()
        lbl = QLabel(f"👤 <b>{self.vm_id}</b>")
        lbl.setStyleSheet("font-size: 18px; color: #333;")
        self.lbl_status = QLabel("Gateway: Bağlanıyor...")
        self.lbl_status.setStyleSheet("color: orange; font-weight: bold;")
        info.addWidget(lbl)
        info.addWidget(self.lbl_status)
        l.addLayout(info)

        l.addStretch()

        btn = QPushButton("🛡️ Politikaları Görüntüle")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet("background-color: #2e7d32; padding: 10px 20px; font-size: 14px;")
        btn.clicked.connect(lambda: PolicyViewerDialog(self.core.policy).exec())
        l.addWidget(btn)

        return f

    def build_chat_tab(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(10)

        tf = QFrame()
        hl = QHBoxLayout(tf)
        hl.addWidget(QLabel("<b>Kime Gönderilecek:</b>"))
        self.cmb_target = QComboBox()
        self.cmb_target.setMinimumWidth(200)
        self.load_users()
        hl.addWidget(self.cmb_target)
        hl.addStretch()
        l.addWidget(tf)

        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        self.chat_area.setStyleSheet(
            "background-color: white; border: 1px solid #ddd; border-radius: 8px; padding: 10px; font-size: 14px;"
        )
        l.addWidget(self.chat_area)

        bl = QHBoxLayout()
        self.txt_msg = QLineEdit()
        self.txt_msg.setPlaceholderText("Güvenli mesajınızı buraya yazın...")
        self.txt_msg.setStyleSheet(
            "padding: 12px; font-size: 14px; border: 1px solid #ccc; border-radius: 20px;"
        )
        self.txt_msg.returnPressed.connect(self.send_message)

        btn = QPushButton("Gönder ➤")
        btn.setStyleSheet(
            "QPushButton { background-color: #0078d7; border-radius: 20px; padding: 10px 20px; font-size: 14px; } QPushButton:hover { background-color: #005a9e; }"
        )
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(self.send_message)

        bl.addWidget(self.txt_msg)
        bl.addWidget(btn)
        l.addLayout(bl)
        return w

    def build_log_tab(self):
        w = QWidget()
        l = QVBoxLayout(w)

        h = QHBoxLayout()
        h.addWidget(QLabel("<b>Gerçek Zamanlı İhlal ve Sistem Kayıtları</b>"))
        h.addStretch()
        btn = QPushButton("🧹 Temizle")
        btn.setStyleSheet("background-color: #757575; font-size: 12px; padding: 5px 10px;")
        btn.clicked.connect(lambda: self.log_box.clear())
        h.addWidget(btn)
        l.addLayout(h)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setStyleSheet(
            "background-color: #1e1e1e; color: #00ff00; font-family: 'Consolas', 'Courier New', monospace; font-size: 13px; border-radius: 6px; padding: 10px;"
        )
        l.addWidget(self.log_box)
        return w

    def send_message(self):
        msg = self.txt_msg.text().strip()
        if not msg: return
        self.core.send(self.cmb_target.currentText(), msg)
        self.txt_msg.clear()

    def load_users(self):
        try:
            r = requests.get(f"{SERVER_URL}/users", timeout=1)
            u = r.json().get("users", [])
            c = self.cmb_target.currentText()
            self.cmb_target.clear()
            self.cmb_target.addItems([x for x in u if x != self.vm_id])
            if c: self.cmb_target.setCurrentText(c)
        except:
            pass

    def on_chat_msg(self, msg, is_mine, is_error):
        # YENİ ÖZELLİK: Hata durumunda kırmızı kutu
        if is_error:
             self.chat_area.append(
                f"<div style='text-align: center; margin: 5px;'><span style='background-color: #ffebee; border: 1px solid #ffcdd2; color: #c62828; padding: 8px 12px; font-size: 14px; font-weight: bold;'>{msg}</span></div>"
            )
        else:
            style = "background-color: #DCF8C6; border-radius: 15px 15px 0 15px;" if is_mine else "background-color: #E5E5EA; border-radius: 15px 15px 15px 0;"
            align = "right" if is_mine else "left"
            self.chat_area.append(
                f"<div style='text-align: {align}; margin: 5px;'><span style='{style} color: black; padding: 8px 12px; font-size: 14px;'>{msg}</span></div>"
            )
        
        sb = self.chat_area.verticalScrollBar()
        sb.setValue(sb.maximum())

    def on_dlp_log(self, msg):
        ts = time.strftime("[%H:%M:%S]")
        if "ENGEL" in msg or "HATA" in msg:
            color = "#ff5252"
            icon = "❌"
        elif "Takıldı" in msg or "Çıkarıldı" in msg:
            color = "#ffff00"
            icon = "⚠️"
        else:
            color = "#69f0ae"
            icon = "ℹ️"
        self.log_box.append(f"<span style='color:{color}'>{ts} {icon} {msg}</span>")

    def on_net_status(self, c):
        self.lbl_status.setText("Gateway: ✔ ÇEVRİMİÇİ" if c else "Gateway: ✖ BAĞLANTI YOK")
        self.lbl_status.setStyleSheet(f"color: {'#2e7d32' if c else '#d32f2f'}; font-weight: bold;")

    def closeEvent(self, e):
        self.core.stop()
        e.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    # Stili dosyadan yükle
    app.setStyleSheet(load_stylesheet())
    win = UnifiedWindow()
    win.show()
    sys.exit(app.exec())