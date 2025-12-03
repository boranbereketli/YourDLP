import sys
import socket
import json
import threading
import requests
import time
from queue import Queue
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

SERVER = "http://127.0.0.1:5000"
GATEWAY_IP = "127.0.0.1"
GATEWAY_PORT = 9101


# ============================================================
#  DLP AGENT CORE
# ============================================================
class DlpAgentCore(QObject):
    signal_msg_received = pyqtSignal(str)
    signal_dlp_event = pyqtSignal(str)
    signal_gateway_lost = pyqtSignal()
    signal_gateway_ok = pyqtSignal()

    def __init__(self, vm_id):
        super().__init__()
        self.vm_id = vm_id
        self.sock = None
        self.file_obj = None # Soket okuma nesnesi
        self.running = True

        self.thread = threading.Thread(target=self.run_agent, daemon=True)
        self.thread.start()

    # ---------------------------------------------------------
    # Bağlantı Kur
    # ---------------------------------------------------------
    def connect_to_gateway(self):
        self.close_connection()
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((GATEWAY_IP, GATEWAY_PORT))
            
            # İlk mesajı "HELLO:<VM_ID>" olarak gönder
            self.sock.sendall(f"HELLO:{self.vm_id}\n".encode("utf-8"))
            
            # Sunucunun ilk yanıtını oku (örn: "Hoş Geldin...")
            self.file_obj = self.sock.makefile("r", encoding="utf-8")
            self.file_obj.readline() # İlk karşılama mesajını tüket
            
            self.signal_gateway_ok.emit()
            return True
        except Exception:
            self.signal_gateway_lost.emit()
            self.close_connection()
            return False

    def close_connection(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None
        self.file_obj = None
    
    # ---------------------------------------------------------
    # Ajanın ana döngüsü (Bağlantı kesilirse yeniden bağlanır)
    # ---------------------------------------------------------
    def run_agent(self):
        while self.running:
            if not self.sock:
                time.sleep(1)
                if not self.connect_to_gateway():
                    continue

            try:
                line = self.file_obj.readline()
                if not line:
                    break # Bağlantı kesildi

                message = line.strip()
                if message:
                    self.process_message(message)

            except Exception:
                break # Okuma hatası

            # Bağlantı kesildiğinde/hata oluştuğunda bu noktaya gelinir, yeniden bağlanmaya çalışılır
            self.signal_gateway_lost.emit()
            self.close_connection()
            time.sleep(3)


    # ---------------------------------------------------------
    # Gelen mesajı işleme (server.py'nin gönderdiği formata göre: "[GÖNDEREN]: İÇERİK")
    # ---------------------------------------------------------
    def process_message(self, message):
        
        if message.startswith("[DLP]"):
            # DLP Engelleme Mesajı
            self.signal_dlp_event.emit(message)
        
        elif message.startswith("["):
            # Normal Chat Mesajı
            self.signal_msg_received.emit(message)


    # ---------------------------------------------------------
    # Mesaj gönderme (vm_agent.py'deki Message formatına göre)
    # ---------------------------------------------------------
    def send_chat(self, target_vm, text):
        if not self.sock:
            self.signal_dlp_event.emit("[DLP] Gateway bağlı değil. Mesaj gönderilemedi.")
            return

        payload = {
            "dst": target_vm,
            "channel": "chat", 
            "payload": text
        }

        try:
            # JSON + yeni satır formatında gönder
            self.sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        except Exception:
            self.signal_gateway_lost.emit()
            self.close_connection()
            self.signal_dlp_event.emit("[DLP] Gönderme hatası. Gateway bağlantısı kesildi.")

# ============================================================
#  AGENT GUI
# ============================================================
class AgentWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("VM Agent Control Panel")
        self.setMinimumSize(950, 700)

        # VM ID input
        vm_id, ok = QInputDialog.getText(self, "VM ID", "VM ID gir (örn: vm_user_1):")
        if not ok or vm_id.strip() == "":
            sys.exit()
        self.vm_id = vm_id.strip()

        # Agent Core
        self.agent = DlpAgentCore(self.vm_id)
        self.agent.signal_msg_received.connect(self.on_msg_received)
        self.agent.signal_dlp_event.connect(self.on_dlp_event)
        self.agent.signal_gateway_ok.connect(self.on_gateway_ok)
        self.agent.signal_gateway_lost.connect(self.on_gateway_lost)

        # Header
        header = self.build_header()

        # Tabs
        self.tabs = QTabWidget()
        self.chat_tab = self.build_chat_tab()
        self.log_tab = self.build_log_tab()

        self.tabs.addTab(self.chat_tab, "Chat")
        self.tabs.addTab(self.log_tab, "DLP Logs")

        main = QVBoxLayout()
        main.addLayout(header)
        main.addWidget(self.tabs)
        self.setLayout(main)

        # Log timer
        self.timer_logs = QTimer()
        self.timer_logs.timeout.connect(self.refresh_logs)
        self.timer_logs.start(3000)

        self.chat_log.append(f"[SİSTEM] VM Agent başlatıldı: {self.vm_id}")

    # ======================================================
    # HEADER
    # ======================================================
    def build_header(self):
        header = QHBoxLayout()

        header.addWidget(QLabel(f"VM ID: {self.vm_id}"))

        self.lbl_gateway = QLabel("Gateway: ?")
        self.lbl_gateway.setStyleSheet("color: gray; font-weight: bold;")
        header.addWidget(self.lbl_gateway)

        btn = QPushButton("Aktif Politikayı Göster")
        btn.clicked.connect(self.show_policy)
        header.addWidget(btn)

        header.addWidget(QLabel("Hedef VM:"))
        self.target_select = QComboBox()
        header.addWidget(self.target_select)

        # ---- Server'dan kullanıcı listesini çek ----
        self.load_users()

        header.addStretch()
        return header

    # ======================================================
    # SERVER → Kullanıcı listesi yükle
    # ======================================================
    # ======================================================
    # SERVER → Kullanıcı listesi yükle
    # ======================================================
    def load_users(self):
        """ Sunucudan (server.py) kayıtlı kullanıcı listesini çeker ve dropdown menüye yükler. """
        try:
            r = requests.get(f"{SERVER}/users", timeout=3) # Timeout eklendi
            
            if r.status_code != 200:
                 # Bağlantı kuruldu ama sunucudan geçersiz yanıt geldi
                QMessageBox.critical(self, "Hata", 
                                     f"Kullanıcı listesi alınamadı. Sunucu HTTP Kodu: {r.status_code}")
                return

            data = r.json()
            users = data.get("users", [])
            
            # Kendi VM ID'mizi listeden çıkaralım
            users = [u for u in users if u != self.vm_id] 

            self.target_select.clear()
            self.target_select.addItems(users)

            if not users:
                QMessageBox.warning(self, "Uyarı", 
                                    f"Hedef kullanıcı listesi boş. Lütfen 'main_window.py' (Policy Manager) üzerinden yeni kullanıcılar ekleyin.")

        except requests.exceptions.ConnectionError:
            # KRİTİK HATA: Sunucuya hiç bağlanılamadı
            self.on_gateway_lost() # Gateway bağlantısını kırmızıya çevir
            QMessageBox.critical(self, "Hata", 
                                 f"Sunucuya bağlanılamadı ({SERVER}). Lütfen **server.py**'nin çalıştığından emin olun.")
        except Exception as e:
            # Diğer tüm hatalar (JSON çözümleme vb.)
            QMessageBox.critical(self, "Hata", 
                                 f"Kullanıcı listesi alınırken beklenmeyen hata oluştu: {type(e).__name__}: {e}")

    # ======================================================
    # CHAT TAB
    # ======================================================
    def build_chat_tab(self):
        w = QWidget()
        l = QVBoxLayout()

        self.chat_log = QTextEdit()
        self.chat_log.setReadOnly(True)
        l.addWidget(self.chat_log)

        self.msg_input = QLineEdit()
        self.msg_input.setPlaceholderText("Mesaj yaz…")
        l.addWidget(self.msg_input)

        btn = QPushButton("Gönder")
        btn.clicked.connect(self.send_msg)
        l.addWidget(btn)

        w.setLayout(l)
        return w

    # ======================================================
    # LOG TAB
    # ======================================================
    def build_log_tab(self):
        w = QWidget()
        l = QVBoxLayout()

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        l.addWidget(self.log_box)

        btn = QPushButton("Yenile")
        btn.clicked.connect(self.refresh_logs)
        l.addWidget(btn)

        w.setLayout(l)
        return w

    # ======================================================
    # CHAT EVENT
    # ======================================================
    def on_msg_received(self, msg):
        self.chat_log.append(msg)

    # ======================================================
    # DLP EVENT
    # ======================================================
    def on_dlp_event(self, event):
        self.log_box.append(event)

    # ======================================================
    # Gateway OK
    # ======================================================
    def on_gateway_ok(self):
        self.lbl_gateway.setText("Gateway: ✔ Bağlı")
        self.lbl_gateway.setStyleSheet("color: green; font-weight: bold;")

    # ======================================================
    # Gateway Lost
    # ======================================================
    def on_gateway_lost(self):
        self.lbl_gateway.setText("Gateway: ✖ Kapalı")
        self.lbl_gateway.setStyleSheet("color: red; font-weight: bold;")

    # ======================================================
    # MESAJ GÖNDER
    # ======================================================
    def send_msg(self):
        msg = self.msg_input.text().strip()
        if not msg:
            return

        target = self.target_select.currentText()
        self.agent.send_chat(target, msg)

        self.chat_log.append(f"[{self.vm_id} -> {target}] {msg}")
        self.msg_input.clear()

    # ======================================================
    # POLICY POPUP
    # ======================================================
    def show_policy(self):
        try:
            r = requests.get(f"{SERVER}/policies/{self.vm_id}")
            policy = json.dumps(r.json(), indent=4)
        except:
            QMessageBox.critical(self, "Hata", "Policy alınamadı.")
            return

        QMessageBox.information(self, "Aktif Politika", policy)

    # ======================================================
    # LOG AL
    # ======================================================

    def refresh_logs(self):
        if not self.agent.sock: # Gateway bağlı değilse log çekmeyi deneme
            return

        try:
            # Sadece benim ID'me ait logları iste
            r = requests.get(f"{SERVER}/logs/{self.vm_id}", timeout=2)
            
            if r.status_code == 200:
                logs = r.json().get("logs", [])
                
                # Eğer yeni log yoksa veya liste aynıysa ekranı titretme (opsiyonel optimizasyon)
                # Ama basitlik için temizleyip yeniden yazıyoruz:
                self.log_box.clear()
                
                if not logs:
                    self.log_box.append("<i>Henüz bu cihaza ait bir ihlal kaydı yok.</i>")
                else:
                    for line in logs:
                        # CSV satırını biraz daha okunaklı hale getirelim
                        parts = line.split(',')
                        if len(parts) >= 5:
                            # Tarih | Olay | Durum | Detay
                            formatted_line = f"<b>[{parts[0]}]</b> {parts[1]} - {parts[3]}: {parts[4]}"
                            self.log_box.append(formatted_line)
                        else:
                            self.log_box.append(line)
        except Exception:
            # Sessizce geç, bağlantı hatası vs. kullanıcıyı sürekli rahatsız etmesin
            pass


# ============================================================
# UYGULAMA BAŞLAT
# ============================================================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = AgentWindow()
    win.show()
    sys.exit(app.exec())
