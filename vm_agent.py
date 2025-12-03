# vm_agent.py

import requests
import threading
import time
import os
import shutil
import pyperclip
import socket
import json
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# DLP Kütüphanesini içe aktar
from YOUR_DLP_LIB import (
    scan_content, read_file_content, quarantine_file, 
    get_usb_mount_points, QUARANTINE_DIR, ALLOWED_EXT,
    MAX_FILE_SIZE, Message
)


# ============================================================
# İSTEMCİ KONFİGÜRASYON
# ============================================================
# TEST AMAÇLI ID VE SERVER AYARLARI
## VM_ID = "vm_user_1" # Test için varsayılan olarak vm_user_1 kullanıldı
SERVER_IP_ADDRESS = "127.0.0.1" # Kendi bilgisayarınızın yerel adresi
SERVER_REST_URL = f"http://{SERVER_IP_ADDRESS}:5000"
SIM_USB_DIR = "SIM_USB_SURUCU"
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(SIM_USB_DIR, exist_ok=True)

SENDER_GATEWAY_HOST = SERVER_IP_ADDRESS
SENDER_GATEWAY_PORT = 9101

# Global Durum
active_policies = {} 
gateway_connection = None 

# ============================================================
# İSTEMCİ / SUNUCU İLETİŞİMİ
# ============================================================

def post_incident_log(event_type, data_type, action, details):
    """ İhlal durumunda logu DLP sunucusuna POST eder """
    log_data = {
        "event_type": event_type,
        "data_type": data_type,
        "action": action,
        "details": details,
        "user_id": VM_ID, 
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
    }
    try:
        response = requests.post(f"{SERVER_REST_URL}/log_incident", json=log_data, timeout=3)
        if response.status_code != 200:
            print(f"[AGENT LOG ERROR] Sunucu hatası ({response.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"[AGENT LOG ERROR] Sunucuya bağlanılamadı: {e}")


def get_dlp_policies():
    """ Sunucudan bu kullanıcı için detaylı DLP politikalarını çeker """
    global active_policies
    try:
        response = requests.get(f"{SERVER_REST_URL}/policies/{VM_ID}", timeout=3)
        if response.status_code == 200:
            active_policies = response.json()
            return active_policies
    except requests.exceptions.RequestException:
        print("[POLICY ERROR] Sunucuya bağlanılamadı. Kısıtlayıcı varsayılanlar kullanılıyor.")
    
    # Varsayılan politika (Sunucuya ulaşılamazsa her şeyi yasakla)
    default_restrictions = {d: True for d in ["TCKN", "TEL_NO", "IBAN_TR", "KREDI_KARTI", "E_POSTA"]}
    active_policies = {"clipboard": default_restrictions.copy(), "usb": default_restrictions.copy(), "network": default_restrictions.copy()}
    return active_policies

# ============================================================
# USB HANDLER & MONITOR 
# ============================================================

class USBFileHandler(FileSystemEventHandler):
    def _process_file(self, file_path):
        usb_policy = active_policies.get("usb")
        if not usb_policy: return

        try:
            if not os.path.isfile(file_path): return
            name = os.path.basename(file_path)
            if name.startswith(".") or name.startswith("~$"): return
            
            try: size = os.path.getsize(file_path)
            except Exception: size = 0
            if size == 0 or size > MAX_FILE_SIZE: return

            ext = os.path.splitext(name)[1].lower()
            content = read_file_content(file_path) if ext in ALLOWED_EXT else ""

            # Dinamik Anahtar Kelimeleri Çek
            dynamic_keywords = usb_policy.get("Keywords", []) 
            incidents = scan_content(content, dynamic_keywords) if content else []
  
            blocked_data_types = []
            
            for incident in incidents:
                data_type = incident["data_type"]
                # Anahtar Kelime Kontrolü
                if data_type == "KEYWORD_MATCH":
                    if dynamic_keywords:
                        blocked_data_types.append("ANAHTAR_KELİME")
                if usb_policy.get(data_type, False):
                    blocked_data_types.append(data_type)
            
            if blocked_data_types:
                types = ", ".join(set(blocked_data_types))
                details = f"{os.path.basename(file_path)} -> Yasak Veri Tipleri: {types}"
                post_incident_log("USB Transferi", types, "ENGEL - Politika İhlali", details)
                
                q = quarantine_file(file_path) 
                if q: print(f"!!! Dosya karantinaya taşındı: {q} !!!")
            
        except Exception as e:
            post_incident_log("USB Transferi", "Hata", "İşlenmedi", f"Dosya işleme hatası: {e}")

    def on_created(self, event):
        if event.is_directory: return
        time.sleep(0.1) 
        self._process_file(event.src_path)

    def on_modified(self, event):
        if event.is_directory: return
        time.sleep(0.05)
        self._process_file(event.src_path)

def scan_existing_files_in_mount(mount_path):
    handler = USBFileHandler()
    print(f"[USB] Mevcut dosyalar taranıyor: {mount_path}")
    for root, _, files in os.walk(mount_path):
        for f in files:
            fp = os.path.join(root, f)
            try:
                handler._process_file(fp)
            except Exception:
                continue

def start_observer_for_mount(mount_path):
    try:
        scan_existing_files_in_mount(mount_path)
        event_handler = USBFileHandler()
        observer = Observer()
        observer.schedule(event_handler, mount_path, recursive=True)
        observer.daemon = True
        observer.start()
        print(f"[USB OBSERVER] Başlatıldı: {mount_path}")
        return observer
    except Exception as e:
        print(f"[USB OBSERVER] Başlatılamadı ({mount_path}): {e}")
        return None

def usb_monitor():
    usb_policy = active_policies.get("usb")
    if not usb_policy: 
        print("[USB] Politika gereği izleyici başlatılmadı.")
        return

    print("[USB] Gerçek USB mount izleyici başlatıldı.")
    known = set()
    observers = {}

    if os.path.exists(SIM_USB_DIR):
        obs = start_observer_for_mount(SIM_USB_DIR)
        if obs:
            observers[SIM_USB_DIR] = obs
            known.add(SIM_USB_DIR)

    try:
        while True:
            mounts = set(get_usb_mount_points(SIM_USB_DIR))
            added = mounts - known
            removed = known - mounts

            for m in added:
                if m == SIM_USB_DIR: continue
                obs = start_observer_for_mount(m)
                if obs: observers[m] = obs
                known.add(m)

            for m in removed:
                if m in observers:
                    try: observers[m].stop(); observers[m].join(timeout=1)
                    except Exception: pass
                    del observers[m]
                known.discard(m)

            time.sleep(2)
    except Exception as e:
        print(f"[USB Monitor Hata]: {e}")

# ============================================================
# CLIPBOARD MONITOR 
# ============================================================

def clipboard_monitor():
    clipboard_policy = active_policies.get("clipboard")
    if not clipboard_policy: 
        print("[CLIPBOARD] Politika gereği izleyici başlatılmadı.")
        return

    print("[CLIPBOARD] Pano İzleyici Aktif.")
    last_clipboard_content = None
    while True:
        try:
            current_clipboard_content = pyperclip.paste() or ""

            if current_clipboard_content != last_clipboard_content and current_clipboard_content:
                # Dinamik Anahtar Kelimeleri Çek
                dynamic_keywords = clipboard_policy.get("Keywords", []) 
                
                # 🚨 scan_content'ı yeni parametre ile çağır
                incidents = scan_content(str(current_clipboard_content), dynamic_keywords) 
                
                blocked_data_types = []
                
                for incident in incidents:
                    data_type = incident["data_type"]

                    # Anahtar Kelime Kontrolü
                    if data_type == "KEYWORD_MATCH":
                        if dynamic_keywords:
                            blocked_data_types.append("ANAHTAR_KELİME")
                            
                    if clipboard_policy.get(data_type, False):
                        blocked_data_types.append(data_type)

                if blocked_data_types:
                    detected_types = ", ".join(set(blocked_data_types))
                    masked_match = incidents[0]['masked_match']

                    post_incident_log("Pano Kopyalama", detected_types, "ENGEL - Pano Temizlendi (Politika)", masked_match)

                    try:
                        clean_msg = f"[DLP] Politika İhlali ({detected_types}) nedeniyle içerik engellendi."
                        pyperclip.copy(clean_msg)
                        last_clipboard_content = clean_msg
                    except Exception: pass
                else:
                    last_clipboard_content = current_clipboard_content

            time.sleep(0.5)
        except Exception: time.sleep(1)


# ============================================================
# AĞ BAĞLANTI YÖNETİMİ
# ============================================================

def connect_to_gateway():
    global gateway_connection
    if gateway_connection: gateway_connection.close(); gateway_connection = None
        
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SENDER_GATEWAY_HOST, SENDER_GATEWAY_PORT))
        sock.sendall(f"HELLO:{VM_ID}\n".encode("utf-8"))
        sock.settimeout(1)
        
        try:
            sock.makefile('r', encoding='utf-8').readline().strip()
        except socket.timeout: pass
            
        sock.settimeout(None)
        gateway_connection = sock
        return True
    except Exception: return False


def listen_for_messages():
    global gateway_connection
    if not gateway_connection: return

    file_obj = gateway_connection.makefile("r", encoding="utf-8")
    while True:
        try:
            line = file_obj.readline()
            if not line: break 
            
            message = line.strip()
            if message:
                print(f"[MESAJ ALINDI] {message}")
                
        except Exception: break
            
    print(f"[{VM_ID}] Gateway bağlantısı kesildi. 5 sn sonra yeniden bağlanma denemesi...")
    gateway_connection = None
    time.sleep(5)
    connect_to_gateway()

def send_network_message(receiver_id, text):
    global gateway_connection
    if not gateway_connection and not connect_to_gateway():
        print(f"[{VM_ID}] HATA: Gateway'e bağlanılamadı. Mesaj gönderilemedi.")
        return

    # Doğrudan dict formatında payload oluştur
    payload = {
        "src": VM_ID,
        "dst": receiver_id,
        "channel": "chat",
        "payload": text
    }
    
    try:
        # JSON + yeni satır formatında gönder
        gateway_connection.sendall((json.dumps(payload) + "\n").encode("utf-8"))
    except Exception as e:
        print(f"[{VM_ID}] Gönderme hatası: {e}. Bağlantı yenileniyor.")
        gateway_connection = None


# vm_agent.py (Revize Edilmiş run_chat_interface)

def run_chat_interface():
    # Başlangıçta hedef ID'yi kullanıcıdan al
    receiver_id = input(f"[{VM_ID}] Lütfen mesaj göndermek istediğiniz Hedef VM ID'sini girin (Örn: vm_user_2): ").strip() or "vm_user_2"
    
    # Kendi kendine mesaj göndermeyi önlemek için kontrol
    if receiver_id == VM_ID:
        print("[HATA] Kendinize mesaj gönderemezsiniz. Lütfen farklı bir VM ID'si girin ve tekrar başlatın.")
        return

    print("---------------------------------------------------------")
    print(f"Chat Başlatıldı: {VM_ID} -> {receiver_id} | Çıkış: 'q', Alıcı Değiştir: 'c'")
    print("---------------------------------------------------------")

    while True:
        try:
            # Mesajı almak için mevcut alıcı ID'sini prompt içinde göster
            text = input(f"[{VM_ID} -> {receiver_id} Mesaj]: ").strip()
            
            # --- YENİ KONTROL ---
            if text.lower() == "q":
                print("Chat arayüzü kapatılıyor...")
                break
            
            if text.lower() == "c":
                # Alıcıyı değiştirme talebi
                print("--- ALICI DEĞİŞTİRME MODU ---")
                new_receiver_id = input(f"Yeni Hedef VM ID'sini girin: ").strip()
                
                if new_receiver_id and new_receiver_id != VM_ID:
                    receiver_id = new_receiver_id
                    print(f"\n✅ Hedef başarıyla {receiver_id}'ye değiştirildi. Devam edebilirsiniz.")
                else:
                    print("⚠️ Geçersiz ID. Alıcı değiştirilmedi.")
                
                # Prompt'a geri dön (Döngünün başına)
                continue
            # --------------------

            if text: 
                send_network_message(receiver_id, text)
        
        except (EOFError, KeyboardInterrupt):
            print("Chat arayüzü kapatılıyor...")
            break
            
    # Döngüden çıkış
    print("Chat arayüzü kapandı.")

# ============================================================
# ANA ÇALIŞMA FONKSİYONU
# ============================================================

def run_vm_agent():
    print(f"[{VM_ID}] DLP Endpoint Ajanı başlatılıyor...")

    # 1. Politikaları Çek
    policies = get_dlp_policies()
    print(f"[{VM_ID}] Aktif Politikalar: {policies}")
    
    # 2. Yerel İzleyicileri Koşullu Olarak Başlat 
    usb_thread = threading.Thread(target=usb_monitor, daemon=True)
    usb_thread.start()
    clipboard_thread = threading.Thread(target=clipboard_monitor, daemon=True)
    clipboard_thread.start()

    # 3. Gateway'e Bağlan ve Dinleyiciyi Başlat 
    if connect_to_gateway():
        listener_thread = threading.Thread(target=listen_for_messages, daemon=True)
        listener_thread.start()
        print("[AGENT] Ağ Gateway Bağlantısı Kuruldu.")
    else:
        print("[AGENT] Ağ Gateway'e bağlanılamadı. Ağ iletişimi engellendi.")

    print("---------------------------------------------------------")
    print(f"--- DLP Endpoint Ajanı ({VM_ID}) ÇALIŞIYOR ---")
    print("---------------------------------------------------------")
    
    run_chat_interface()
    
    print(f"[{VM_ID}] Ajanın yerel izlemesi devam ediyor. Çıkmak için CTRL+C.")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n--- DLP Endpoint Modu Durduruluyor ---")


if __name__ == "__main__":
    try:
        # Tek bir VM ile test edileceği için vm_user_1 sabit ID'si kullanılabilir
        chosen_id = input("Lütfen bu VM Ajanı için ID girin (Örn: vm_user_1): ").strip() or "vm_user_1"
        VM_ID = chosen_id
        run_vm_agent()
    except Exception as e:
        print(f"Kritik hata: {e}")
        sys.exit(1)
