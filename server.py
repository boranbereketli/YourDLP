# server.py (Kalıcı Hafızalı - Persistent)

from flask import Flask, request, jsonify
import threading
import socket
import time
import os
import csv
import json
from YOUR_DLP_LIB import (
    scan_content, Message, LOG_CSV, 
    DLP_SCAN_ORDER 
)

app = Flask(__name__)
POLICY_FILE = "policies.json"  # Veritabanı dosyası

# ============================================================
# VARSAYILAN POLİTİKALAR (İlk kurulum için)
# ============================================================
DEFAULT_POLICIES = {
    "vm_user_1": {
        "clipboard": {"TCKN": True, "IBAN_TR": True, "KREDI_KARTI": True, "E_POSTA": False, "TEL_NO": False, "Keywords": ["araba", "pilot"]}, 
        "usb":       {"TCKN": False, "IBAN_TR": True, "KREDI_KARTI": True, "E_POSTA": False, "TEL_NO": False},  
        "network":   {
            "vm_user_2": {"TCKN": True,  "IBAN_TR": True, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False, "Keywords": ["domates", "patates"]},
        }, 
    },
    "vm_user_2": {
        "clipboard": {"TCKN": False, "IBAN_TR": False, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False}, 
        "usb":       {"TCKN": True,  "IBAN_TR": True, "KREDI_KARTI": True, "E_POSTA": True, "TEL_NO": True},   
        "network":   {
            "vm_user_1": {"TCKN": True,  "IBAN_TR": False, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False},
        }, 
    },
    "vm_user_3": {
        "clipboard": {"TCKN": False, "IBAN_TR": False, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False}, 
        "usb":       {"TCKN": False, "IBAN_TR": False, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False}, 
        "network":   {},
    },
}

# Başlangıçta boş, load_policies() ile doldurulacak
USER_POLICIES = {}

# ============================================================
# KALICILIK (Persistence) FONKSİYONLARI
# ============================================================
def save_policies():
    """ USER_POLICIES sözlüğünü JSON dosyasına yazar. """
    try:
        with open(POLICY_FILE, 'w', encoding='utf-8') as f:
            json.dump(USER_POLICIES, f, indent=4, ensure_ascii=False)
        print("[SERVER] Politikalar 'policies.json' dosyasına kaydedildi.")
    except Exception as e:
        print(f"[ERROR] Politikalar kaydedilemedi: {e}")

def load_policies():
    """ Sunucu açılışında dosyadan politikaları yükler. """
    global USER_POLICIES
    if os.path.exists(POLICY_FILE):
        try:
            with open(POLICY_FILE, 'r', encoding='utf-8') as f:
                USER_POLICIES = json.load(f)
            print(f"[SERVER] Politikalar '{POLICY_FILE}' dosyasından yüklendi.")
        except Exception as e:
            print(f"[ERROR] Politikalar yüklenirken hata: {e}. Varsayılanlar kullanılıyor.")
            USER_POLICIES = DEFAULT_POLICIES.copy()
            save_policies()
    else:
        # Dosya yoksa varsayılanları yükle ve dosyayı oluştur
        print("[SERVER] Kayıt dosyası bulunamadı. Varsayılan politikalar oluşturuluyor...")
        USER_POLICIES = DEFAULT_POLICIES.copy()
        save_policies()

# Uygulama başlarken yükle
load_policies()

# ============================================================
# SOCKET & CONFIG
# ============================================================
GATEWAY_LISTEN_HOST = "127.0.0.1" 
GATEWAY_LISTEN_PORT = 9101
LIVE_CONNECTIONS = {}

# ============================================================
# REST API
# ============================================================

def log_incident(event_type, data_type, action, details):
    log_line = f"{time.strftime('%Y-%m-%d %H:%M:%S')},{event_type},{data_type},{action},{details}\n"
    try:
        if not os.path.exists(LOG_CSV):
            with open(LOG_CSV, "w", encoding="utf-8") as f:
                f.write("Tarih,Olay_Tipi,Veri_Tipi,Aksiyon,Detay\n")
        with open(LOG_CSV, "a", encoding="utf-8") as f:
            f.write(log_line)
    except Exception as e:
        print(f"[SERVER LOG ERROR] {e}")
    print(f"\n[SERVER LOG] {data_type} | {action} | {details}")

@app.route('/policies/<user_id>', methods=['GET'])
def get_policies(user_id):
    default_restrictions = {d: True for d in DLP_SCAN_ORDER}
    policies = USER_POLICIES.get(user_id, {
        "clipboard": default_restrictions.copy(),
        "usb":       default_restrictions.copy(),
        "network":   {d: default_restrictions.copy() for d in USER_POLICIES.keys()},
    })
    return jsonify(policies)

@app.route('/log_incident', methods=['POST'])
def receive_incident():
    data = request.json
    try:
        details = f"User: {data.get('user_id', 'UNKNOWN')} | {data.get('details', 'No details')}"
        log_incident(
            event_type=data.get('event_type', 'UNKNOWN_EVENT'),
            data_type=data.get('data_type', 'N/A'),
            action=data.get('action', 'N/A'),
            details=details
        )
        return jsonify({"status": "ok", "message": "Log recorded"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/update_policy', methods=['POST'])
def update_policy():
    data = request.json
    user_id = data.get("user_id")
    policies = data.get("policies")

    if not user_id or not policies:
        return jsonify({"error": "user_id ve policies zorunlu"}), 400

    # Politikayı güncelle
    USER_POLICIES[user_id] = policies
    
    # 💾 Değişikliği diske kaydet
    save_policies() 

    return jsonify({"status": "ok", "message": "Policy güncellendi ve kaydedildi."}), 200

# YENİ EKLENEN ENDPOINT: Silme işlemi için
@app.route('/delete_policy/<user_id>', methods=['POST'])
def delete_policy(user_id):
    if user_id in USER_POLICIES:
        del USER_POLICIES[user_id]
        
        # 💾 Değişikliği diske kaydet
        save_policies()
        
        return jsonify({"status": "ok", "message": f"{user_id} silindi."}), 200
    return jsonify({"error": "Kullanıcı bulunamadı"}), 404

@app.route('/logs/<vm_id>', methods=['GET'])
def get_logs_for_user(vm_id):
    try:
        if not os.path.exists(LOG_CSV):
            return jsonify({"logs": []})
        filtered = []
        with open(LOG_CSV, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines:
            if f"User: {vm_id}" in line:
                filtered.append(line.strip())
                continue
            if f"{vm_id}->" in line:
                filtered.append(line.strip())
                continue
        return jsonify({"logs": filtered}), 200
    except Exception as e:
        return jsonify({"logs": [], "error": str(e)})

@app.route("/users", methods=["GET"])
def get_users():
    return jsonify({"users": list(USER_POLICIES.keys())})

# ============================================================
# DLP NETWORK GATEWAY
# ============================================================
def process_message(msg: Message):
    src = msg.src
    dst = msg.dst
    
    if dst not in LIVE_CONNECTIONS:
        log_incident("Ağ Mesajı", "Hata", "ENGEL - Alıcı Offline", f"{src}->{dst}")
        return False, f"[DLP] HATA: Alıcı VM ({dst}) Gateway'e bağlı değil."

    network_policy_for_dst = USER_POLICIES.get(src, {}).get("network", {}).get(dst)
    
    if network_policy_for_dst is None:
        log_incident(f"{msg.channel} Mesajı", "YOK", "İZİN VERİLDİ - Hedefe Özel Kural Yok", f"{src}->{dst} | İçerik taranmadı.")
        recipient_sock = LIVE_CONNECTIONS[dst]['socket']
        try: recipient_sock.sendall(f"[{src}]: {msg.payload}\n".encode("utf-8"))
        except: return False, f"[DLP] HATA: Mesaj gönderilemedi."
        return True, "[DLP] Mesaj incelemesiz iletildi."

    dynamic_keywords = network_policy_for_dst.get("Keywords", []) 
    incidents = scan_content(msg.payload, dynamic_keywords) 
    blocked_data_types = []

    if incidents:
        for incident in incidents:
            data_type = incident["data_type"]
            if data_type == "KEYWORD_MATCH" and dynamic_keywords:
                blocked_data_types.append("ANAHTAR_KELİME")
            if network_policy_for_dst.get(data_type, False): 
                blocked_data_types.append(data_type)
        
        if blocked_data_types:
            data_type_str = "/".join(set(blocked_data_types))
            log_incident(f"{msg.channel} Mesajı", data_type_str, "ENGEL - Kısıtlı Veri Tespiti", f"{src}->{dst} | Yasak: {data_type_str}")
            return False, f"[DLP] Mesajınız yasaklanmış veri ({data_type_str}) içerdiği için engellendi."
        else:
            log_incident(f"{msg.channel} Mesajı", "YOK (İzin Verildi)", "İZİN VERİLDİ - Hassas Veri Politika İzni", f"{src}->{dst}")
    else:
        log_incident(f"{msg.channel} Mesajı", "YOK", "İZİN VERİLDİ - Temiz", f"{src}->{dst}")

    recipient_sock = LIVE_CONNECTIONS[dst]['socket']
    try: recipient_sock.sendall(f"[{src}]: {msg.payload}\n".encode("utf-8"))
    except: return False, f"[DLP] HATA: Mesaj gönderilemedi."
        
    return True, "[DLP] Mesaj iletildi."

def client_handler(conn, addr):
    user_id = None
    try:
        conn_file = conn.makefile("r", encoding="utf-8")
        try:
            initial_data = conn_file.readline().strip()
            if initial_data.startswith("HELLO:"):
                user_id = initial_data.split(":", 1)[1].strip()
                LIVE_CONNECTIONS[user_id] = {'ip': addr[0], 'socket': conn}
                print(f"[GATEWAY] Yeni Ajan Bağlandı: {user_id} ({addr[0]})")
                conn.sendall(f"Hoş Geldin, {user_id}. Gateway aktif.\n".encode("utf-8"))
            else:
                conn.sendall("ERROR: Lütfen ilk mesajda 'HELLO:<VM_ID>' gönderin.\n".encode("utf-8"))
                return
        except Exception: return

        for line in conn_file:
            try:
                data = json.loads(line.rstrip("\n"))
                msg = Message(src=user_id, dst=data.get("dst", "UNKNOWN"), channel=data.get("channel", "chat"), payload=data.get("payload", ""))
            except:
                conn.sendall("[DLP] Geçersiz mesaj formatı.\n".encode("utf-8")); continue

            success, response_msg = process_message(msg)
            if not success: conn.sendall(f"{response_msg}\n".encode("utf-8"))

    except: pass
    finally:
        if user_id in LIVE_CONNECTIONS: del LIVE_CONNECTIONS[user_id]
        conn.close()

def run_gateway():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.bind((GATEWAY_LISTEN_HOST, GATEWAY_LISTEN_PORT))
        server_sock.listen(5)
        print(f"[GATEWAY] Çoklu Ajan Dinleniyor: {GATEWAY_LISTEN_HOST}:{GATEWAY_LISTEN_PORT}")
    except OSError as e: print(f"[GATEWAY HATA] {e}"); return

    try:
        while True:
            conn, addr = server_sock.accept()
            threading.Thread(target=client_handler, args=(conn, addr), daemon=True).start()
    except: pass
    finally: server_sock.close()

def start_server():
    gateway_thread = threading.Thread(target=run_gateway, daemon=True)
    gateway_thread.start()
    print("\n[SERVER] DLP Policy & Log REST API başlatılıyor (Port 5000)...")
    app.run(host='127.0.0.1', port=5000)

if __name__ == '__main__':
    start_server()