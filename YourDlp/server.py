# server.py (Revize Edilmiş)

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

# ============================================================
# YENİ POLİTİKA VERİTABANI ve AYARLAR
# ============================================================

# Network yapısı: {user_id: {kanal: {hedef_user_id: {veri_tipi: True/False (True=Yasak)}}}}
# NOT: Network altında tanımlanmayan hedefler için GİZLİ varsayılan kural: SERBEST (İnceleme atlanır).

USER_POLICIES = {
    # -----------------------------------------------------------------
    # VM_USER_1 POLİTİKASI: (Sadece vm_user_2'ye kısıtlı)
    # -----------------------------------------------------------------
    "vm_user_1": {
        "clipboard": {"TCKN": True, "IBAN_TR": True, "KREDI_KARTI": True, "E_POSTA": False, "TEL_NO": False,"Keywords": ["araba", "pilot"]}, 
        "usb":       {"TCKN": False, "IBAN_TR": True, "KREDI_KARTI": True, "E_POSTA": False, "TEL_NO": False},  
        # NETWORK: Sadece vm_user_2'ye giderken bu kısıtlamalar geçerli.
        "network":   {
            "vm_user_2": {"TCKN": True,  "IBAN_TR": True, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False,"Keywords": ["domates", "patates"]},
            # Başka bir hedefe (Örn: vm_user_3) kural tanımlanmamıştır, yani serbesttir.
        }, 
    },
    
    # -----------------------------------------------------------------
    # VM_USER_2 POLİTİKASI: (Sadece vm_user_1'e kısıtlı)
    # -----------------------------------------------------------------
    "vm_user_2": {
        "clipboard": {"TCKN": False, "IBAN_TR": False, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False}, 
        "usb":       {"TCKN": True,  "IBAN_TR": True, "KREDI_KARTI": True, "E_POSTA": True, "TEL_NO": True},   
        "network":   {
            "vm_user_1": {"TCKN": True,  "IBAN_TR": False, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False},
        }, 
    },
    
    # -----------------------------------------------------------------
    # VM_USER_3 POLİTİKASI: (Network Kuralı Yok -> Herkese Serbest)
    # -----------------------------------------------------------------
    "vm_user_3": {
        "clipboard": {"TCKN": False, "IBAN_TR": False, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False}, 
        "usb":       {"TCKN": False, "IBAN_TR": False, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False}, 
        "network":   {}, # Network altında hedef tanımlı değil -> herkese serbest
    },
    
    # ... vm_user_4 ve diğerleri de network altında kural tanımlanmadığı sürece serbesttir.
}

# 🚨 NETWORK_DLP_EXCLUSIONS KALDIRILDI / İhtiyaç Kalmadı
# Socket Ayarları (Aynı kalır)
GATEWAY_LISTEN_HOST = "127.0.0.1" 
GATEWAY_LISTEN_PORT = 9101
LIVE_CONNECTIONS = {}

# ============================================================
# LOGGING & REST API ENDPOINTS (Aynı kalır)
# ============================================================

def log_incident(event_type, data_type, action, details):
    """ Logları sunucu tarafında CSV dosyasına kaydeder. """
    # ... (kod aynı kalır) ...
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
    """ VM'lerin çekmesi için veri tipi bazlı politikaları döndürür """
    default_restrictions = {d: True for d in DLP_SCAN_ORDER}
    policies = USER_POLICIES.get(user_id, {
        "clipboard": default_restrictions.copy(),
        "usb":       default_restrictions.copy(),
        "network":   {d: default_restrictions.copy() for d in USER_POLICIES.keys()}, # Varsayılan olarak herkese kısıtla
    })
    return jsonify(policies)

@app.route('/log_incident', methods=['POST'])
def receive_incident():
    # ... (kod aynı kalır) ...
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

    USER_POLICIES[user_id] = policies

    return jsonify({"status": "ok", "message": "Policy güncellendi"}), 200


# ============================================================
# DLP NETWORK GATEWAY (Yeni Politika Uygulama Mantığı)
# ============================================================

def process_message(msg: Message):
    """ Mesajı inceler/yönlendirir. """
    src = msg.src
    dst = msg.dst
    
    if dst not in LIVE_CONNECTIONS:
        log_incident("Ağ Mesajı", "Hata", "ENGEL - Alıcı Offline", f"{src}->{dst}")
        return False, f"[DLP] HATA: Alıcı VM ({dst}) Gateway'e bağlı değil."

    # Kaynak kullanıcının bu hedefe uyguladığı kısıtlamaları çek
    # Eğer src kullanıcısının politikasında dst için özel kural yoksa, network_policy_for_dst = None döner.
    network_policy_for_dst = USER_POLICIES.get(src, {}).get("network", {}).get(dst)
    
    # 1. Politika Kontrolü: İnceleme Yapılmalı mı?
    if network_policy_for_dst is None:
        # ➡️ Muafiyet/Serbestlik: Kaynak, bu hedefe kısıtlama tanımlamamış (Varsayılan: İzin Verilir, İnceleme Atlanır)
        log_incident(
            event_type=f"{msg.channel} Mesajı",
            data_type="YOK",
            action="İZİN VERİLDİ - Hedefe Özel Kural Yok (İncelemesiz Yönlendirme)",
            details=f"{src}->{dst} | İçerik taranmadı (Politika Tanımsız)."
        )
        
        # Mesajı İlet
        recipient_sock = LIVE_CONNECTIONS[dst]['socket']
        payload_to_send = f"[{src}]: {msg.payload}\n"
        recipient_sock.sendall(payload_to_send.encode("utf-8"))
        return True, "[DLP] Mesaj incelemesiz iletildi."

      # Dinamik Anahtar Kelimeleri Çek
    dynamic_keywords = network_policy_for_dst.get("Keywords", []) 

    # 2. Hassas Veri Tarama (Hem Regex hem de Keywords aranır)
    # 🚨 scan_content'ı yeni parametre ile çağır
    incidents = scan_content(msg.payload, dynamic_keywords) 
    blocked_data_types = []

    if incidents:
        # Tespit edilen her bir veri tipi için tanımlanmış kısıtlamayı kontrol et
        for incident in incidents:
            data_type = incident["data_type"]

            # Anahtar kelime eşleşmesi ise, 'Keywords' alanının varlığı yasaktır.
            if data_type == "KEYWORD_MATCH":
                # Eğer Keywords listesi tanımlıysa, bu KEYWORD_MATCH her zaman yasak olarak kabul edilir
                # (Zaten kurala girdiği için buraya gelmiştir).
                if dynamic_keywords:
                    blocked_data_types.append("ANAHTAR_KELİME")

            # network_policy_for_dst[data_type] == True ise, yasaktır.
            if network_policy_for_dst.get(data_type, False): 
                blocked_data_types.append(data_type)
        
        if blocked_data_types:
            # ⛔ ENGELLEME
            data_type_str = "/".join(set(blocked_data_types))
            log_incident(
                event_type=f"{msg.channel} Mesajı",
                data_type=data_type_str,
                action="ENGEL - Kısıtlı Veri Tespiti",
                details=f"{src}->{dst} | Yasaklanan Veri Tipleri: {data_type_str}",
            )
            return False, f"[DLP] Mesajınız yasaklanmış veri ({data_type_str}) içerdiği için engellendi."
        else:
            # ✅ İZİN VERME (Hassas veri var ama bu hedefe gitmesi yasaklanmamış)
            log_incident(
                event_type=f"{msg.channel} Mesajı",
                data_type="YOK (İzin Verildi)",
                action="İZİN VERİLDİ - Hassas Veri Politika İzni",
                details=f"{src}->{dst} | Hassas veri var ancak bu hedefe gitmesi yasaklı değil.",
            )
            
    else:
        # Temiz mesaj
        log_incident(
            event_type=f"{msg.channel} Mesajı",
            data_type="YOK",
            action="İZİN VERİLDİ - Mesaj iletildi (Temiz)",
            details=f"{src}->{dst} | {msg.payload[:50]}...",
        )

    # Mesajı İlet (Engellenmediyse)
    recipient_sock = LIVE_CONNECTIONS[dst]['socket']
    payload_to_send = f"[{src}]: {msg.payload}\n"
    recipient_sock.sendall(payload_to_send.encode("utf-8"))
    return True, "[DLP] Mesaj iletildi."


# ... (Geri kalan client_handler, run_gateway ve start_server fonksiyonları aynı kalır)

def client_handler(conn, addr):
    # ... (Önceki yanıtta verilen kod aynı kalır) ...
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
                msg = Message(
                    src=user_id, 
                    dst=data.get("dst", "UNKNOWN"),
                    channel=data.get("channel", "chat"),
                    payload=data.get("payload", "")
                )
            except (json.JSONDecodeError, KeyError, AttributeError):
                conn.sendall("[DLP] Geçersiz mesaj formatı.\n".encode("utf-8"))
                continue

            success, response_msg = process_message(msg)
            
            if not success:
                 conn.sendall(f"{response_msg}\n".encode("utf-8"))

    except ConnectionResetError:
        print(f"[GATEWAY] Ajan bağlantısı kesildi: {user_id} ({addr[0]})")
    except Exception as e:
        print(f"[GATEWAY ERROR] {user_id} Ajan hatası: {e}")
    finally:
        if user_id in LIVE_CONNECTIONS: del LIVE_CONNECTIONS[user_id]
        conn.close()


def run_gateway():
    # ... (Önceki yanıtta verilen kod aynı kalır) ...
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.bind((GATEWAY_LISTEN_HOST, GATEWAY_LISTEN_PORT))
        server_sock.listen(5)
        print(f"[GATEWAY] Çoklu Ajan Dinleniyor: {GATEWAY_LISTEN_HOST}:{GATEWAY_LISTEN_PORT}")
    except OSError as e:
        print(f"[GATEWAY HATA] Port kullanılıyor veya izin yok: {e}")
        return

    try:
        while True:
            conn, addr = server_sock.accept()
            handler_thread = threading.Thread(target=client_handler, args=(conn, addr), daemon=True)
            handler_thread.start()
    except KeyboardInterrupt:
        print("\n[GATEWAY] Kapatılıyor...")
    except Exception as e:
        print(f"[GATEWAY KRİTİK HATA] {e}")
    finally:
        server_sock.close()


def start_server():
    # ... (Önceki yanıtta verilen kod aynı kalır) ...
    gateway_thread = threading.Thread(target=run_gateway, daemon=True)
    gateway_thread.start()
    
    print("\n[SERVER] DLP Policy & Log REST API başlatılıyor (Port 5000)...")
    app.run(host='127.0.0.1', port=5000)

if __name__ == '__main__':
    start_server()
