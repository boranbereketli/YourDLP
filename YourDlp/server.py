# server.py

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
# POLİTİKA VERİTABANI ve AYARLAR
# ============================================================

# Politika yapısı: {user_id: {kanal: {veri_tipi: True/False (True=Yasak)}}
USER_POLICIES = {
    # -----------------------------------------------------------------
    # VM_USER_1 POLİTİKASI: En Kısıtlı Ajan (Test Göndericisi)
    # -----------------------------------------------------------------
    "vm_user_1": {
        # Clipboard: TC, IBAN, Kredi Kartı yasak (L1, L2 testleri için)
        "clipboard": {"TCKN": True, "IBAN_TR": True, "KREDI_KARTI": True, "E_POSTA": False, "TEL_NO": False}, 
        # USB: IBAN ve Kredi Kartı yasak (L3, L4 testleri için)
        "usb":       {"TCKN": False, "IBAN_TR": True, "KREDI_KARTI": True, "E_POSTA": False, "TEL_NO": False},  
        # Network: TC ve IBAN yasak (N1, N2, N3 testleri için)
        "network":   {"TCKN": True,  "IBAN_TR": True, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False}, 
    },
    
    # -----------------------------------------------------------------
    # VM_USER_2 POLİTİKASI: Biraz Daha Serbest Ajan (Test Alıcısı)
    # -----------------------------------------------------------------
    "vm_user_2": {
        # Clipboard: Tamamen serbest
        "clipboard": {"TCKN": False, "IBAN_TR": False, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False}, 
        # USB: Her şey yasak
        "usb":       {"TCKN": True,  "IBAN_TR": True, "KREDI_KARTI": True, "E_POSTA": True, "TEL_NO": True},   
        # Network: Sadece TC yasak (N4, N5 testleri için)
        "network":   {"TCKN": True,  "IBAN_TR": False, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False}, 
    },
    
    # -----------------------------------------------------------------
    # VM_USER_3 POLİTİKASI: Ağ Muafiyeti Testi İçin
    # -----------------------------------------------------------------
    "vm_user_3": {
        # Network: Herhangi bir içerik kısıtlaması yok (Muafiyet, E1 testi için hazırlanmıştır)
        "network":   {"TCKN": False, "IBAN_TR": False, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False}, 
        "clipboard": {"TCKN": False, "IBAN_TR": False, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False}, 
        "usb":       {"TCKN": False, "IBAN_TR": False, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False}, 
    },
    
    # -----------------------------------------------------------------
    # VM_USER_4 POLİTİKASI: Ağ Muafiyeti Hedefi
    # -----------------------------------------------------------------
    "vm_user_4": {
        # Boş bırakılabilir, sadece hedef olarak kullanılacak
        "network":   {"TCKN": False, "IBAN_TR": False, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False}, 
        "clipboard": {"TCKN": False, "IBAN_TR": False, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False}, 
        "usb":       {"TCKN": False, "IBAN_TR": False, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False}, 
    }
}

# Ağ İletişim Muafiyetleri (Gateway bu trafiği HİÇ İNCELEMEZ, doğrudan yönlendirir)
NETWORK_DLP_EXCLUSIONS = {
    # E1 ve E2 Testi için: vm_user_3 ve vm_user_4 arasındaki trafik inceleme dışıdır.
    ("vm_user_3", "vm_user_4"), 
}

# Socket Ayarları (Yerel test için 127.0.0.1'de çalışacak)
GATEWAY_LISTEN_HOST = "127.0.0.1" 
GATEWAY_LISTEN_PORT = 9101
LIVE_CONNECTIONS = {}

# ============================================================
# LOGGING & REST API ENDPOINTS
# ============================================================

def log_incident(event_type, data_type, action, details):
    """ Logları sunucu tarafında CSV dosyasına kaydeder. """
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
        "network":   default_restrictions.copy(),
    })
    return jsonify(policies)

@app.route('/log_incident', methods=['POST'])
def receive_incident():
    """ Uç nokta ajanlarından gelen logları kaydeder """
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


# ============================================================
# DLP NETWORK GATEWAY FONKSİYONLARI (Aynı kalır)
# ============================================================

# (process_message, client_handler, run_gateway, start_server fonksiyonları 
#  önceki yanıttaki haliyle korunmuştur.)

def process_message(msg: Message):
    """ Mesajı inceler/yönlendirir. Her zaman Gateway'den geçer. """
    src = msg.src
    dst = msg.dst
    
    if dst not in LIVE_CONNECTIONS:
        log_incident("Ağ Mesajı", "Hata", "ENGEL - Alıcı Offline", f"{src}->{dst}")
        return False, f"[DLP] HATA: Alıcı VM ({dst}) Gateway'e bağlı değil."

    if (src, dst) in NETWORK_DLP_EXCLUSIONS:
        log_incident(
            event_type=f"{msg.channel} Mesajı",
            data_type="YOK",
            action="İZİN VERİLDİ - Politika Muafiyeti (İncelemesiz Yönlendirme)",
            details=f"{src}->{dst} | İçerik taranmadı."
        )
        recipient_sock = LIVE_CONNECTIONS[dst]['socket']
        payload_to_send = f"[{src}]: {msg.payload}\n"
        recipient_sock.sendall(payload_to_send.encode("utf-8"))
        return True, "[DLP] Mesaj incelemesiz iletildi."

    incidents = scan_content(msg.payload)
    src_network_policy = USER_POLICIES.get(src, {}).get("network", {})
    blocked_data_types = []

    if incidents:
        for incident in incidents:
            data_type = incident["data_type"]
            if src_network_policy.get(data_type, False): 
                blocked_data_types.append(data_type)
        
        if blocked_data_types:
            data_type_str = "/".join(set(blocked_data_types))
            log_incident(
                event_type=f"{msg.channel} Mesajı",
                data_type=data_type_str,
                action="ENGEL - Kısıtlı Veri Tespiti",
                details=f"{src}->{dst} | Yasaklanan Veri Tipleri: {data_type_str}",
            )
            return False, f"[DLP] Mesajınız yasaklanmış veri ({data_type_str}) içerdiği için engellendi."
        else:
            log_incident(
                event_type=f"{msg.channel} Mesajı",
                data_type="YOK (İzin Verildi)",
                action="İZİN VERİLDİ - Hassas Veri Politika İzni",
                details=f"{src}->{dst} | Hassas veri var ancak {src} için yasaklı değil.",
            )
            
    else:
        log_incident(
            event_type=f"{msg.channel} Mesajı",
            data_type="YOK",
            action="İZİN VERİLDİ - Mesaj iletildi (Temiz)",
            details=f"{src}->{dst} | {msg.payload[:50]}...",
        )

    recipient_sock = LIVE_CONNECTIONS[dst]['socket']
    payload_to_send = f"[{src}]: {msg.payload}\n"
    recipient_sock.sendall(payload_to_send.encode("utf-8"))
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
    # REST API ve Ağ Geçidi'ni eş zamanlı başlat
    gateway_thread = threading.Thread(target=run_gateway, daemon=True)
    gateway_thread.start()
    
    print("\n[SERVER] DLP Policy & Log REST API başlatılıyor (Port 5000)...")
    app.run(host='127.0.0.1', port=5000)

if __name__ == '__main__':
    start_server()