# server.py

from flask import Flask, request, jsonify
import threading
import socket
import time
import os
import json
import csv  # <-- CSV kütüphanesi eklendi

# Harici kütüphaneniz
from YOUR_DLP_LIB import (
    scan_content, Message, LOG_CSV, 
    DLP_SCAN_ORDER 
)

app = Flask(__name__)
POLICY_FILE = "policies.json"

# Konsol Renkleri
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

# ============================================================
# CONFIG
# ============================================================
GATEWAY_LISTEN_HOST = "127.0.0.1" 
GATEWAY_LISTEN_PORT = 9101
LIVE_CONNECTIONS = {}
USER_POLICIES = {}

# ============================================================
# PERSISTENCE (Kalıcılık)
# ============================================================
def save_policies():
    try:
        with open(POLICY_FILE, 'w', encoding='utf-8') as f:
            json.dump(USER_POLICIES, f, indent=4, ensure_ascii=False)
        print(f"{Colors.OKGREEN}[SERVER] Politikalar kaydedildi.{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[ERROR] Politikalar kaydedilemedi: {e}{Colors.ENDC}")

def load_policies():
    global USER_POLICIES
    if os.path.exists(POLICY_FILE):
        try:
            with open(POLICY_FILE, 'r', encoding='utf-8') as f:
                USER_POLICIES = json.load(f)
            print(f"{Colors.OKCYAN}[SERVER] Politikalar yüklendi: {len(USER_POLICIES)} kullanıcı.{Colors.ENDC}")
            return
        except Exception as e:
            print(f"{Colors.FAIL}[ERROR] Yükleme hatası: {e}.{Colors.ENDC}")
    
    USER_POLICIES = {}
    save_policies()

load_policies()

# ============================================================
# LOGGING (GÜNCELLENDİ: Güvenli CSV Yazma)
# ============================================================
def log_incident(event_type, data_type, action, details):
    # --- CSV KAYDI (DÜZELTİLDİ) ---
    # csv.writer kullanarak virgül içeren verilerin CSV'yi bozmasını engelliyoruz.
    try:
        file_exists = os.path.exists(LOG_CSV)
        with open(LOG_CSV, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Dosya yoksa başlıkları yaz
            if not file_exists:
                writer.writerow(["Tarih", "Olay_Tipi", "Veri_Tipi", "Aksiyon", "Detay"])
            
            # Veriyi güvenli şekilde yaz
            writer.writerow([
                time.strftime('%Y-%m-%d %H:%M:%S'),
                event_type,
                data_type,
                action,
                details
            ])
    except Exception as e:
        print(f"[LOG ERROR] {e}")

    # --- KONSOL ÇIKTISI ---
    timestamp = time.strftime('%H:%M:%S')
    if "ENGEL" in action:
        color = Colors.FAIL
        icon = "⛔"
    elif "İZİN" in action:
        color = Colors.OKGREEN
        icon = "✅"
    else:
        color = Colors.WARNING
        icon = "⚠️"

    # Konsolda detaylar çok uzunsa kırpabiliriz
    safe_details = (details[:75] + '..') if len(details) > 75 else details
    print(f"{color}[{timestamp}] {icon} {event_type} | {data_type} | {action} -> {safe_details}{Colors.ENDC}")


# ============================================================
# REST API ENDPOINTS
# ============================================================

@app.route('/all_logs', methods=['GET'])
def get_all_logs():
    """CSV dosyasını okur ve JSON olarak döner. Hatalı satırları onarır."""
    logs = []
    if os.path.exists(LOG_CSV):
        try:
            with open(LOG_CSV, 'r', encoding='utf-8') as f:
                # DictReader kullanıyoruz
                reader = csv.DictReader(f)
                
                # --- HATA DÜZELTME BLOĞU ---
                for row in reader:
                    # Eğer satırda beklenenden fazla virgül varsa, DictReader bunları 'None' key'ine atar.
                    # Bu durum JSON.dumps'ta çökme yaratır. Bunu temizliyoruz:
                    if None in row:
                        extra_data = row.pop(None) # None key'ini sil ve veriyi al
                        # Ekstra veriyi 'Detay' sütununa ekleyelim ki kaybolmasın
                        if 'Detay' in row and extra_data:
                            row['Detay'] += " " + " ".join(extra_data)
                    
                    logs.append(row)
                
                logs.reverse() # En yeniler en üstte
        except Exception as e:
            # Hata durumunda boş liste dön, sunucuyu çökertme
            print(f"[LOG READ ERROR] {e}")
            return jsonify({"error": str(e), "logs": []})
            
    return jsonify({"logs": logs})

@app.route('/policies/<user_id>', methods=['GET'])
def get_policies(user_id):
    policies = USER_POLICIES.get(user_id, {
        "clipboard": {d: False for d in DLP_SCAN_ORDER},
        "usb":       {d: False for d in DLP_SCAN_ORDER},
        "network":   {},
    })
    return jsonify(policies)

@app.route('/log_incident', methods=['POST'])
def receive_incident():
    data = request.json
    try:
        details = f"User: {data.get('user_id', 'UNKNOWN')} | {data.get('details', 'No details')}"
        log_incident(
            event_type=data.get('event_type', 'UNKNOWN'),
            data_type=data.get('data_type', 'N/A'),
            action=data.get('action', 'N/A'),
            details=details
        )
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/update_policy', methods=['POST'])
def update_policy():
    data = request.json
    user_id = data.get("user_id")
    new_policies = data.get("policies")

    if not user_id or not new_policies:
        return jsonify({"error": "Eksik parametre"}), 400

    current_policy = USER_POLICIES.get(user_id, {})
    
    current_policy["clipboard"] = new_policies.get("clipboard", current_policy.get("clipboard", {}))
    current_policy["usb"] = new_policies.get("usb", current_policy.get("usb", {}))
    current_policy["network"] = new_policies.get("network", current_policy.get("network", {}))

    USER_POLICIES[user_id] = current_policy
    save_policies()
    return jsonify({"status": "ok"}), 200

@app.route("/users", methods=["GET"])
def get_users():
    return jsonify({"users": list(USER_POLICIES.keys())})

# ============================================================
# DLP NETWORK GATEWAY (SOCKET)
# ============================================================
def process_message(msg: Message, sender_sock):
    src = msg.src
    dst = msg.dst
    
    if dst not in LIVE_CONNECTIONS:
        log_incident("Ağ", "Hata", "HATA", f"{src}->{dst} (Alıcı Offline)")
        return False, "OFFLINE"

    src_policy = USER_POLICIES.get(src, {})
    network_policy_for_dst = src_policy.get("network", {}).get(dst)
    
    recipient_sock = LIVE_CONNECTIONS[dst]['socket']

    if network_policy_for_dst is None:
        log_incident("Ağ", "Genel", "İZİN", f"{src}->{dst}")
        try:
            recipient_sock.sendall(f"MSG:{src}:{msg.payload}\n".encode("utf-8"))
            return True, "OK"
        except:
            return False, "SEND_ERR"

    dynamic_keywords = network_policy_for_dst.get("Keywords", []) 
    incidents = scan_content(msg.payload.lower(), [k.lower() for k in dynamic_keywords])
    
    blocked_reasons = []
    if incidents:
        for incident in incidents:
            d_type = incident["data_type"]
            if d_type == "KEYWORD_MATCH" and dynamic_keywords:
                blocked_reasons.append("KEYWORD")
            
            if network_policy_for_dst.get(d_type, False): 
                blocked_reasons.append(d_type)
        
    if blocked_reasons:
        reason_str = "/".join(set(blocked_reasons))
        log_incident("Ağ", reason_str, "ENGEL", f"{src}->{dst}")
        return False, f"BLOCKED:{reason_str}"
    
    log_incident("Ağ", "Temiz", "İZİN", f"{src}->{dst}")
    try:
        recipient_sock.sendall(f"MSG:{src}:{msg.payload}\n".encode("utf-8"))
        return True, "OK"
    except:
        return False, "SEND_ERR"

def client_handler(conn, addr):
    user_id = None
    try:
        conn_file = conn.makefile("r", encoding="utf-8")
        
        first_line = conn_file.readline().strip()
        if first_line.startswith("HELLO:"):
            user_id = first_line.split(":", 1)[1].strip()
            LIVE_CONNECTIONS[user_id] = {'ip': addr[0], 'socket': conn}
            print(f"{Colors.OKBLUE}[GATEWAY] Bağlandı: {user_id} ({addr[0]}){Colors.ENDC}")
            conn.sendall(f"WELCOME:{user_id}\n".encode("utf-8"))
        else:
            conn.close()
            return

        for line in conn_file:
            try:
                data = json.loads(line.rstrip("\n"))
                msg = Message(
                    src=user_id, 
                    dst=data.get("dst", "UNKNOWN"), 
                    channel=data.get("channel", "chat"), 
                    payload=data.get("payload", "")
                )
                
                success, status_code = process_message(msg, conn)
                
                if success:
                    conn.sendall(f"ACK:{msg.dst}:{msg.payload}\n".encode("utf-8"))
                else:
                    conn.sendall(f"ERR:{msg.dst}:{status_code}\n".encode("utf-8"))

            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"[Global Error] {e}")

    except Exception:
        pass
    finally:
        if user_id and user_id in LIVE_CONNECTIONS:
            del LIVE_CONNECTIONS[user_id]
            print(f"{Colors.WARNING}[GATEWAY] Ayrıldı: {user_id}{Colors.ENDC}")
        try: conn.close()
        except: pass

def run_gateway():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind((GATEWAY_LISTEN_HOST, GATEWAY_LISTEN_PORT))
        server_sock.listen(5)
        print(f"{Colors.HEADER}[GATEWAY] Dinleniyor: {GATEWAY_LISTEN_HOST}:{GATEWAY_LISTEN_PORT}{Colors.ENDC}")
        while True:
            conn, addr = server_sock.accept()
            threading.Thread(target=client_handler, args=(conn, addr), daemon=True).start()
    except OSError as e:
        print(f"[GATEWAY FATAL] {e}")
    finally:
        server_sock.close()

if __name__ == '__main__':
    threading.Thread(target=run_gateway, daemon=True).start()
    print("\n[SERVER] API başlatılıyor (Port 5000)...")
    app.run(host='127.0.0.1', port=5000)