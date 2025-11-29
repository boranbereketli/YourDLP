"""
Basit Policy Server
- GET  → İstemciden policy çekme
- POST → İstemciden policy güncelleme
"""

from flask import Flask, jsonify, request
import json

app = Flask(__name__)

POLICY = {
    "usb_policy": "SMART",         # STRICT | SMART
    "scan_on_modify": True,        # USB değişiklikte tarama
    "features": {
        "clipboard_enabled": True,
        "usb_enabled": True,
        "network_enabled": False
    },
    "banned_words": ["password", "secret", "iban"],
    "scan_rules": {
        "TCKN": True,
        "TEL_NO": True,
        "IBAN_TR": True,
        "KREDI_KARTI": True,
        "E_POSTA": True
    }
}

try:
    with open("server_policy.json", "r", encoding="utf-8") as f:
        file_data = json.load(f)
        POLICY.update(file_data)  # dosyadaki son policy RAM'e yazılır
        print("[SERVER] Mevcut policy dosyadan yüklendi.")
except Exception:
    print("[SERVER] Dosya bulunmadı, varsayılan policy kullanılıyor.")

@app.route("/get_policy/<endpoint_id>", methods=["GET"])
def get_policy(endpoint_id):
    if endpoint_id != "PC1":
        return jsonify({"error": "unknown endpoint"}), 404
    return jsonify(POLICY)

@app.route("/update_policy", methods=["POST"])
def update_policy():
    global POLICY
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "JSON yok"}), 400
        
        POLICY.update(data)

        with open("server_policy.json", "w", encoding="utf-8") as f:
            json.dump(POLICY, f, indent=4, ensure_ascii=False)

        return jsonify({
            "status": "success",
            "message": "Policy güncellendi",
            "current_policy": POLICY
        })

    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500


if __name__ == "__main__":
    print("Policy Server ÇALIŞIYOR → http://127.0.0.1:5000")
    print("GET  → /get_policy/PC1")
    print("POST → /update_policy")
    app.run(host="127.0.0.1", port=5000, debug=True)
