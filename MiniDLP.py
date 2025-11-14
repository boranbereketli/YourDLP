import time
import os
import shutil
import pyperclip
import threading
import re
import socket
from dataclasses import dataclass
from typing import Optional



from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from docx import Document
import PyPDF2
import pandas as pd
from pptx import Presentation

# ============================================================
# 1) DLP KURALLARI ve TARAYICI
# ============================================================

DLP_RULES = {
    "TCKN": {
        "pattern": r'\b\d{11}\b',
        "description": "11 Haneli TC Kimlik Numarası Formatı"
    },
    "KREDI_KARTI": {
        "pattern": r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
        "description": "16 Haneli Kredi Kartı Numarası Formatı"
    },
    "E_POSTA": {
        "pattern": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "description": "E-posta Adresi Formatı"
    },
    "IBAN_TR": {
        # TRxx ile başlayan Türk IBAN formatı (basitleştirilmiş)
        "pattern": r'TR\d{2}[A-Z0-9]{4}\s?(\d{4}\s?){4}\d{2}',
        "description": "Türk IBAN Numarası Formatı"
    }
}

def scan_content(content: str):
    """
    Verilen metin içeriğini tüm DLP kurallarına göre tarar ve bulunan olayları döndürür.
    """
    incidents = []
    for data_type, rule in DLP_RULES.items():
        matches = re.findall(rule["pattern"], content)
        for match in matches:
            if isinstance(match, tuple):
                match = "".join(match)

            if data_type in ["TCKN", "KREDI_KARTI", "IBAN_TR"]:
                flat = match.replace(" ", "")
                masked_data = f"XXXX...{flat[-4:]}"
            else:
                masked_data = f"<{data_type} tespit edildi>"

            incidents.append({
                "data_type": data_type,
                "description": rule["description"],
                "masked_match": masked_data
            })
    return incidents


# ============================================================
# 2) LOGLAMA
# ============================================================

def log_incident(event_type, data_type, action, details):
    """
    DLP olaylarını tek bir CSV dosyasına kaydeder ve ekrana bilgi basar.
    Excel'de Türkçe karakter uyumluluğu için 'windows-1254' kodlaması kullanıldı.
    """
    log_line = f"{time.strftime('%Y-%m-%d %H:%M:%S')},{event_type},{data_type},{action},{details}\n"

    try:
        if not os.path.exists("dlp_incidents.csv"):
            with open("dlp_incidents.csv", "w", encoding="windows-1254") as f:
                f.write("Tarih,Olay_Tipi,Veri_Tipi,Aksiyon,Detay\n")

        with open("dlp_incidents.csv", "a", encoding="windows-1254") as f:
            f.write(log_line)

        print(f"\n[!!! DLP OLAYI KAYDEDİLDİ !!!] - {data_type} tespiti. Aksiyon: {action}")
        print(f"Olay Tipi: {event_type} | Detay: {details}\n")

    except PermissionError:
        print("\n[!!! LOGLAMA BAŞARISIZ !!!] - dlp_incidents.csv kilitli olabilir (Excel'de açık mı?)")
        print(f"Olay (Kaydedilemedi): {log_line}")
    except Exception as e:
        print(f"\n[!!! LOGLAMA HATASI !!!] - {e}")


# ============================================================
# 3) ENDPOINT ORTAMI (USB KLASÖRLERİ)
# ============================================================

USB_DIR = "SIM_USB_SURUCU"
QUARANTINE_DIR = "KARANTINA_ALANI"
if not os.path.exists(USB_DIR):
    os.makedirs(USB_DIR)
if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)


# ============================================================
# 4) CLIPBOARD (PANO) İZLEYİCİ AGENT
# ============================================================

def clipboard_monitor():
    """Kopyala-Yapıştır eylemlerini izler ve hassas veriyi engeller."""
    print("[CLIPBOARD] Pano İzleyici Aktif. Kopyala-Yapıştır eylemleri izleniyor.")
    last_clipboard_content = ""

    while True:
        try:
            current_clipboard_content = pyperclip.paste()

            if current_clipboard_content != last_clipboard_content and current_clipboard_content:
                incidents = scan_content(current_clipboard_content)

                if incidents:
                    detected_types = {i['data_type'] for i in incidents}

                    if len(detected_types) >= 2:
                        risk_level = "YÜKSEK RİSK - Çoklu Veri Sızıntısı"
                    else:
                        risk_level = "ENGEL - Pano Temizlendi"

                    data_type = ", ".join(detected_types)
                    masked_match = incidents[0]['masked_match']

                    log_incident("Pano Kopyalama", data_type, risk_level, masked_match)

                    # ENGELLEME: panoyu temizle
                    pyperclip.copy("Bu içerik hassas veri içerdiği için DLP tarafından engellenmiştir.")

                last_clipboard_content = pyperclip.paste()

            time.sleep(0.5)

        except Exception:
            # Özellikle Linux'ta bazen clipboard erişimi patlayabilir; çok dert etmeyelim.
            time.sleep(5)


# ============================================================
# 5) USB (DOSYA) İZLEYİCİ AGENT
# ============================================================

# ============================================================
# EK DOSYA FORMAT DESTEKLERİ (DOCX, PDF, XLSX, PPTX)
# ============================================================


def read_file_content(path):
    ext = os.path.splitext(path)[1].lower()

    try:
        # TXT & CSV
        if ext in ['.txt', '.csv']:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()

        # DOCX
        elif ext == '.docx':
            doc = Document(path)
            return "\n".join(p.text for p in doc.paragraphs)

        # PDF
        elif ext == '.pdf':
            text = ""
            with open(path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                for page in reader.pages:
                    text += page.extract_text() or ""
            return text

        # EXCEL (xlsx/xls)
        elif ext in ['.xlsx', '.xls']:
            dfs = pd.read_excel(path, sheet_name=None)
            return "\n".join(df.to_string(index=False) for df in dfs.values())

        # POWERPOINT
        elif ext == '.pptx':
            prs = Presentation(path)
            text_runs = []
            for slide in prs.slides:
                for shape in slide.shapes:
                    if hasattr(shape, "text"):
                        text_runs.append(shape.text)
            return "\n".join(text_runs)

        # Desteklenmeyen
        else:
            return ""

    except Exception as e:
        print(f"[!] Dosya okunamadı ({path}): {e}")
        return ""


class USBFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return

        file_path = event.src_path
        file_name = os.path.basename(file_path)
        print(f"\n[USB] Yeni dosya kopyalandı: {file_name}. İçerik taranıyor...")

        try:
            content = read_file_content(file_path)

            if content:
                incidents = scan_content(content)

                if incidents:
                    detected_types = {i['data_type'] for i in incidents}
                    data_type = ", ".join(detected_types)
                    masked_match = incidents[0]['masked_match']

                    log_incident(
                        "USB Transferi",
                        data_type,
                        "ENGEL - Karantina",
                        f"{file_name} -> {masked_match}"
                    )

                    new_path = os.path.join(QUARANTINE_DIR, file_name)
                    shutil.move(file_path, new_path)
                    print(f"!!! Dosya karantinaya taşındı: {new_path} !!!")

                else:
                    print(f"[USB] Dosya temiz: {file_name}")

            else:
                print(f"[USB] Dosya boş veya okunamadı: {file_name}")

        except Exception as e:
            log_incident("USB Transferi", "Hata", "İşlenmedi", f"Dosya işleme hatası: {e}")


"""
class USBFileHandler(FileSystemEventHandler):
    """
    SIM_USB_SURUCU klasöründe (Simüle edilmiş USB) yeni dosya oluştuğunda tetiklenir.
    """
    def on_created(self, event):
        if event.is_directory:
            return

        file_path = event.src_path
        file_name = os.path.basename(file_path)
        print(f"\n[USB] Yeni dosya kopyalandı: {file_name}. İçerik taranıyor...")

        try:
            if file_name.endswith('.txt'):
                time.sleep(0.1)  # Dosyanın tamamen yazılmasını bekle

                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                incidents = scan_content(content)

                if incidents:
                    detected_types = {i['data_type'] for i in incidents}
                    data_type = ", ".join(detected_types)
                    masked_match = incidents[0]['masked_match']

                    log_incident("USB Transferi", data_type, "ENGEL - Karantina", f"{file_name} -> {masked_match}")

                    # Karantinaya taşı
                    new_path = os.path.join(QUARANTINE_DIR, file_name)
                    shutil.move(file_path, new_path)
                    print(f"!!! Dosya karantinaya taşındı: {new_path} !!!")
                else:
                    print(f"[USB] Dosya ({file_name}) temiz. Kopyalama başarılı.")
            else:
                print(f"[USB] '{file_name}' desteklenmeyen dosya tipi. (Pas geçildi)")

        except Exception as e:
            log_incident("USB Transferi", "Hata", "İşlenmedi", f"Dosya işleme hatası: {e}")

"""







def usb_monitor():
    """USB izleme hizmetini başlatır ve observer döndürür."""
    event_handler = USBFileHandler()
    observer = Observer()
    observer.schedule(event_handler, USB_DIR, recursive=False)
    observer.start()
    return observer


# ============================================================
# 6) NETWORK AGENT MİMARİSİ (SENDER / GATEWAY / RECEIVER)
# ============================================================

@dataclass
class Message:
    src: str
    dst: str
    channel: str
    payload: str


class DLPAgentGateway:
    """
    Ortadaki DLP Gateway.
    Sender'dan gelen mesajı alır, tarar, receiver'a gönderip göndermemeye karar verir.
    """
    def __init__(self, name="DLP_GATEWAY"):
        self.name = name

    def handle(self, msg: Message) -> Optional[Message]:
        print(f"\n[{self.name}] Mesaj alındı: {msg.src} -> {msg.dst}")
        print(f"Kanal : {msg.channel}")
        print(f"İçerik: {msg.payload}")

        incidents = scan_content(msg.payload)

        if incidents:
            detected_types = sorted({i["data_type"] for i in incidents})
            data_type_str = "/".join(detected_types)
            masked_samples = ", ".join(sorted({i["masked_match"] for i in incidents}))

            log_incident(
                event_type=f"{msg.channel} Mesajı",
                data_type=data_type_str,
                action="ENGEL - Mesaj gönderilmedi",
                details=f"{msg.src}->{msg.dst} | {masked_samples}",
            )

            print(f"[{self.name}] UYARI: Mesaj BLOKLANDI!")
            print(f"  Veri tipleri : {data_type_str}")
            print(f"  Örnek       : {masked_samples}")
            return None
        else:
            log_incident(
                event_type=f"{msg.channel} Mesajı",
                data_type="YOK",
                action="İZİN VERİLDİ - Mesaj iletildi",
                details=f"{msg.src}->{msg.dst} | {msg.payload[:50]}",
            )

            print(f"[{self.name}] Mesaj temiz, {msg.dst}'ye iletiliyor.")
            return msg


# --- Network konfigürasyonları (burayı kendi IP'lerine göre düzenle) ---

# Gateway tarafı:
GATEWAY_LISTEN_HOST = ""   # Sender buraya bağlanacak
GATEWAY_LISTEN_PORT = 9001

RECEIVER_HOST = ""       # Receiver'ın IP'si
RECEIVER_PORT = 9002

# Sender tarafı:
SENDER_GATEWAY_HOST = ""  # Gateway'in IP'si
SENDER_GATEWAY_PORT = 9001

# Receiver tarafı:
RECEIVER_LISTEN_HOST = ""
RECEIVER_LISTEN_PORT = 9002


def run_gateway():
    dlp = DLPAgentGateway()

    print(f"[{dlp.name}] Receiver'a bağlanılıyor: {RECEIVER_HOST}:{RECEIVER_PORT}")
    receiver_sock = socket.create_connection((RECEIVER_HOST, RECEIVER_PORT))
    print(f"[{dlp.name}] Receiver bağlantısı OK.")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((GATEWAY_LISTEN_HOST, GATEWAY_LISTEN_PORT))
    server_sock.listen(1)
    print(f"[{dlp.name}] Sender için dinleniyor: {GATEWAY_LISTEN_HOST}:{GATEWAY_LISTEN_PORT}")

    sender_sock, sender_addr = server_sock.accept()
    print(f"[{dlp.name}] Sender bağlandı:", sender_addr)

    sender_file = sender_sock.makefile("r", encoding="utf-8")

    try:
        for line in sender_file:
            text = line.rstrip("\n")
            if not text:
                continue

            msg = Message(
                src="SENDER_PC",
                dst="RECEIVER_PC",
                channel="chat",
                payload=text,
            )

            checked = dlp.handle(msg)

            if checked is None:
                sender_sock.sendall(
                    "[DLP] Mesajın hassas veri içerdiği için gönderilmedi.\n".encode("utf-8")
                )
            else:
                receiver_sock.sendall((checked.payload + "\n").encode("utf-8"))

    except KeyboardInterrupt:
        print("\n[Gateway] Kapatılıyor...")
    finally:
        sender_file.close()
        sender_sock.close()
        receiver_sock.close()
        server_sock.close()


def run_sender():
    print("========================================")
    print("   Endpoint Sender Agent (PC1)         ")
    print("========================================")
    print(f"DLP Gateway: {SENDER_GATEWAY_HOST}:{SENDER_GATEWAY_PORT}")
    print("Çıkmak için 'q' yaz.\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SENDER_GATEWAY_HOST, SENDER_GATEWAY_PORT))
    print("[SENDER] Gateway'e bağlanıldı.\n")

    gateway_file = sock.makefile("r", encoding="utf-8")

    try:
        while True:
            text = input("Gönderilecek mesaj: ").strip()
            if text.lower() in {"q", "quit", "exit"}:
                print("[SENDER] Çıkılıyor...")
                break

            if not text:
                continue

            sock.sendall((text + "\n").encode("utf-8"))

            sock.settimeout(0.2)
            try:
                line = gateway_file.readline()
                if line:
                    print("[GATEWAY MESAJI]", line.strip())
            except Exception:
                pass
            finally:
                sock.settimeout(None)

    except KeyboardInterrupt:
        print("\n[SENDER] Kapatılıyor...")
    finally:
        gateway_file.close()
        sock.close()


def run_receiver():
    print("========================================")
    print("   Endpoint Receiver Agent (PC2)       ")
    print("========================================")
    print(f"{RECEIVER_LISTEN_HOST}:{RECEIVER_LISTEN_PORT} dinleniyor...\n")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((RECEIVER_LISTEN_HOST, RECEIVER_LISTEN_PORT))
    server_sock.listen(1)

    conn, addr = server_sock.accept()
    print("[RECEIVER] Gateway bağlandı:", addr)

    conn_file = conn.makefile("r", encoding="utf-8")

    try:
        for line in conn_file:
            text = line.rstrip("\n")
            if not text:
                continue
            print(f"[RECEIVER] Yeni mesaj: {text}")
    except KeyboardInterrupt:
        print("\n[RECEIVER] Kapatılıyor...")
    finally:
        conn_file.close()
        conn.close()
        server_sock.close()


# ============================================================
# 7) ANA MENÜ
# ============================================================

def run_endpoint_dlp():
    """Clipboard + USB izleme modunu başlatır."""
    usb_observer = usb_monitor()
    clipboard_thread = threading.Thread(target=clipboard_monitor, daemon=True)
    clipboard_thread.start()

    print("---------------------------------------------------------")
    print("--- Mini DLP Endpoint Modu Başlatıldı ---")
    print(f"1. Pano Kontrolü: Aktif")
    print(f"2. USB Kontrolü: Aktif (Klasör: {USB_DIR})")
    print("Kapsam: TCKN, Kredi Kartı, E-posta, IBAN")
    print("Durdurmak için: CTRL+C\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n--- DLP Endpoint Modu Durduruluyor ---")
        usb_observer.stop()
        usb_observer.join()
        print("Durduruldu. Olaylar 'dlp_incidents.csv' dosyasında kayıtlıdır.")


def main_menu():
    print("===================================================")
    print("   Tek Dosyalık DLP Agent Sistemi (Mini Proje)     ")
    print("===================================================")
    print("Mod Seç:")
    print("  1) Endpoint DLP (Clipboard + USB izle)")
    print("  2) Sender Agent (PC1)")
    print("  3) DLP Gateway (Aradaki AI/DLP Agent)")
    print("  4) Receiver Agent (PC2)")
    print("  q) Çık")
    print("===================================================\n")

    choice = input("Seçimin: ").strip().lower()

    if choice == "1":
        run_endpoint_dlp()
    elif choice == "2":
        run_sender()
    elif choice == "3":
        run_gateway()
    elif choice == "4":
        run_receiver()
    elif choice in {"q", "quit", "exit"}:
        print("Çıkılıyor...")
    else:
        print("Geçersiz seçim.")


if __name__ == "__main__":
    main_menu()
