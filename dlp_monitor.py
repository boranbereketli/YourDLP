import time
import os
import shutil
import pyperclip
import threading
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- 1. GENİŞLETİLMİŞ DLP KURALI TANIMLARI ---

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
        # Basit e-posta adresi formatı
        "pattern": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "description": "E-posta Adresi Formatı"
    },
    "IBAN_TR": {
        # TRxx ile başlayan Türk IBAN formatı
        "pattern": r'TR\d{2}[A-Z0-9]{4}\s?(\d{4}\s?){4}\d{2}',
        "description": "Türk IBAN Numarası Formatı"
    }
}

def scan_content(content):
    """
    Verilen metin içeriğini tüm DLP kurallarına göre tarar ve bulunan olayları döndürür.
    """
    incidents = []
    for data_type, rule in DLP_RULES.items():
        matches = re.findall(rule["pattern"], content)
        for match in matches:
            # Maskeleme: Kural tipine göre sonu maskelenir.
            if data_type in ["TCKN", "KREDI_KARTI", "IBAN_TR"]:
                # Son 4 karakteri göster, kalanı X ile gizle
                masked_data = f"XXXX...{match.replace(' ', '')[-4:]}"
            else:
                # E-posta gibi uzun veriler için sadece tipini belirt
                masked_data = f"<{data_type} tespit edildi>"

            incidents.append({
                "data_type": data_type,
                "description": rule["description"],
                "masked_match": masked_data
            })
    return incidents

# --- 2. LOGLAMA (Olay Kaydı) FONKSİYONU ---

def log_incident(event_type, data_type, action, details):
    """
    DLP olaylarını tek bir CSV dosyasına kaydeder ve ekrana bilgi basar.
    Excel uyumluluğu için 'utf-8-sig' kodlaması kullanıldı.
    PermissionError'a karşı korumalı hale getirildi.
    """
    
    log_line = f"{time.strftime('%Y-%m-%d %H:%M:%S')},{event_type},{data_type},{action},{details}\n"
    
    try:
        # dlp_incidents.csv yoksa başlık satırını ekle
        if not os.path.exists("dlp_incidents.csv"):
            with open("dlp_incidents.csv", "w", encoding='utf-8-sig') as f:
                f.write("Tarih,Olay_Tipi,Veri_Tipi,Aksiyon,Detay\n")
        
        # Yeni olayı kaydet
        with open("dlp_incidents.csv", "a", encoding='utf-8-sig') as f:
            f.write(log_line)
            
        print(f"\n[!!! DLP OLAYI KAYDEDİLDİ !!!] - {data_type} tespiti. Aksiyon: {action}")
        print(f"Olay Tipi: {event_type} | Detay: {details}\n")

    except PermissionError:
        # Eğer dosya kilitliyse (Excel'de açıksa) burası çalışır
        print(f"\n[!!! LOGLAMA BAŞARISIZ !!!] - Dosya kilitli (Excel'de açık mı?)")
        print(f"Olay (Kaydedilemedi): {log_line}")
    except Exception as e:
        # Diğer olası hatalar için
        print(f"\n[!!! LOGLAMA HATASI !!!] - {e}")

# --- 3. UÇ NOKTA AYARLARI ve Klasör Hazırlığı ---

USB_DIR = "SIM_USB_SURUCU"
QUARANTINE_DIR = "KARANTINA_ALANI"
# Klasörler yoksa oluşturulur
if not os.path.exists(USB_DIR): os.makedirs(USB_DIR)
if not os.path.exists(QUARANTINE_DIR): os.makedirs(QUARANTINE_DIR)

# --- 4. PANO (CLIPBOARD) İZLEYİCİ MODÜLÜ ---

def clipboard_monitor():
    """Kopyala-Yapıştır eylemlerini izler ve hassas veriyi engeller."""
    print("[MODÜL 1] Pano İzleyici Aktif. Kopyala-Yapıştır eylemleri izleniyor.")
    last_clipboard_content = ""
    
    while True:
        try:
            current_clipboard_content = pyperclip.paste()

            if current_clipboard_content != last_clipboard_content and current_clipboard_content:
                
                incidents = scan_content(current_clipboard_content)
                
                if incidents:
                    # **Ek Özellik: Eşik Kontrolü Simülasyonu**
                    # Eğer panoya 2'den fazla farklı hassas veri tipi kopyalandıysa
                    detected_types = {i['data_type'] for i in incidents}
                    
                    if len(detected_types) >= 2:
                        risk_level = "YÜKSEK RİSK - Çoklu Veri Sızıntısı"
                    else:
                        risk_level = "ENGEL - Pano Temizlendi"
                        
                    data_type = ", ".join(detected_types) # Tüm tipleri log'a ekle
                    masked_match = incidents[0]['masked_match'] # Sadece ilkini log'a ekle

                    log_incident("Pano Kopyalama", data_type, risk_level, masked_match)
                    
                    # ENGELLEME AKSİYONU
                    pyperclip.copy("Bu içerik hassas veri içerdiği için DLP tarafından engellenmiştir.")
                    
                last_clipboard_content = pyperclip.paste()
            
            time.sleep(0.5)

        except Exception as e:
            time.sleep(5)


# --- 5. USB (DOSYA HAREKETİ) İZLEYİCİ MODÜLÜ SINIFI ---

class USBFileHandler(FileSystemEventHandler):
    """
    SIM_USB_SURUCU klasöründe (Simüle edilmiş USB) yeni dosya oluştuğunda tetiklenir.
    """
    def on_created(self, event):
        if event.is_directory:
            return
        
        file_path = event.src_path
        file_name = os.path.basename(file_path)
        print(f"\n[MODÜL 2] Yeni dosya kopyalandı: {file_name}. İçerik taranıyor...")

        try:
            # Sadece .txt uzantılı dosyaları kontrol ediyoruz
            if file_name.endswith('.txt'):
                time.sleep(0.1) # Dosyanın yazılmasının tamamlanmasını bekle
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                incidents = scan_content(content)
                
                if incidents:
                    # Hassas veri bulundu: KARANTİNA!
                    detected_types = {i['data_type'] for i in incidents}
                    data_type = ", ".join(detected_types)
                    masked_match = incidents[0]['masked_match']

                    log_incident("USB Transferi", data_type, "ENGEL - Karantina", f"{file_name} -> {masked_match}")
                    
                    # ENGELLEME AKSİYONU
                    new_path = os.path.join(QUARANTINE_DIR, file_name)
                    shutil.move(file_path, new_path)
                    print(f"!!! Dosya karantinaya taşındı: {new_path} !!!")

                else:
                    print(f"[MODÜL 2] Dosya ({file_name}) temiz. Kopyalama başarılı.")
            else:
                 print(f"[MODÜL 2] '{file_name}' desteklenmeyen dosya tipi. (Pas Geçildi)")

        except Exception as e:
            log_incident("USB Transferi", "Hata", "İşlenmedi", f"Dosya işleme hatası: {e}")

def usb_monitor():
    """USB izleme hizmetini başlatır ve döndürür."""
    event_handler = USBFileHandler()
    observer = Observer()
    observer.schedule(event_handler, USB_DIR, recursive=False)
    observer.start()
    return observer


# --- 6. ANA BAŞLATICI FONKSİYONU ---

if __name__ == "__main__":
    
    # Modül 2'yi (USB İzleyici) başlat
    usb_observer = usb_monitor()
    
    # Modül 1'i (Pano İzleyici) ayrı bir iş parçacığında başlat
    clipboard_thread = threading.Thread(target=clipboard_monitor, daemon=True)
    clipboard_thread.start()
    
    print("---------------------------------------------------------")
    print("--- Mini DLP: Gelişmiş Modüller Başlatıldı ---")
    print(f"1. Pano Kontrolü: Aktif")
    print(f"2. USB Kontrolü: Aktif (Klasör: {USB_DIR})")
    print("Yeni Kapsam: TCKN, Kredi Kartı, E-posta, IBAN")
    print("Durdurmak için: Terminale gelin ve CTRL+C tuşlarına basın.")
    print("---------------------------------------------------------")
    
    try:
        # Ana thread'i açık tutar
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n--- DLP Sistemi Durduruluyor ---")
        
        # Temiz durdurma
        usb_observer.stop()
        usb_observer.join()
        
        print("Durduruldu. Tüm olaylar 'dlp_incidents.csv' dosyasında kayıtlıdır.")