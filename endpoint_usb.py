import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dlp_rules import scan_content
import os
import shutil
from endpoint_clipboard import log_incident # Loglama fonksiyonunu paylaşıyoruz

# --- Simüle Edilmiş USB ve Karantina Alanı ---
USB_DIR = "SIM_USB_SURUCU"
QUARANTINE_DIR = "KARANTINA_ALANI"
if not os.path.exists(USB_DIR): os.makedirs(USB_DIR)
if not os.path.exists(QUARANTINE_DIR): os.makedirs(QUARANTINE_DIR)


class USBFileHandler(FileSystemEventHandler):
    """
    SIM_USB_SURUCU klasöründe yeni dosya oluştuğunda tetiklenir.
    """
    def on_created(self, event):
        if event.is_directory:
            return
        
        file_path = event.src_path
        file_name = os.path.basename(file_path)
        print(f"\n[USB İzleyici] Yeni dosya kopyalandı: {file_name}")

        try:
            # Sadece metin dosyalarını kontrol ediyoruz (simülasyonu basit tutmak için)
            if file_name.endswith(('.txt')):
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Hassas veri taraması
                incidents = scan_content(content)
                
                if incidents:
                    # Hassas veri bulundu, Engelleme Aksiyonu!
                    data_type = incidents[0]['data_type']
                    masked_match = incidents[0]['masked_match']
                    
                    # Loglama yap
                    log_incident("USB Transferi", data_type, "ENGEL - Karantina", f"{file_name} -> {masked_match}")
                    
                    # ENGELLEME SİMÜLASYONU: Dosyayı karantinaya taşı
                    new_path = os.path.join(QUARANTINE_DIR, file_name)
                    shutil.move(file_path, new_path)
                    print(f"!!! DİKKAT: Hassas Veri Tespit Edildi. Dosya Karantinaya Taşındı: {new_path} !!!")

                else:
                    print(f"[USB İzleyici] Dosya ({file_name}) temiz. Kopyalama başarılı.")

        except Exception as e:
            log_incident("USB Transferi", "Hata", "İşlenmedi", f"Dosya okuma hatası: {file_name}. Hata: {e}")


def usb_monitor():
    print(f"--- USB İzleyici Başlatıldı (Klasör: {USB_DIR}) ---")
    print("Test etmek için bu klasöre bir .txt dosyası kopyalayın.")
    
    event_handler = USBFileHandler()
    observer = Observer()
    observer.schedule(event_handler, USB_DIR, recursive=False)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n--- USB İzleyici Durduruldu ---")
        
    observer.join()

if __name__ == "__main__":
    usb_monitor()