import time
import pyperclip
from dlp_rules import scan_content
import os

# --- Loglama (Olay Kaydı) Fonksiyonu ---
def log_incident(event_type, data_type, action, details):
    """
    DLP olaylarını tek bir CSV dosyasına kaydeder.
    """
    with open("dlp_incidents.csv", "a") as f:
        # Tarih, Olay Tipi, Hassas Veri Tipi, Aksiyon, Detay
        log_line = f"{time.strftime('%Y-%m-%d %H:%M:%S')},{event_type},{data_type},{action},{details}\n"
        f.write(log_line)
        print(f"\n[!!! DLP OLAYI KAYDEDİLDİ !!!] - {data_type} tespiti. Aksiyon: {action}\n")

# --- Pano İzleyici Fonksiyonu ---
def clipboard_monitor():
    print("--- Pano İzleyici Başlatıldı (CTRL+C ile durdurun) ---")
    last_clipboard_content = ""
    
    while True:
        try:
            # 1. Pano içeriğini al
            current_clipboard_content = pyperclip.paste()

            # Yeni bir kopyalama yapılmışsa kontrol et
            if current_clipboard_content != last_clipboard_content and current_clipboard_content:
                
                # 2. Hassas veri taraması yap
                incidents = scan_content(current_clipboard_content)
                
                if incidents:
                    # 3. Hassas veri bulundu, Engelleme Aksiyonu!
                    
                    # Loglama yap
                    log_incident("Pano Kopyalama", incidents[0]['data_type'], "ENGEL - Pano Temizlendi", incidents[0]['masked_match'])
                    
                    # ENGELLEME SİMÜLASYONU: Panoyu temizle
                    pyperclip.copy("")
                    print("!!! DİKKAT: Hassas Veri Tespit Edildi ve Kopyalama Engellendi. Pano Temizlendi. !!!")
                    
                last_clipboard_content = pyperclip.paste() # Pano temizlenmiş hali
            
            time.sleep(1) # Her saniye kontrol et

        except KeyboardInterrupt:
            print("\n--- Pano İzleyici Durduruldu ---")
            break
        except Exception as e:
            # Bazen pano erişiminde hatalar olabilir (özellikle Linux'ta)
            print(f"Bir hata oluştu: {e}")
            time.sleep(5)
            
if __name__ == "__main__":
    # Eğer dlp_incidents.csv yoksa, başlık satırını ekle
    if not os.path.exists("dlp_incidents.csv"):
        with open("dlp_incidents.csv", "w") as f:
            f.write("Tarih,Olay_Tipi,Veri_Tipi,Aksiyon,Detay\n")
            
    clipboard_monitor()