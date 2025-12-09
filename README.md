
# 🛡️ YourDLP — Data Loss Prevention (DLP) System  
Comprehensive Clipboard • USB • Network Protection with Central Policy Server

YourDLP, kurum içi veri sızıntılarını gerçek zamanlı olarak önlemek için geliştirilmiş uçtan uca bir **Data Loss Prevention (DLP)** çözümüdür.  
Sistem; pano (clipboard), USB dosya aktiviteleri ve ağ mesaj trafiğini merkezi bir politika sunucusundan aldığı kurallara göre denetler.

---

## 🚀 Özellikler

### 🖥️ Central Policy Server (Flask)
- Kullanıcı bazlı politikaları JSON dosyasında yönetir  
- Tüm olayları `dlp_incidents.csv` dosyasına kaydeder  
- REST API sağlar:  
  - `/policies/<user>`  
  - `/update_policy`  
  - `/log_incident`  
  - `/all_logs`

### 📡 Network Gateway
- Agent’lar arası mesaj trafiğini karşılar  
- Mesaj içeriğini dinamik anahtar kelimeler ve veri tipleri ile tarar  
- Hedef kullanıcıya özel network politikalarını uygular  
- Engellenen mesajları loglar

### 🧩 Unified Agent (PyQt6)
#### 📋 Clipboard DLP
- TC, IBAN, KK, telefon, e-posta ve dinamik anahtar kelime tespiti  
- Yasaklı içerik panodan otomatik silinir  
- Olay politikaya göre işlenir ve sunucuya raporlanır  

#### 💾 USB DLP
- USB’ye kopyalanan tüm dosyalar gerçek zamanlı taranır  
- Hassas veri bulunursa dosya otomatik karantinaya alınır  
- Desteklenen formatlar: txt, csv, docx, pdf, xlsx, pptx  

#### 🌐 Güvenli Chat + Network DLP
- Agent'lar arası güvenli mesajlaşma  
- Her mesaj sunucu tarafından politikaya göre doğrulanır  
- Yasaklı içerik tespit edilirse iletim engellenir  

#### 🖥️ GUI Özellikleri
- Güvenli Sohbet ekranı  
- DLP olay günlüğü  
- Politika görüntüleyici  
- Tray icon desteği  

---

## 📁 Proje Yapısı

```
YourDLP/
│
├── server.py              # Merkez Sunucu + Network Gateway
├── unified_agent.py       # Agent uygulaması (GUI + Workers)
├── YOUR_DLP_LIB.py        # DLP motoru: regex, karantina, dosya okuma
├── policies.json          # Kullanıcı politikaları
├── dlp_incidents.csv      # Olay logları
├── config.json            # Agent konfigürasyonu
│
├── main_window.py         # Yönetim paneli
├── policy_window.py       # Politika düzenleme ekranı
├── user_form.py           # Yönetim paneli kullanıcı formu
├── styles.qss             # GUI teması
│
└── README.md
```

---

## 🔧 Kurulum

### 1. Gerekli bağımlılıkları yükleyin

```bash
pip install -r requirements.txt
```

### 2. Sunucuyu başlatın

```bash
python server.py
```

### 3. Agent uygulamasını başlatın

```bash
python unified_agent.py
```

Agent açıldığında VM ID ister.  
Bu ID, `policies.json` içerisinde tanımlı olmalıdır.

---

## 🧠 Politika Sistemi

### Örnek politika:
```json
{
  "clipboard": {
    "TCKN": true,
    "IBAN_TR": true,
    "KREDI_KARTI": true,
    "E_POSTA": false,
    "TEL_NO": false,
    "Keywords": ["gizli", "proje"]
  },
  "usb": {
    "TCKN": true,
    "IBAN_TR": true,
    "KREDI_KARTI": true,
    "E_POSTA": false,
    "TEL_NO": false
  },
  "network": {
    "vm_user_2": {
      "TCKN": true,
      "Keywords": ["domates"]
    }
  }
}
```

---

## 🔍 Loglama Formatı

`dlp_incidents.csv`:

| Tarih | Olay Tipi | Veri Tipi | Aksiyon | Detay |
|------|-----------|-----------|---------|--------|

Örnek:

```
2025-12-09 14:33:21, PANO, TCKN, ENGEL, TC: ******1234
```

---

## 🏁 Çalışma Mantığı

1. Agent başlar, sunucudan politikaları çeker  
2. Clipboard / USB watcher başlatılır  
3. Kullanıcı mesaj gönderdiğinde içerik taranır  
4. Engellenirse:  
   - İşlem durdurulur  
   - Log oluşturulur  
   - Kullanıcı bilgilendirilir  
5. İzinliyse işlem gerçekleştirilir  

---

## 🔐 Güvenlik Özeti

- Hassas veri tespiti (regex + checksum doğrulama)  
- Dinamik anahtar kelime taraması  
- Karantina mekanizması  
- Uç nokta → sunucu olay raporlama  
- Network policy enforcement  

---

## 📜 Lisans

Bu proje sahibine aittir.

---

## 🤝 Katkı

Pull request ve issue’lara açıktır.

