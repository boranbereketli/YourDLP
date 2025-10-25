import re

# Hassas Veri Tiplerini ve Onlara Karşılık Gelen Regex Kurallarını tanımlıyoruz.
# Bir DLP sistemi, metin içindeki bu desenleri arayarak hassas veriyi tespit eder.

DLP_RULES = {
    "TCKN": {
        # TCKN: 11 haneli bir sayı dizisi. (Daha karmaşık matematiksel doğrulamalar yapılabilir, ama bu yeterli.)
        "pattern": r'\b\d{11}\b',
        "description": "11 Haneli TC Kimlik Numarası Formatı"
    },
    "KREDI_KARTI": {
        # Kredi Kartı: 16 hane, aralarında boşluk, tire veya hiçbiri olabilir.
        "pattern": r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
        "description": "16 Haneli Kredi Kartı Numarası Formatı"
    }
}

def scan_content(content):
    """
    Verilen metin içeriğini tüm DLP kurallarına göre tarar.
    """
    incidents = []
    
    for data_type, rule in DLP_RULES.items():
        # re.findall: Kurala uyan tüm eşleşmeleri bul.
        matches = re.findall(rule["pattern"], content)
        
        for match in matches:
            # Bulunan veriyi güvenli bir şekilde kaydetmek için maskeliyoruz (son 4 hane hariç)
            masked_data = f"XXXX-XXXX-XXXX-{match[-4:]}"
            
            incidents.append({
                "data_type": data_type,
                "description": rule["description"],
                "masked_match": masked_data,
                "full_match": match # Gerçek hayatta bu kısım sadece yöneticilere gösterilir.
            })
            
    return incidents

# Basit bir test:
if __name__ == "__main__":
    test_text = "Müşteri TCKN: 12345678901 ve kartı 4000 1234 5678 9010."
    results = scan_content(test_text)
    print("Test Sonuçları:", results)