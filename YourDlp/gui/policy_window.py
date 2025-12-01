from PyQt6.QtWidgets import *
import requests

SERVER = "http://127.0.0.1:5000"

DATA_TYPES = ["TCKN", "IBAN_TR", "KREDI_KARTI", "E_POSTA", "TEL_NO"]


# ======================================================
#  POLICY TAB SINIFI (Clipboard, USB, Network target paneli)
# ======================================================
class PolicyTab(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()
        self.checks = {}

        # Checkboxlar
        for d in DATA_TYPES:
            cb = QCheckBox(d)
            layout.addWidget(cb)
            self.checks[d] = cb

        # Keywords alanı
        layout.addWidget(QLabel("Anahtar Kelimeler (virgülle ayır):"))
        self.keywords = QLineEdit()
        layout.addWidget(self.keywords)

        self.setLayout(layout)

    # Policy → GUI
    def load(self, data: dict):
        for d in DATA_TYPES:
            self.checks[d].setChecked(bool(data.get(d, False)))

        kws = data.get("Keywords", [])
        self.keywords.setText(", ".join(kws))

    # GUI → Policy
    def export(self):
        out = {d: self.checks[d].isChecked() for d in DATA_TYPES}
        kws = [k.strip() for k in self.keywords.text().split(",") if k.strip()]
        out["Keywords"] = kws
        return out



# ======================================================
#  ASIL PENCERE — POLICYWINDOW
# ======================================================
class PolicyWindow(QWidget):
    def __init__(self, vm_id):
        super().__init__()
        self.vm_id = vm_id
        self.setWindowTitle(f"Politika Düzenle — {vm_id}")
        self.setMinimumSize(800, 500)

        main = QVBoxLayout()

        # Tabs
        self.tabs = QTabWidget()

        self.clip_tab = PolicyTab()
        self.usb_tab = PolicyTab()
        self.net_tab = self.build_network_tab()

        self.tabs.addTab(self.clip_tab, "Clipboard")
        self.tabs.addTab(self.usb_tab, "USB")
        self.tabs.addTab(self.net_tab, "Network")

        main.addWidget(self.tabs)

        # Kaydet butonu
        btn = QPushButton("POLİTİKAYI KAYDET")
        btn.clicked.connect(self.save)
        main.addWidget(btn)

        self.setLayout(main)

        # Politika çek
        self.fetch_existing()


    # ===============================================
    # NETWORK PANEL
    # ===============================================
    def build_network_tab(self):
        wrapper = QWidget()
        layout = QHBoxLayout()

        # Sol liste: hedef kullanıcılar
        self.target_list = QListWidget()
        self.target_list.itemSelectionChanged.connect(self.load_target_policy)
        layout.addWidget(self.target_list, 30)

        # Sağ panel: seçili hedefin policy tabı
        self.target_panel = PolicyTab()
        layout.addWidget(self.target_panel, 70)

        wrapper.setLayout(layout)
        return wrapper


    # ===============================================
    # MEVCUT POLİTİKAYI SUNUCUDAN GETİR
    # ===============================================
    def fetch_existing(self):
        try:
            r = requests.get(f"{SERVER}/policies/{self.vm_id}")
            if r.status_code != 200:
                return
            self.raw_policy = r.json()
        except:
            return

        # Clipboard
        self.clip_tab.load(self.raw_policy.get("clipboard", {}))

        # USB
        self.usb_tab.load(self.raw_policy.get("usb", {}))

        # Network hedefleri listeye koy
        self.network_data = self.raw_policy.get("network", {})
        for target in self.network_data.keys():
            self.target_list.addItem(target)


    # ===============================================
    # NETWORK — Seçilen hedefin panelini doldur
    # ===============================================
    def load_target_policy(self):
        item = self.target_list.currentItem()
        if not item:
            return

        target_vm = item.text()
        policy = self.network_data.get(target_vm, {})
        self.target_panel.load(policy)


    # ===============================================
    # GÖNDERİLECEK JSON’U HAZIRLA
    # ===============================================
    def build_final_policy(self):
        final = {
            "clipboard": self.clip_tab.export(),
            "usb": self.usb_tab.export(),
            "network": {}
        }

        # Network hedefleri
        for i in range(self.target_list.count()):
            target = self.target_list.item(i).text()
            final["network"][target] = self.target_panel.export()

        return final


    # ===============================================
    # POLİTIKA KAYDET → SERVER'A POST
    # ===============================================
    def save(self):
        payload = {
            "user_id": self.vm_id,
            "policies": self.build_final_policy()
        }

        try:
            r = requests.post(f"{SERVER}/update_policy", json=payload)
            if r.status_code == 200:
                QMessageBox.information(self, "OK", "Politika güncellendi!")
            else:
                QMessageBox.critical(self, "HATA", "Sunucuya gönderilemedi.")
        except Exception as e:
            QMessageBox.critical(self, "HATA", str(e))
