# policy_window.py (Full and Persistent Saving Features)

from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt
import requests
import json

SERVER = "http://127.0.0.1:5000"

DATA_TYPES = ["TCKN", "IBAN_TR", "CREDIT_CARD", "EMAIL", "PHONE_NO"]


# ======================================================
#  POLICY TAB CLASS (Content for a single tab)
# ======================================================
class PolicyTab(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()
        self.checks = {}

        # Checkboxes (TCKN, IBAN, etc.)
        for d in DATA_TYPES:
            cb = QCheckBox(d)
            layout.addWidget(cb)
            self.checks[d] = cb

        # Keywords section
        layout.addWidget(QLabel("Forbidden Keywords (separate with comma):"))
        self.keywords = QLineEdit()
        self.keywords.setPlaceholderText("e.g.: secret, project, salary")
        layout.addWidget(self.keywords)
        
        layout.addStretch()
        self.setLayout(layout)

    # Policy (Dict) -> GUI
    def load(self, data: dict):
        """ Fills the boxes on the screen with incoming data. """
        if not data: data = {}
        for d in DATA_TYPES:
            # Check if True, uncheck if False or Missing
            self.checks[d].setChecked(bool(data.get(d, False)))

        # Convert Keywords list to text box string
        kws = data.get("Keywords", [])
        if isinstance(kws, list):
            self.keywords.setText(", ".join(kws))
        else:
            self.keywords.setText("")
        
        # Enable interaction
        self.set_controls_enabled(True)

    # GUI -> Policy (Dict)
    def export(self):
        """ Converts the boxes on the screen back into data. """
        out = {d: self.checks[d].isChecked() for d in DATA_TYPES}
        
        # Convert text box back to list
        text = self.keywords.text()
        kws = [k.strip() for k in text.split(",") if k.strip()]
        out["Keywords"] = kws
        
        return out
        
    def set_controls_enabled(self, enabled):
        """ Enable/Disable controls """
        for cb in self.checks.values():
            cb.setEnabled(enabled)
        self.keywords.setEnabled(enabled)


# ======================================================
#  MAIN WINDOW — POLICYWINDOW
# ======================================================
class PolicyWindow(QWidget):
    def __init__(self, vm_id, initial_target=None):
        super().__init__()
        self.vm_id = vm_id
        self.setWindowTitle(f"Edit Policy — {vm_id}")
        self.setMinimumSize(800, 500)
        
        # Data structures
        self.network_data = {}    # { 'target_vm': {TCKN: True...} }
        self.raw_policy = {}      # Raw data from server
        self.current_target_vm = None # Currently selected target in Network tab

        # Layout
        main = QVBoxLayout()

        # Tabs
        self.tabs = QTabWidget()

        self.clip_tab = PolicyTab()
        self.usb_tab = PolicyTab()
        self.net_tab = self.build_network_tab()

        self.tabs.addTab(self.clip_tab, "Clipboard")
        self.tabs.addTab(self.usb_tab, "USB Transfer")
        self.tabs.addTab(self.net_tab, "Network")

        main.addWidget(self.tabs)

        # Save button
        btn_save = QPushButton("💾 SAVE POLICY")
        btn_save.setStyleSheet("font-weight: bold; padding: 10px; background-color: #4CAF50; color: white;")
        btn_save.clicked.connect(self.save)
        main.addWidget(btn_save)

        self.setLayout(main)

        # Fetch data at startup
        self.fetch_existing()

    # ===============================================
    # NETWORK TAB STRUCTURE
    # ===============================================
    def build_network_tab(self):
        wrapper = QWidget()
        layout = QHBoxLayout()

        # Left side: Target List and Buttons
        left_layout = QVBoxLayout()
        
        lbl = QLabel("Target VM List:")
        lbl.setStyleSheet("font-weight: bold")
        left_layout.addWidget(lbl)
        
        self.target_list = QListWidget()
        self.target_list.itemSelectionChanged.connect(self.on_target_selection_change)
        left_layout.addWidget(self.target_list)
        
        btn_add = QPushButton("+ Add Target")
        btn_add.clicked.connect(self.add_new_target)
        left_layout.addWidget(btn_add)
        
        btn_del = QPushButton("- Delete Target")
        btn_del.clicked.connect(self.delete_selected_target)
        left_layout.addWidget(btn_del)
        
        layout.addLayout(left_layout, 30)

        # Right side: Settings for selected target
        right_layout = QVBoxLayout()
        lbl_r = QLabel("Restrictions for Selected Target:")
        lbl_r.setStyleSheet("font-weight: bold")
        right_layout.addWidget(lbl_r)

        self.target_panel = PolicyTab()
        self.target_panel.set_controls_enabled(False) # Initially disabled (no selection)
        right_layout.addWidget(self.target_panel)
        
        layout.addLayout(right_layout, 70)

        wrapper.setLayout(layout)
        return wrapper

    # ===============================================
    # FETCH DATA (GET)
    # ===============================================
    def fetch_existing(self):
        try:
            r = requests.get(f"{SERVER}/policies/{self.vm_id}", timeout=3)
            if r.status_code != 200:
                QMessageBox.critical(self, "Error", "Policy could not be fetched from the server.")
                return
            self.raw_policy = r.json()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not connect to server: {e}")
            return

        # 1. Load Clipboard
        self.clip_tab.load(self.raw_policy.get("clipboard", {}))

        # 2. Load USB
        self.usb_tab.load(self.raw_policy.get("usb", {}))

        # 3. Load Network Data to memory and fill the list
        net_data = self.raw_policy.get("network", {})
        if isinstance(net_data, dict):
            self.network_data = net_data
        else:
            self.network_data = {}

        self.target_list.clear()
        
        if self.network_data:
            for target in self.network_data.keys():
                self.target_list.addItem(target)
        
        # No selection yet, clear panel
        self.target_panel.load({})
        self.target_panel.set_controls_enabled(False)


    # ===============================================
    # NETWORK LOGIC
    # ===============================================
    
    def on_target_selection_change(self):
        """ Runs when a new target is selected from the list. """
        # 1. Save the previous selection (if it exists)
        if self.current_target_vm and self.current_target_vm in self.network_data:
            self.network_data[self.current_target_vm] = self.target_panel.export()

        # 2. Find the new selection
        item = self.target_list.currentItem()
        if not item:
            self.current_target_vm = None
            self.target_panel.load({})
            self.target_panel.set_controls_enabled(False)
            return

        target_vm = item.text()
        self.current_target_vm = target_vm
        
        # 3. Load its data into the panel
        policy = self.network_data.get(target_vm, {})
        self.target_panel.load(policy)


    def add_new_target(self):
        """ Adds a new target to the list. """
        target_vm_id, ok = QInputDialog.getText(self, "New Target", "Enter Target VM ID (e.g.: vm_user_2):")
        if ok and target_vm_id:
            target_vm_id = target_vm_id.strip()
            if not target_vm_id: return
            
            if target_vm_id == self.vm_id:
                QMessageBox.warning(self, "Error", "You cannot add yourself as a target.")
                return
                
            if target_vm_id in self.network_data:
                QMessageBox.warning(self, "Error", "This target is already in the list.")
                return

            # Initialize with default restrictions (All Blocked)
            default_rules = {d: True for d in DATA_TYPES}
            default_rules["Keywords"] = []
            
            self.network_data[target_vm_id] = default_rules
            self.target_list.addItem(target_vm_id)
            
            # Select the newly added item
            self.target_list.setCurrentRow(self.target_list.count() - 1)

    def delete_selected_target(self):
        """ Deletes the selected target from the list and dictionary. """
        item = self.target_list.currentItem()
        if not item: return

        target_vm = item.text()
        res = QMessageBox.question(self, "Confirmation", f"Are you sure you want to delete '{target_vm}' target?\n(Traffic to this target will no longer be inspected.)", 
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if res == QMessageBox.StandardButton.Yes:
            # Delete from dictionary
            if target_vm in self.network_data:
                del self.network_data[target_vm]
            
            # Delete from list
            row = self.target_list.currentRow()
            self.target_list.takeItem(row)
            
            self.current_target_vm = None
            self.target_panel.load({})
            self.target_panel.set_controls_enabled(False)

    # ===============================================
    # SAVE PROCESS
    # ===============================================
    def save(self):
        """ Collects all data and POSTs it to the server. """
        
        # 1. Capture the last pending change in the Network tab
        if self.current_target_vm and self.current_target_vm in self.network_data:
            self.network_data[self.current_target_vm] = self.target_panel.export()

        # 2. Prepare the final package
        final_policy = {
            "clipboard": self.clip_tab.export(),
            "usb": self.usb_tab.export(),
            "network": self.network_data
        }
        
        payload = {
            "user_id": self.vm_id,
            "policies": final_policy
        }
        
        # 3. Send to server
        try:
            r = requests.post(f"{SERVER}/update_policy", json=payload, timeout=5)
            if r.status_code == 200:
                QMessageBox.information(self, "Success", "✅ Policy updated and saved to server.")
                self.close()
            else:
                QMessageBox.critical(self, "Error", f"Save failed. Server error: {r.status_code}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not reach server: {e}")