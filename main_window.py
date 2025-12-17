import sys
import requests
import json
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

# Other modules
from user_form import AddUserDialog
from policy_window import PolicyWindow

SERVER = "http://127.0.0.1:5000"

DATA_TYPES = ["TCKN", "IBAN_TR", "CREDIT_CARD", "E_MAIL", "PHONE_NO"]

# =====================================================
# LOG VIEWER DIALOG
# =====================================================

class LogViewerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("System Logs and Violations")
        self.resize(1100, 600)
        
        self.setStyleSheet("background-color: #f4f6f9;") 
        
        layout = QVBoxLayout(self)
        
        # Info Label
        lbl_info = QLabel("🔎 Below is a list of all DLP events and blocks occurring in the system.")
        lbl_info.setStyleSheet("color: #555; font-size: 14px; margin-bottom: 5px; font-weight: bold;")
        layout.addWidget(lbl_info)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Date", "Event Type", "Data Type", "Action", "Details"])
        
        # Table Settings
        self.table.setAlternatingRowColors(True) 
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows) 
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers) 
        
        # Column Widths
        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(1, 150)
        self.table.setColumnWidth(2, 120)
        self.table.setColumnWidth(3, 200)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.table)
        
        # Close Button
        btn_close = QPushButton("Close")
        btn_close.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close, alignment=Qt.AlignmentFlag.AlignRight)
        
        self.load_logs()

    def load_logs(self):
        self.table.setRowCount(0)
        try:
            # Fetch data from server
            r = requests.get(f"{SERVER}/all_logs", timeout=3)
            if r.status_code == 200:
                data = r.json()
                logs = data.get("logs", [])
                
                self.table.setRowCount(len(logs))
                for row_idx, log in enumerate(logs):
                    items = [
                        log.get("Date", ""),
                        log.get("Event_Type", ""),
                        log.get("Data_Type", ""),
                        log.get("Action", ""),
                        log.get("Details", "")
                    ]
                    
                    for col_idx, text in enumerate(items):
                        item = QTableWidgetItem(str(text))
                        
                        # Highlighting logic for Actions
                        # Note: We keep "ENGEL" and "İZİN" check if server returns Turkish, 
                        # but we change display style accordingly.
                        if "ENGEL" in items[3] or "BLOCK" in items[3].upper():  
                            item.setBackground(QColor("#ffebee")) # Light Red
                            if col_idx == 3: 
                                item.setForeground(QColor("#c62828")) # Dark Red
                                item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
                                
                        elif "İZİN" in items[3] or "ALLOW" in items[3].upper():
                            item.setBackground(QColor("#e8f5e9")) # Light Green
                            if col_idx == 3: 
                                item.setForeground(QColor("#2e7d32")) # Dark Green
                                item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
                        
                        self.table.setItem(row_idx, col_idx, item)
            else:
                QMessageBox.warning(self, "Error", "Logs could not be retrieved from the server.")
        except Exception as e:
            QMessageBox.critical(self, "Connection Error", f"Could not connect to server: {str(e)}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("YourDLP Manager")
        self.setMinimumSize(900, 650)
        
        # Main Style (CSS)
        self.setStyleSheet("""
            QMainWindow { background-color: #f4f6f9; }
            QLabel { font-family: 'Segoe UI', sans-serif; font-size: 14px; color: #333; }
            QPushButton {
                font-family: 'Segoe UI', sans-serif;
                font-size: 14px;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
                color: white;
                border: none;
            }
            QPushButton:hover { opacity: 0.9; }
            QListWidget {
                background-color: white;
                border-radius: 8px;
                border: 1px solid #dce4ec;
                font-size: 14px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 12px;
                border-bottom: 1px solid #eee;
                color: #333;
            }
            QListWidget::item:selected {
                background-color: #e3f2fd;
                color: #0d47a1;
                border-radius: 6px;
            }
        """)

        central = QWidget()
        self.layout = QVBoxLayout(central)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(20)
        
        # 1. HEADER
        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border-radius: 12px;
                border: 1px solid #e0e0e0;
            }
        """)
        header_lay = QHBoxLayout(header_frame)
        header_lay.setContentsMargins(25, 20, 25, 20)

        # Title and Status
        title_lay = QVBoxLayout()
        lbl_title = QLabel("🛡️ <b>DLP Policy Manager</b>")
        lbl_title.setStyleSheet("font-size: 22px; color: #1a237e;")
        
        self.lbl_server_status = QLabel("Server Status: Checking...")
        self.lbl_server_status.setStyleSheet("color: gray; font-size: 13px;")
        
        title_lay.addWidget(lbl_title)
        title_lay.addWidget(self.lbl_server_status)
        
        header_lay.addLayout(title_lay)
        header_lay.addStretch()

        # Log Button (Orange)
        btn_logs = QPushButton("📜 System Logs")
        btn_logs.setStyleSheet("background-color: #f57f17; margin-right: 10px;")
        btn_logs.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_logs.clicked.connect(self.open_logs)
        header_lay.addWidget(btn_logs)

        # Refresh Button (Greyish)
        btn_refresh = QPushButton("🔄 Refresh")
        btn_refresh.setStyleSheet("background-color: #607d8b;")
        btn_refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_refresh.clicked.connect(self.load_existing_users)
        header_lay.addWidget(btn_refresh)

        self.layout.addWidget(header_frame)
        
        # 2. USER LIST
        group_box = QGroupBox("Registered Users (VM)")
        group_box.setStyleSheet("QGroupBox { font-weight: bold; font-size: 15px; color: #444; }")
        group_lay = QVBoxLayout(group_box)

        self.user_list = QListWidget()
        self.user_list.setAlternatingRowColors(True)
        group_lay.addWidget(self.user_list)
        
        self.layout.addWidget(group_box)
        
        # 3. ACTION BUTTONS
        action_frame = QFrame()
        action_lay = QHBoxLayout(action_frame)
        action_lay.setContentsMargins(0, 10, 0, 10)
        action_lay.setSpacing(15)

        # Add Button (Green)
        btn_add = QPushButton("➕ Add New User")
        btn_add.setStyleSheet("background-color: #2e7d32; padding: 12px 25px;")
        btn_add.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_add.clicked.connect(self.add_user)

        # Edit Button (Blue)
        btn_edit = QPushButton("📝 Edit Policy")
        btn_edit.setStyleSheet("background-color: #1565c0; padding: 12px 25px;")
        btn_edit.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_edit.clicked.connect(self.edit_policy)

        # Delete Button (Red)
        btn_del = QPushButton("🗑️ Delete")
        btn_del.setStyleSheet("background-color: #c62828; padding: 12px 25px;")
        btn_del.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_del.clicked.connect(self.delete_user)

        action_lay.addWidget(btn_add)
        action_lay.addWidget(btn_edit)
        action_lay.addStretch() 
        action_lay.addWidget(btn_del)
        
        self.layout.addWidget(action_frame)

        self.setCentralWidget(central)
        
        # Initial load
        self.load_existing_users()

    # =====================================================
    # LOGIC
    # =====================================================
    def load_existing_users(self):
        """Fetches and lists users from the server."""
        self.user_list.clear()
        try:
            r = requests.get(f"{SERVER}/users", timeout=2)
            if r.status_code == 200:
                self.lbl_server_status.setText("Server Status: ✅ Online")
                self.lbl_server_status.setStyleSheet("color: green; font-weight: bold;")
                
                users = r.json().get("users", [])
                if not users:
                    self.user_list.addItem("⚠️ No registered users found.")
                    return

                for vm_id in users:
                    display_text = f"👤  {vm_id}  |  DLP Agent  |  (127.0.0.1)"
                    item = QListWidgetItem(display_text)
                    item.setData(Qt.ItemDataRole.UserRole, {
                        "vm_id": vm_id,
                        "ip": "127.0.0.1",
                        "port": 9101,
                        "name": "(Registered)"
                    })
                    self.user_list.addItem(item)
            else:
                self.set_server_error(f"Error Code: {r.status_code}")
                
        except requests.exceptions.ConnectionError:
            self.set_server_error("No Connection")
        except Exception as e:
             self.set_server_error(str(e))

    def set_server_error(self, msg):
        self.lbl_server_status.setText(f"Server Status: ❌ {msg}")
        self.lbl_server_status.setStyleSheet("color: red; font-weight: bold;")
        self.user_list.addItem("❌ Server unreachable. Please start server.py.")

    def create_default_policy(self, vm_id):
        """Creates a default policy for a new user."""
        default_restrictions = {d: False for d in DATA_TYPES} 
        default_restrictions["Keywords"] = []
        
        default_policy = {
            "clipboard": default_restrictions.copy(), 
            "usb":       default_restrictions.copy(),  
            "network":   {}, 
        }
        
        payload = {"user_id": vm_id, "policies": default_policy}
        try:
            requests.post(f"{SERVER}/update_policy", json=payload, timeout=2)
            QMessageBox.information(self, "Success", f"Default policy created for '{vm_id}'.")
        except:
            QMessageBox.warning(self, "Warning", "Default policy could not be sent to server (can be edited later).")

    def add_user(self):
        dialog = AddUserDialog(self)
        if dialog.exec():
            vm_id, ip = dialog.get_data()
            
            if not vm_id:
                QMessageBox.warning(self, "Warning", "Please enter a valid VM ID.")
                return
            
            item = QListWidgetItem(f"👤  {vm_id}  |  IP: {ip}")
            item.setData(Qt.ItemDataRole.UserRole, {
                "vm_id": vm_id, 
                "ip": ip
            })
            self.user_list.addItem(item)
    
            self.create_default_policy(vm_id)
            self.load_existing_users()

    def delete_user(self):
        selected_items = self.user_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a user to delete.")
            return
        
        item = selected_items[0]
        data = item.data(Qt.ItemDataRole.UserRole)
        if not data: return 

        vm_id = data["vm_id"]
        
        reply = QMessageBox.question(self, 'Confirm Deletion', 
                                     f"Are you sure you want to delete user '{vm_id}' and their policies?", 
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                                     QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            try:
                # Delete from server
                requests.post(f"{SERVER}/delete_policy/{vm_id}", timeout=2)
                # Remove from list
                self.user_list.takeItem(self.user_list.row(item))
                QMessageBox.information(self, "Deleted", "User successfully deleted.")
            except:
                QMessageBox.critical(self, "Error", "An error occurred while deleting from the server.")

    def edit_policy(self):
        selected_items = self.user_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a user to edit.")
            return

        item = selected_items[0]
        data = item.data(Qt.ItemDataRole.UserRole)
        if not data: return

        vm_id = data["vm_id"]
        
        # Open Policy Window
        self.policy_win = PolicyWindow(vm_id)
        self.policy_win.show()

    def open_logs(self):
        """Opens the log viewer dialog."""
        dialog = LogViewerDialog(self)
        dialog.exec()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec())