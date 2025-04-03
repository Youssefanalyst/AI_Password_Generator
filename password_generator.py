# quantum_password_manager.py
import sys
import random
import string
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, 
    QHBoxLayout, QLabel, QPushButton, QTabWidget, 
    QLineEdit, QCheckBox, QSpinBox, QListWidget, 
    QMessageBox, QProgressBar, QListWidgetItem
)
from PyQt6.QtGui import QIcon
from cryptography.fernet import Fernet
import numpy as np
import qdarktheme
from datetime import datetime
import json
import os
from PyQt6.QtCore import Qt
import tensorflow as tf
from transformers import GPT2LMHeadModel, GPT2Tokenizer
import torch

class QuantumPasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Quantum Password Manager with AI")
        self.setGeometry(100, 100, 900, 700)
        self.setWindowIcon(QIcon('icon.png'))
        
        # Initialize components
        self.vault_file = "quantum_vault.db"
        self.key = self._initialize_key()
        self.password_history = []
        
        # Load AI models
        self.load_ai_models()
        
        # Setup UI
        self.init_ui()
        qdarktheme.setup_theme("dark")
    
    def load_ai_models(self):
        """Load AI models for password generation"""
        try:
            # Load GPT-2 for AI password generation
            self.tokenizer = GPT2Tokenizer.from_pretrained("gpt2")
            self.gpt_model = GPT2LMHeadModel.from_pretrained("gpt2")
            self.ai_available = True
        except Exception as e:
            print(f"AI models could not be loaded: {str(e)}")
            self.ai_available = False
    
    def _initialize_key(self):
        """Initialize or load encryption key"""
        if os.path.exists(self.vault_file):
            try:
                with open(self.vault_file, 'r') as f:
                    data = json.load(f)
                    return data['key'].encode()
            except:
                return self._generate_new_key()
        return self._generate_new_key()
    
    def _generate_new_key(self):
        """Generate new encryption key"""
        key = Fernet.generate_key()
        self._save_vault({'key': key.decode(), 'passwords': []})
        return key
    
    def _save_vault(self, data):
        """Save vault data to file"""
        with open(self.vault_file, 'w') as f:
            json.dump(data, f, indent=4)
    
    def init_ui(self):
        """Initialize user interface"""
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # Create tabs
        self.tabs.addTab(self.create_generator_tab(), "🔐 Generator")
        self.tabs.addTab(self.create_vault_tab(), "🗄️ Vault")
        
        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")

    def create_generator_tab(self):
        """Create password generator tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Password length
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 128)
        self.length_spin.setValue(24)
        
        # Generation options
        self.quantum_check = QCheckBox("Quantum Entropy")
        self.quantum_check.setChecked(True)
        self.ai_check = QCheckBox("AI Generation (GPT-2)")
        self.ai_check.setChecked(True)
        self.ai_check.setEnabled(self.ai_available)
        
        if not self.ai_available:
            self.ai_check.setToolTip("AI models not available - using simulation")
        
        # Character options
        self.upper_check = QCheckBox("Uppercase (A-Z)")
        self.upper_check.setChecked(True)
        self.lower_check = QCheckBox("Lowercase (a-z)")
        self.lower_check.setChecked(True)
        self.digits_check = QCheckBox("Digits (0-9)")
        self.digits_check.setChecked(True)
        self.symbols_check = QCheckBox("Symbols (!@#$%)")
        self.symbols_check.setChecked(True)
        
        # Note field
        self.note_input = QLineEdit()
        self.note_input.setPlaceholderText("Add note about this password...")
        
        # Generate buttons
        btn_layout = QHBoxLayout()
        generate_btn = QPushButton("Generate Password")
        generate_btn.clicked.connect(self.generate_password)
        ai_generate_btn = QPushButton("Generate with AI")
        ai_generate_btn.clicked.connect(self.generate_ai_password)
        ai_generate_btn.setEnabled(self.ai_available)
        
        btn_layout.addWidget(generate_btn)
        btn_layout.addWidget(ai_generate_btn)
        
        # Password display
        self.password_display = QLineEdit()
        self.password_display.setReadOnly(True)
        
        # Strength meter
        self.strength_bar = QProgressBar()
        self.strength_label = QLabel("Strength: 0%")
        
        # Layout
        options_layout = QVBoxLayout()
        options_layout.addWidget(QLabel("Password Length:"))
        options_layout.addWidget(self.length_spin)
        options_layout.addWidget(self.quantum_check)
        options_layout.addWidget(self.ai_check)
        
        char_layout = QVBoxLayout()
        char_layout.addWidget(self.upper_check)
        char_layout.addWidget(self.lower_check)
        char_layout.addWidget(self.digits_check)
        char_layout.addWidget(self.symbols_check)
        
        main_layout = QVBoxLayout()
        main_layout.addLayout(options_layout)
        main_layout.addLayout(char_layout)
        main_layout.addWidget(QLabel("Note:"))
        main_layout.addWidget(self.note_input)
        main_layout.addLayout(btn_layout)
        main_layout.addWidget(self.password_display)
        main_layout.addWidget(self.strength_bar)
        main_layout.addWidget(self.strength_label)
        
        tab.setLayout(main_layout)
        return tab
    
    def create_vault_tab(self):
        """Create password vault tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Password list
        self.vault_list = QListWidget()
        self.vault_list.itemDoubleClicked.connect(self.show_password_details)
        self.load_vault()
        
        # Action buttons
        btn_layout = QHBoxLayout()
        copy_btn = QPushButton("Copy")
        copy_btn.clicked.connect(self.copy_password)
        delete_btn = QPushButton("Delete")
        delete_btn.clicked.connect(self.delete_password)
        
        btn_layout.addWidget(copy_btn)
        btn_layout.addWidget(delete_btn)
        
        layout.addWidget(self.vault_list)
        layout.addLayout(btn_layout)
        tab.setLayout(layout)
        return tab
    
    def generate_password(self):
        """Generate a new password"""
        try:
            length = self.length_spin.value()
            note = self.note_input.text()
            
            if self.quantum_check.isChecked():
                password = self._generate_quantum_password(length)
            else:
                password = self._generate_standard_password(length)
            
            strength = self._calculate_strength(password)
            
            self.password_display.setText(password)
            self.strength_bar.setValue(strength)
            self.strength_label.setText(f"Strength: {strength}%")
            
            self._save_password(password, note, strength)
            self.load_vault()
            self.note_input.clear()
            
            self.status_bar.showMessage("Password generated successfully", 3000)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Generation failed: {str(e)}")
    
    def generate_ai_password(self):
        """Generate password using AI"""
        try:
            length = self.length_spin.value()
            note = self.note_input.text()
            
            if self.ai_available:
                password = self._generate_gpt_password(length)
            else:
                password = self._simulate_ai_password(length)
            
            strength = self._calculate_strength(password)
            
            self.password_display.setText(password)
            self.strength_bar.setValue(strength)
            self.strength_label.setText(f"Strength: {strength}%")
            
            self._save_password(password, note, strength)
            self.load_vault()
            self.note_input.clear()
            
            self.status_bar.showMessage("AI password generated", 3000)
            
        except Exception as e:
            QMessageBox.critical(self, "AI Error", f"AI generation failed: {str(e)}")
    
    def _generate_gpt_password(self, length):
        """Generate password using GPT-2 model"""
        prompt = "Generate a strong password with letters, numbers, and symbols:"
        inputs = self.tokenizer(prompt, return_tensors="pt")
        
        outputs = self.gpt_model.generate(
            inputs.input_ids,
            max_length=length + len(inputs.input_ids[0]),
            num_return_sequences=1,
            do_sample=True,
            top_k=50,
            top_p=0.95,
            temperature=0.7
        )
        
        password = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        password = password.split(":")[-1].strip()
        
        # Ensure the password meets our requirements
        password = self._enforce_password_rules(password, length)
        return password
    
    def _simulate_ai_password(self, length):
        """Simulate AI password generation when models aren't available"""
        chars = []
        if self.upper_check.isChecked():
            chars.extend(string.ascii_uppercase)
        if self.lower_check.isChecked():
            chars.extend(string.ascii_lowercase)
        if self.digits_check.isChecked():
            chars.extend(string.digits)
        if self.symbols_check.isChecked():
            chars.extend("!@#$%^&*")
        
        if not chars:
            raise ValueError("No character types selected")
        
        # AI-like generation pattern
        password = []
        patterns = ['CVC', 'CVV', 'CVCV', 'CVVC', 'CVCVC']
        vowels = 'aeiouAEIOU'
        consonants = ''.join(c for c in chars if c not in vowels and c.isalpha())
        
        if not consonants or not vowels:
            consonants = vowels = chars
        
        while len(password) < length:
            pattern = random.choice(patterns)
            for p in pattern:
                if len(password) >= length:
                    break
                if p == 'V':
                    password.append(random.choice(vowels))
                else:
                    password.append(random.choice(consonants))
            
            if len(password) < length and random.random() < 0.3:
                special = [c for c in chars if not c.isalnum()]
                if special:
                    password.append(random.choice(special))
        
        # Randomly apply leet substitutions
        leet = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
        for i in range(len(password)):
            if password[i].lower() in leet and random.random() < 0.3:
                password[i] = leet[password[i].lower()]
        
        return ''.join(password[:length])
    
    def _enforce_password_rules(self, password, min_length):
        """Ensure generated password meets requirements"""
        # Remove whitespace and special tokens
        password = ''.join(c for c in password if c.isprintable() and not c.isspace())
        
        # Ensure minimum length
        if len(password) < min_length:
            password += self._generate_standard_password(min_length - len(password))
        
        # Ensure at least one character from each selected category
        chars_to_add = []
        if self.upper_check.isChecked() and not any(c.isupper() for c in password):
            chars_to_add.append(random.choice(string.ascii_uppercase))
        if self.lower_check.isChecked() and not any(c.islower() for c in password):
            chars_to_add.append(random.choice(string.ascii_lowercase))
        if self.digits_check.isChecked() and not any(c.isdigit() for c in password):
            chars_to_add.append(random.choice(string.digits))
        if self.symbols_check.isChecked() and not any(not c.isalnum() for c in password):
            chars_to_add.append(random.choice("!@#$%^&*"))
        
        if chars_to_add:
            # Replace random characters with required types
            for i, c in enumerate(chars_to_add):
                if i < len(password):
                    password = password[:i] + c + password[i+1:]
        
        return password[:min_length]
    
    def _generate_quantum_password(self, length):
        """Generate password using quantum simulation"""
        bits = bin(random.getrandbits(256))[2:]  # 256-bit simulation
        
        chars = []
        if self.upper_check.isChecked():
            chars.extend(string.ascii_uppercase)
        if self.lower_check.isChecked():
            chars.extend(string.ascii_lowercase)
        if self.digits_check.isChecked():
            chars.extend(string.digits)
        if self.symbols_check.isChecked():
            chars.extend("!@#$%^&*")
        
        if not chars:
            raise ValueError("No character types selected")
        
        password = []
        for i in range(0, len(bits), 8):
            if len(password) >= length:
                break
            byte = bits[i:i+8]
            if len(byte) == 8:
                index = int(byte, 2) % len(chars)
                password.append(chars[index])
        
        return ''.join(password[:length])
    
    def _generate_standard_password(self, length):
        """Generate password using classical methods"""
        chars = []
        if self.upper_check.isChecked():
            chars.extend(string.ascii_uppercase)
        if self.lower_check.isChecked():
            chars.extend(string.ascii_lowercase)
        if self.digits_check.isChecked():
            chars.extend(string.digits)
        if self.symbols_check.isChecked():
            chars.extend("!@#$%^&*")
        
        if not chars:
            raise ValueError("No character types selected")
        
        return ''.join(random.choice(chars) for _ in range(length))
    
    def _calculate_strength(self, password):
        """Calculate password strength (0-100)"""
        length = len(password)
        char_types = 0
        
        if any(c.isupper() for c in password): char_types += 1
        if any(c.islower() for c in password): char_types += 1
        if any(c.isdigit() for c in password): char_types += 1
        if any(not c.isalnum() for c in password): char_types += 1
        
        entropy = length * (char_types * 8)  # Simplified entropy calculation
        return min(100, entropy)
    
    def _save_password(self, password, note, strength):
        """Save password to encrypted vault"""
        cipher = Fernet(self.key)
        timestamp = datetime.now().isoformat()
        
        entry = {
            'password': cipher.encrypt(password.encode()).decode(),
            'note': note,
            'strength': strength,
            'timestamp': timestamp
        }
        
        with open(self.vault_file, 'r+') as f:
            data = json.load(f)
            data['passwords'].append(entry)
            self._save_vault(data)
    
    def load_vault(self):
        """Load passwords from vault"""
        self.vault_list.clear()
        try:
            with open(self.vault_file, 'r') as f:
                data = json.load(f)
                cipher = Fernet(self.key)
                
                for entry in data['passwords']:
                    try:
                        pwd = cipher.decrypt(entry['password'].encode()).decode()
                        note = entry.get('note', '')
                        item = QListWidgetItem(f"{pwd[:12]}... - {note[:20]}...")
                        item.setData(Qt.ItemDataRole.UserRole, {
                            'password': pwd,
                            'note': note,
                            'strength': entry.get('strength', 0),
                            'timestamp': entry.get('timestamp', '')
                        })
                        self.vault_list.addItem(item)
                    except:
                        continue
        except FileNotFoundError:
            pass
    
    def show_password_details(self, item):
        """Show detailed password information"""
        data = item.data(Qt.ItemDataRole.UserRole)
        QMessageBox.information(
            self,
            "Password Details",
            f"Password: {data['password']}\n\n"
            f"Note: {data['note']}\n\n"
            f"Strength: {data['strength']}%\n"
            f"Created: {data['timestamp']}"
        )
    
    def copy_password(self):
        """Copy password to clipboard"""
        selected = self.vault_list.currentItem()
        if selected:
            data = selected.data(Qt.ItemDataRole.UserRole)
            QApplication.clipboard().setText(data['password'])
            self.status_bar.showMessage("Password copied to clipboard", 3000)
    
    def delete_password(self):
        """Delete selected password"""
        selected = self.vault_list.currentRow()
        if selected >= 0:
            with open(self.vault_file, 'r') as f:
                data = json.load(f)
                if 0 <= selected < len(data['passwords']):
                    del data['passwords'][selected]
                    self._save_vault(data)
                    self.load_vault()
                    self.status_bar.showMessage("Password deleted", 3000)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = QuantumPasswordManager()
    window.show()
    sys.exit(app.exec())