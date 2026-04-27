#!/usr/bin/env python3
"""
NetHawk Service Manager GUI
A simple GUI to manage the NetHawk Remote Capture Service
"""

import sys
import os
import subprocess
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QTextEdit, 
                             QGroupBox, QLineEdit, QMessageBox, QFileDialog)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QFont

class ServiceManagerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetHawk Service Manager")
        self.setGeometry(100, 100, 600, 500)
        
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        
        # Service status
        status_group = QGroupBox("Service Status")
        status_layout = QVBoxLayout()
        
        self.status_label = QLabel("Checking...")
        self.status_label.setFont(QFont("Arial", 12, QFont.Bold))
        status_layout.addWidget(self.status_label)
        
        self.info_label = QLabel("")
        status_layout.addWidget(self.info_label)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Control buttons
        control_group = QGroupBox("Service Control")
        control_layout = QVBoxLayout()
        
        btn_layout1 = QHBoxLayout()
        self.start_btn = QPushButton("Start Service")
        self.start_btn.clicked.connect(self.start_service)
        self.stop_btn = QPushButton("Stop Service")
        self.stop_btn.clicked.connect(self.stop_service)
        self.restart_btn = QPushButton("Restart Service")
        self.restart_btn.clicked.connect(self.restart_service)
        btn_layout1.addWidget(self.start_btn)
        btn_layout1.addWidget(self.stop_btn)
        btn_layout1.addWidget(self.restart_btn)
        control_layout.addLayout(btn_layout1)
        
        btn_layout2 = QHBoxLayout()
        self.install_btn = QPushButton("Install Service")
        self.install_btn.clicked.connect(self.install_service)
        self.uninstall_btn = QPushButton("Uninstall Service")
        self.uninstall_btn.clicked.connect(self.uninstall_service)
        btn_layout2.addWidget(self.install_btn)
        btn_layout2.addWidget(self.uninstall_btn)
        control_layout.addLayout(btn_layout2)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Configuration
        config_group = QGroupBox("Configuration")
        config_layout = QVBoxLayout()
        
        config_file_layout = QHBoxLayout()
        config_file_layout.addWidget(QLabel("Config File:"))
        self.config_file = QLineEdit()
        self.config_file.setPlaceholderText("C:\\ProgramData\\NetHawk\\service_config.json")
        config_file_layout.addWidget(self.config_file)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_config)
        config_file_layout.addWidget(browse_btn)
        config_layout.addLayout(config_file_layout)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Log viewer
        log_group = QGroupBox("Service Log (Last 50 lines)")
        log_layout = QVBoxLayout()
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Consolas", 9))
        log_layout.addWidget(self.log_view)
        refresh_log_btn = QPushButton("Refresh Log")
        refresh_log_btn.clicked.connect(self.refresh_log)
        log_layout.addWidget(refresh_log_btn)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        # Auto-refresh timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_status)
        self.timer.start(2000)  # Update every 2 seconds
        
        # Initial update
        self.update_status()
        self.refresh_log()
    
    def run_command(self, cmd):
        """Run a command and return output"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            return result.returncode == 0, result.stdout, result.stderr
        except Exception as e:
            return False, "", str(e)
    
    def update_status(self):
        """Update service status"""
        success, output, error = self.run_command("sc query NetHawkCaptureService")
        if not success:
            self.status_label.setText("Service Not Installed")
            self.status_label.setStyleSheet("color: red;")
            self.info_label.setText("The service is not installed on this system.")
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(False)
            self.restart_btn.setEnabled(False)
            return
        
        if "RUNNING" in output:
            self.status_label.setText("Service Status: RUNNING")
            self.status_label.setStyleSheet("color: green;")
            self.info_label.setText("The service is running and accepting connections.")
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.restart_btn.setEnabled(True)
        elif "STOPPED" in output:
            self.status_label.setText("Service Status: STOPPED")
            self.status_label.setStyleSheet("color: orange;")
            self.info_label.setText("The service is installed but not running.")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.restart_btn.setEnabled(True)
        else:
            self.status_label.setText("Service Status: UNKNOWN")
            self.status_label.setStyleSheet("color: gray;")
            self.info_label.setText(f"Status: {output}")
    
    def start_service(self):
        """Start the service"""
        success, output, error = self.run_command("net start NetHawkCaptureService")
        if success:
            QMessageBox.information(self, "Success", "Service started successfully!")
        else:
            QMessageBox.warning(self, "Error", f"Failed to start service:\n{error}")
        self.update_status()
    
    def stop_service(self):
        """Stop the service"""
        reply = QMessageBox.question(self, "Confirm", "Stop the NetHawk service?")
        if reply == QMessageBox.Yes:
            success, output, error = self.run_command("net stop NetHawkCaptureService")
            if success:
                QMessageBox.information(self, "Success", "Service stopped successfully!")
            else:
                QMessageBox.warning(self, "Error", f"Failed to stop service:\n{error}")
            self.update_status()
    
    def restart_service(self):
        """Restart the service"""
        reply = QMessageBox.question(self, "Confirm", "Restart the NetHawk service?")
        if reply == QMessageBox.Yes:
            self.run_command("net stop NetHawkCaptureService")
            import time
            time.sleep(2)
            success, output, error = self.run_command("net start NetHawkCaptureService")
            if success:
                QMessageBox.information(self, "Success", "Service restarted successfully!")
            else:
                QMessageBox.warning(self, "Error", f"Failed to restart service:\n{error}")
            self.update_status()
    
    def install_service(self):
        """Install the service"""
        service_exe = os.path.join(os.path.dirname(__file__), "dist", "NetHawkService.exe")
        if not os.path.exists(service_exe):
            QMessageBox.warning(self, "Error", 
                              f"Service executable not found:\n{service_exe}\n\nPlease build it first using build_service.bat")
            return
        
        reply = QMessageBox.question(self, "Confirm", 
                                    "Install NetHawk Remote Capture Service?\n\nThis requires administrator privileges.")
        if reply == QMessageBox.Yes:
            config_file = self.config_file.text() if self.config_file.text() else None
            cmd = f'"{service_exe}" --install'
            if config_file:
                cmd += f' --config "{config_file}"'
            
            success, output, error = self.run_command(cmd)
            if success:
                QMessageBox.information(self, "Success", "Service installed successfully!")
            else:
                QMessageBox.warning(self, "Error", f"Failed to install service:\n{error}\n\nYou may need to run as administrator.")
            self.update_status()
    
    def uninstall_service(self):
        """Uninstall the service"""
        reply = QMessageBox.question(self, "Confirm", 
                                    "Uninstall NetHawk Remote Capture Service?\n\nThis will stop and remove the service.")
        if reply == QMessageBox.Yes:
            service_exe = os.path.join(os.path.dirname(__file__), "dist", "NetHawkService.exe")
            if os.path.exists(service_exe):
                self.run_command(f'"{service_exe}" --uninstall')
            else:
                self.run_command("sc delete NetHawkCaptureService")
            QMessageBox.information(self, "Success", "Service uninstalled.")
            self.update_status()
    
    def browse_config(self):
        """Browse for config file"""
        filename, _ = QFileDialog.getOpenFileName(self, "Select Config File", 
                                                 "C:\\ProgramData\\NetHawk", 
                                                 "JSON Files (*.json)")
        if filename:
            self.config_file.setText(filename)
    
    def refresh_log(self):
        """Refresh log view"""
        log_file = os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 
                               'NetHawk', 'nethawk_service.log')
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    # Show last 50 lines
                    self.log_view.setText(''.join(lines[-50:]))
            except Exception as e:
                self.log_view.setText(f"Error reading log: {e}")
        else:
            self.log_view.setText("Log file not found. Service may not have run yet.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ServiceManagerGUI()
    window.show()
    sys.exit(app.exec_())

