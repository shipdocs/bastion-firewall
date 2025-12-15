#!/usr/bin/env python3
"""
Improved Douane GUI - Better user interface for firewall decisions

This provides an enhanced GUI with:
- Better visual design
- More information about connections
- Timeout indicators
- Application icons (if available)
- Rule management interface
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from pathlib import Path
import threading
import socket
import subprocess


# Port descriptions for common ports
PORT_DESCRIPTIONS = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP (Email)",
    53: "DNS",
    80: "HTTP (Web)",
    110: "POP3 (Email)",
    143: "IMAP (Email)",
    443: "HTTPS (Secure Web)",
    465: "SMTPS (Secure Email)",
    587: "SMTP Submission",
    993: "IMAPS (Secure Email)",
    995: "POP3S (Secure Email)",
    3306: "MySQL Database",
    5432: "PostgreSQL Database",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
    27017: "MongoDB",
}


def get_port_description(port):
    """Get human-readable description of port"""
    return PORT_DESCRIPTIONS.get(port, f"Port {port}")


def reverse_dns_lookup(ip, timeout=0.5):
    """Try to get hostname from IP (non-blocking)"""
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except:
        return None


def get_process_info(app_path):
    """Get additional process information"""
    try:
        # Try to get process info using ps
        result = subprocess.run(
            ['ps', 'aux'],
            capture_output=True,
            text=True,
            timeout=1
        )

        for line in result.stdout.split('\n'):
            if app_path in line:
                parts = line.split()
                if len(parts) >= 11:
                    return {
                        'user': parts[0],
                        'pid': parts[1],
                        'cpu': parts[2],
                        'mem': parts[3],
                    }
    except:
        pass
    return None


def assess_risk_level(dest_port, dest_ip, app_name):
    """Assess risk level of connection"""
    # Known safe ports
    safe_ports = [80, 443, 53, 123]
    # Suspicious ports
    suspicious_ports = [23, 3389, 5900]  # Telnet, RDP, VNC

    if dest_port in safe_ports:
        return "low", "🟢"
    elif dest_port in suspicious_ports:
        return "high", "🔴"
    elif dest_port < 1024:
        return "medium", "🟡"
    else:
        return "medium", "🟡"


class ImprovedFirewallDialog:
    """Enhanced firewall decision dialog"""

    def __init__(self, conn_info, timeout=30, learning_mode=False):
        """
        Initialize dialog.

        Args:
            conn_info: ConnectionInfo object with connection details
            timeout: Seconds before auto-deny (0 = no timeout)
            learning_mode: If True, show that we're in learning mode (always allows)
        """
        self.conn_info = conn_info
        self.timeout = timeout
        self.learning_mode = learning_mode
        self.decision = None
        self.permanent = False
        self.root = None
        self.time_remaining = timeout
        self.timer_label = None
    
    def show(self):
        """Display the dialog and wait for user decision"""
        self.root = tk.Tk()
        self.root.title("Firewall - Connection Request")
        self.root.geometry("900x750")
        self.root.resizable(True, True)
        self.root.minsize(850, 700)

        # Make window appear on top and grab focus
        self.root.attributes('-topmost', True)
        self.root.focus_force()

        # Center window on screen
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (900 // 2)
        y = (self.root.winfo_screenheight() // 2) - (750 // 2)
        self.root.geometry(f"900x750+{x}+{y}")
        
        # Configure style with modern theme
        style = ttk.Style()
        style.theme_use('clam')  # Modern theme

        # Custom styles
        style.configure('Title.TLabel', font=('Ubuntu', 16, 'bold'))
        style.configure('Header.TLabel', font=('Ubuntu', 11, 'bold'), foreground='#2c3e50')
        style.configure('Info.TLabel', font=('Ubuntu', 10), foreground='#34495e')
        style.configure('Category.TLabel', font=('Ubuntu', 10, 'italic'), foreground='#16a085')

        # Frame styles
        style.configure('TLabelframe', borderwidth=2, relief='solid')
        style.configure('TLabelframe.Label', font=('Ubuntu', 10, 'bold'), foreground='#2c3e50')
        
        # Main container with background
        self.root.configure(bg='#ecf0f1')
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_frame.configure(style='Main.TFrame')

        # Configure main frame style
        style.configure('Main.TFrame', background='#ecf0f1')
        
        # Title with icon
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, columnspan=2, pady=(0, 20))

        if self.learning_mode:
            title_text = "📚 Network Connection (Learning Mode)"
            title_color = '#27ae60'  # Green for learning
        else:
            title_text = "🔒 Network Connection Request"
            title_color = '#d35400'  # Orange for enforcement

        title_label = ttk.Label(
            title_frame,
            text=title_text,
            style='Title.TLabel',
            foreground=title_color
        )
        title_label.pack()

        # Learning mode notice
        if self.learning_mode:
            notice_label = ttk.Label(
                title_frame,
                text="(Connection will be allowed - just learning your preferences)",
                font=('Arial', 9, 'italic'),
                foreground='#27ae60'
            )
            notice_label.pack()
        
        # Application info section
        app_frame = ttk.LabelFrame(main_frame, text="Application", padding="10")
        app_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        current_row = 0

        ttk.Label(app_frame, text="Name:", style='Header.TLabel').grid(row=current_row, column=0, sticky=tk.W, pady=2)
        ttk.Label(app_frame, text=self.conn_info.app_name or "Unknown", style='Info.TLabel', font=('Ubuntu', 10, 'bold')).grid(row=current_row, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        current_row += 1

        # Show category if available
        if hasattr(self.conn_info, 'app_category') and self.conn_info.app_category:
            ttk.Label(app_frame, text="Type:", style='Header.TLabel').grid(row=current_row, column=0, sticky=tk.W, pady=2)
            ttk.Label(app_frame, text=self.conn_info.app_category, style='Info.TLabel', foreground='#16a085').grid(row=current_row, column=1, sticky=tk.W, padx=(10, 0), pady=2)
            current_row += 1

        ttk.Label(app_frame, text="Path:", style='Header.TLabel').grid(row=current_row, column=0, sticky=tk.W, pady=2)
        path_label = ttk.Label(app_frame, text=self.conn_info.app_path or "unknown", style='Info.TLabel', wraplength=500)
        path_label.grid(row=current_row, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        current_row += 1

        # Get process info
        proc_info = get_process_info(self.conn_info.app_path) if self.conn_info.app_path else None
        if proc_info:
            ttk.Label(app_frame, text="Process:", style='Header.TLabel').grid(row=current_row, column=0, sticky=tk.W, pady=2)
            proc_text = f"PID {proc_info['pid']} (User: {proc_info['user']}, CPU: {proc_info['cpu']}%, Mem: {proc_info['mem']}%)"
            ttk.Label(app_frame, text=proc_text, style='Info.TLabel', foreground='#7f8c8d', font=('Ubuntu', 9)).grid(row=current_row, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        
        # Connection info section
        conn_frame = ttk.LabelFrame(main_frame, text="Connection Details", padding="10")
        conn_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        # Try reverse DNS lookup
        hostname = reverse_dns_lookup(self.conn_info.dest_ip)
        if hostname and hostname != self.conn_info.dest_ip:
            dest_text = f"{hostname} ({self.conn_info.dest_ip})"
        else:
            dest_text = self.conn_info.dest_ip

        ttk.Label(conn_frame, text="Destination:", style='Header.TLabel').grid(row=0, column=0, sticky=tk.W, pady=2)
        dest_label = ttk.Label(conn_frame, text=dest_text, style='Info.TLabel', foreground='#2980b9', wraplength=500)
        dest_label.grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=2)

        # Port with description
        port_desc = get_port_description(self.conn_info.dest_port)
        ttk.Label(conn_frame, text="Port:", style='Header.TLabel').grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Label(conn_frame, text=f"{self.conn_info.dest_port} - {port_desc}",
                 style='Info.TLabel', foreground='#8e44ad').grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=2)

        ttk.Label(conn_frame, text="Protocol:", style='Header.TLabel').grid(row=2, column=0, sticky=tk.W, pady=2)
        ttk.Label(conn_frame, text=self.conn_info.protocol.upper(), style='Info.TLabel').grid(row=2, column=1, sticky=tk.W, padx=(10, 0), pady=2)

        # Risk assessment
        risk_level, risk_icon = assess_risk_level(self.conn_info.dest_port, self.conn_info.dest_ip, self.conn_info.app_name)
        risk_text = f"{risk_icon} {risk_level.upper()} risk"
        risk_colors = {'low': '#27ae60', 'medium': '#f39c12', 'high': '#e74c3c'}
        ttk.Label(conn_frame, text="Risk:", style='Header.TLabel').grid(row=3, column=0, sticky=tk.W, pady=2)
        ttk.Label(conn_frame, text=risk_text, style='Info.TLabel',
                 foreground=risk_colors.get(risk_level, '#95a5a6')).grid(row=3, column=1, sticky=tk.W, padx=(10, 0), pady=2)

        ttk.Label(conn_frame, text="Time:", style='Header.TLabel').grid(row=4, column=0, sticky=tk.W, pady=2)
        ttk.Label(conn_frame, text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 style='Info.TLabel').grid(row=4, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        
        # Warning message
        warning_frame = ttk.Frame(main_frame)
        warning_frame.grid(row=3, column=0, columnspan=2, pady=(0, 10))
        
        warning_text = "⚠️  This application wants to connect to the internet.\nDo you want to allow this connection?"
        warning_label = ttk.Label(
            warning_frame,
            text=warning_text,
            style='Info.TLabel',
            foreground='#e67e22',
            justify=tk.CENTER
        )
        warning_label.pack()

        # Three-button layout
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=(15, 10))

        # Allow Once button (Blue - Temporary)
        allow_once_btn = tk.Button(
            button_frame,
            text="✓ Allow Once",
            command=self._allow_once,
            bg='#3498db',
            fg='white',
            font=('Ubuntu', 11, 'bold'),
            width=14,
            height=2,
            cursor='hand2',
            relief='flat',
            borderwidth=0,
            activebackground='#2980b9',
            activeforeground='white'
        )
        allow_once_btn.pack(side=tk.LEFT, padx=5)

        # Hover effects
        allow_once_btn.bind('<Enter>', lambda e: allow_once_btn.config(bg='#2980b9'))
        allow_once_btn.bind('<Leave>', lambda e: allow_once_btn.config(bg='#3498db'))

        # Allow Always button (Green - Permanent)
        allow_always_btn = tk.Button(
            button_frame,
            text="✓✓ Allow Always",
            command=self._allow_always,
            bg='#27ae60',
            fg='white',
            font=('Ubuntu', 11, 'bold'),
            width=14,
            height=2,
            cursor='hand2',
            relief='flat',
            borderwidth=0,
            activebackground='#229954',
            activeforeground='white'
        )
        allow_always_btn.pack(side=tk.LEFT, padx=5)

        # Hover effects
        allow_always_btn.bind('<Enter>', lambda e: allow_always_btn.config(bg='#229954'))
        allow_always_btn.bind('<Leave>', lambda e: allow_always_btn.config(bg='#27ae60'))

        # Deny button (Red - Block)
        deny_btn = tk.Button(
            button_frame,
            text="✗ Deny",
            command=self._deny,
            bg='#e74c3c',
            fg='white',
            font=('Ubuntu', 11, 'bold'),
            width=14,
            height=2,
            cursor='hand2',
            relief='flat',
            borderwidth=0,
            activebackground='#c0392b',
            activeforeground='white'
        )
        deny_btn.pack(side=tk.LEFT, padx=5)

        # Hover effects
        deny_btn.bind('<Enter>', lambda e: deny_btn.config(bg='#c0392b'))
        deny_btn.bind('<Leave>', lambda e: deny_btn.config(bg='#e74c3c'))
        
        # Keyboard shortcuts hint
        shortcuts_label = ttk.Label(
            main_frame,
            text="Keyboard: Enter=Allow Once | A=Allow Always | Esc=Deny",
            font=('Arial', 8, 'italic'),
            foreground='#7f8c8d'
        )
        shortcuts_label.grid(row=5, column=0, columnspan=2, pady=(5, 5))

        # Timeout indicator
        if self.timeout > 0:
            self.timer_label = ttk.Label(
                main_frame,
                text=f"Auto-deny in {self.timeout} seconds...",
                style='Info.TLabel',
                foreground='#95a5a6'
            )
            self.timer_label.grid(row=6, column=0, columnspan=2)
            self._start_timer()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._deny)

        # Keyboard shortcuts
        self.root.bind('<Return>', lambda e: self._allow_once())
        self.root.bind('<Escape>', lambda e: self._deny())
        self.root.bind('a', lambda e: self._allow_always())

        # Run dialog
        self.root.mainloop()

        return self.decision, self.permanent

    def _start_timer(self):
        """Start countdown timer"""
        if self.time_remaining > 0:
            self.timer_label.config(text=f"Auto-deny in {self.time_remaining} seconds...")
            self.time_remaining -= 1
            self.root.after(1000, self._start_timer)
        else:
            # Timeout - auto deny
            self._deny()

    def _allow_once(self):
        """User chose to allow once (temporary)"""
        self.decision = 'allow'
        self.permanent = False
        self.root.quit()
        self.root.destroy()

    def _allow_always(self):
        """User chose to allow always (permanent)"""
        self.decision = 'allow'
        self.permanent = True
        self.root.quit()
        self.root.destroy()

    def _deny(self):
        """User chose to deny"""
        self.decision = 'deny'
        self.permanent = False
        if self.root:
            self.root.quit()
            self.root.destroy()


class RuleManagerGUI:
    """GUI for managing firewall rules"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Douane Firewall - Rule Manager")
        self.root.geometry("800x600")

        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Title
        title_label = ttk.Label(
            main_frame,
            text="Firewall Rules",
            font=('Arial', 16, 'bold')
        )
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))

        # Rules list
        list_frame = ttk.Frame(main_frame)
        list_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Treeview for rules
        columns = ('Application', 'Destination', 'Port', 'Action', 'Type')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', yscrollcommand=scrollbar.set)

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.tree.yview)

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=(10, 0))

        ttk.Button(button_frame, text="Delete Rule", command=self._delete_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Refresh", command=self._load_rules).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", command=self.root.destroy).pack(side=tk.LEFT, padx=5)

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)

        # Load rules
        self._load_rules()

    def _load_rules(self):
        """Load and display current rules"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)

        # TODO: Load actual rules from UFW/database
        # For now, show example
        self.tree.insert('', 'end', values=('firefox', '93.184.216.34', '443', 'Allow', 'Permanent'))
        self.tree.insert('', 'end', values=('chrome', '142.250.185.46', '443', 'Allow', 'Permanent'))

    def _delete_rule(self):
        """Delete selected rule"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a rule to delete")
            return

        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this rule?"):
            for item in selection:
                self.tree.delete(item)
            # TODO: Actually delete from UFW/database

    def show(self):
        """Show the rule manager"""
        self.root.mainloop()


def test_dialog():
    """Test the improved dialog"""
    from ufw_firewall_gui import ConnectionInfo

    conn_info = ConnectionInfo(
        app_name="firefox",
        app_path="/usr/bin/firefox",
        dest_ip="93.184.216.34",
        dest_port=443,
        protocol="tcp"
    )

    dialog = ImprovedFirewallDialog(conn_info, timeout=30)
    decision, permanent = dialog.show()

    print(f"Decision: {decision}")
    print(f"Permanent: {permanent}")


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        test_dialog()
    elif len(sys.argv) > 1 and sys.argv[1] == '--rules':
        manager = RuleManagerGUI()
        manager.show()
    else:
        print("Usage:")
        print("  python3 douane_gui_improved.py --test   # Test the dialog")
        print("  python3 douane_gui_improved.py --rules  # Show rule manager")

