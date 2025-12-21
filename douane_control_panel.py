#!/usr/bin/env python3
"""
Douane Firewall Control Panel - Main GUI window
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import json
import subprocess
import os
import time
from pathlib import Path
from douane.inbound_firewall import InboundFirewallDetector


class DouaneControlPanel:
    """Main control panel window for Douane Firewall"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Douane Firewall Control Panel")
        self.root.geometry("1000x750")
        self.root.minsize(900, 650)
        self.root.resizable(True, True)
        
        # Load config and rules
        self.config_file = Path('/etc/douane/config.json')
        self.rules_file = Path('/etc/douane/rules.json')
        self.config = self.load_config()
        self.rules = self.load_rules()
        
        self.create_ui()
        self.start_polling()
        
    def load_config(self):
        """Load configuration"""
        if self.config_file.exists():
            try:
                with open(self.config_file) as f:
                    return json.load(f)
            except:
                pass
        return {'mode': 'learning', 'timeout_seconds': 30}
    
    def load_rules(self):
        """Load saved rules"""
        if self.rules_file.exists():
            try:
                with open(self.rules_file) as f:
                    return json.load(f)
            except:
                pass
        return {}
    
    def save_config(self):
        """Save configuration using pkexec (config file is owned by root)"""
        try:
            import tempfile
            import subprocess

            # Write to temporary file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp:
                json.dump(self.config, tmp, indent=2)
                tmp_path = tmp.name

            # Use pkexec to copy temp file to /etc/douane/config.json
            result = subprocess.run(
                ['pkexec', 'cp', tmp_path, str(self.config_file)],
                capture_output=True,
                text=True
            )

            # Clean up temp file
            os.unlink(tmp_path)

            if result.returncode == 0:
                messagebox.showinfo("Success", "Configuration saved! Restart firewall for changes to take effect.")
            else:
                messagebox.showerror("Error", f"Failed to save configuration: {result.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {e}")
    
    def create_ui(self):
        """Create the user interface"""
        # Create notebook (tabs)
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=(10, 0))

        # Tab 1: Overview
        overview_frame = ttk.Frame(notebook)
        notebook.add(overview_frame, text='Overview')
        self.create_overview_tab(overview_frame)

        # Tab 2: Settings
        settings_frame = ttk.Frame(notebook)
        notebook.add(settings_frame, text='Settings')
        self.create_settings_tab(settings_frame)

        # Tab 3: Rules
        rules_frame = ttk.Frame(notebook)
        notebook.add(rules_frame, text='Rules')
        self.create_rules_tab(rules_frame)

        # Tab 4: Logs
        logs_frame = ttk.Frame(notebook)
        notebook.add(logs_frame, text='Logs')
        self.create_logs_tab(logs_frame)

        # Tab 5: Inbound Protection
        inbound_frame = ttk.Frame(notebook)
        notebook.add(inbound_frame, text='Inbound Protection')
        self.create_inbound_tab(inbound_frame)

        # Bottom buttons - ALWAYS VISIBLE with proper height
        button_frame = ttk.Frame(self.root, relief='raised', borderwidth=1)
        button_frame.pack(fill='x', side='bottom', padx=10, pady=10)

        # Configure button style with larger padding for better visibility
        style = ttk.Style()
        style.configure('Control.TButton', padding=(10, 10), font=('Ubuntu', 11))

        ttk.Button(button_frame, text="🚀 Start Firewall", command=self.start_firewall,
                  width=18, style='Control.TButton').pack(side='left', padx=5, pady=5)
        ttk.Button(button_frame, text="⏹️ Stop Firewall", command=self.stop_firewall,
                  width=18, style='Control.TButton').pack(side='left', padx=5, pady=5)
        ttk.Button(button_frame, text="🔄 Restart Firewall", command=self.restart_firewall,
                  width=18, style='Control.TButton').pack(side='left', padx=5, pady=5)
        ttk.Button(button_frame, text="❌ Close", command=self.root.quit,
                  width=12, style='Control.TButton').pack(side='right', padx=5, pady=5)
    
    def create_overview_tab(self, parent):
        """Create overview tab"""
        # Status section
        status_frame = ttk.LabelFrame(parent, text="Status", padding=10)
        status_frame.pack(fill='x', padx=10, pady=10)
        
        self.status_label = ttk.Label(status_frame, text="Checking status...", font=('Ubuntu', 12))
        self.status_label.pack()
        
        ttk.Button(status_frame, text="Refresh Status", command=self.refresh_all).pack(pady=5)
        
        # Statistics section
        stats_frame = ttk.LabelFrame(parent, text="Statistics", padding=10)
        stats_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=10, wrap=tk.WORD)
        self.stats_text.pack(fill='both', expand=True)
        
        self.update_status()
        self.update_statistics()
    
    def create_settings_tab(self, parent):
        """Create settings tab"""
        # Mode selection
        mode_frame = ttk.LabelFrame(parent, text="Operating Mode", padding=10)
        mode_frame.pack(fill='x', padx=10, pady=10)
        
        self.mode_var = tk.StringVar(value=self.config.get('mode', 'learning'))
        
        ttk.Radiobutton(mode_frame, text="Learning Mode (shows popups, always allows)", 
                       variable=self.mode_var, value='learning').pack(anchor='w', pady=5)
        ttk.Radiobutton(mode_frame, text="Enforcement Mode (actually blocks traffic)", 
                       variable=self.mode_var, value='enforcement').pack(anchor='w', pady=5)
        
        # Timeout setting
        timeout_frame = ttk.LabelFrame(parent, text="Popup Timeout", padding=10)
        timeout_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(timeout_frame, text="Auto-deny after (seconds):").pack(side='left', padx=5)
        self.timeout_var = tk.IntVar(value=self.config.get('timeout_seconds', 30))
        ttk.Spinbox(timeout_frame, from_=10, to=300, textvariable=self.timeout_var, width=10).pack(side='left', padx=5)
        
        # Save button
        ttk.Button(parent, text="Save Settings", command=self.save_settings).pack(pady=20)

    def create_rules_tab(self, parent):
        """Create rules management tab"""
        # Rules list
        rules_frame = ttk.LabelFrame(parent, text="Active Rules", padding=10)
        rules_frame.pack(fill='both', expand=True, padx=10, pady=10)

        # Create treeview for rules
        columns = ('Application', 'Port', 'Action')
        self.rules_tree = ttk.Treeview(rules_frame, columns=columns, show='headings', height=15)

        self.rules_tree.heading('Application', text='Application')
        self.rules_tree.heading('Port', text='Port')
        self.rules_tree.heading('Action', text='Action')

        self.rules_tree.column('Application', width=400)
        self.rules_tree.column('Port', width=100)
        self.rules_tree.column('Action', width=100)

        # Scrollbar
        scrollbar = ttk.Scrollbar(rules_frame, orient='vertical', command=self.rules_tree.yview)
        self.rules_tree.configure(yscrollcommand=scrollbar.set)

        self.rules_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # Buttons
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill='x', padx=10, pady=10)

        ttk.Button(button_frame, text="Refresh Rules", command=self.update_rules_list).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Delete Selected", command=self.delete_rule).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Clear All Rules", command=self.clear_all_rules).pack(side='left', padx=5)

        self.update_rules_list()

    def create_logs_tab(self, parent):
        """Create logs viewer tab"""
        logs_frame = ttk.LabelFrame(parent, text="Daemon Logs", padding=10)
        logs_frame.pack(fill='both', expand=True, padx=10, pady=10)

        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=20, wrap=tk.WORD, font=('Courier', 9))
        self.logs_text.pack(fill='both', expand=True)

        # Initial message
        self.logs_text.insert('1.0', "Click 'Refresh Logs' to view daemon logs...")

        button_frame = ttk.Frame(parent)
        button_frame.pack(fill='x', padx=10, pady=10)

        ttk.Button(button_frame, text="Refresh Logs", command=self.update_logs).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Clear Logs", command=self.clear_logs).pack(side='left', padx=5)

    def create_inbound_tab(self, parent):
        """Create inbound firewall protection tab"""
        # Info frame
        info_frame = ttk.LabelFrame(parent, text="Firewall Protection Status", padding=10)
        info_frame.pack(fill='x', padx=10, pady=10)

        # Explanation
        explanation = tk.Label(info_frame, text=(
            "Douane protects OUTBOUND connections (applications trying to connect to the internet).\n"
            "For complete protection, you also need INBOUND firewall rules to block unsolicited incoming connections.\n\n"
            "This tab helps you set up inbound protection using UFW (Uncomplicated Firewall)."
        ), justify='left', wraplength=700)
        explanation.pack(anchor='w', pady=5)

        # Status frame
        status_frame = ttk.LabelFrame(parent, text="Current Protection Status", padding=10)
        status_frame.pack(fill='x', padx=10, pady=10)

        # Outbound status
        outbound_frame = ttk.Frame(status_frame)
        outbound_frame.pack(fill='x', pady=5)
        ttk.Label(outbound_frame, text="Outbound Protection:", font=('TkDefaultFont', 10, 'bold')).pack(side='left')
        self.outbound_status_label = ttk.Label(outbound_frame, text="✅ Active (Douane)", foreground='green')
        self.outbound_status_label.pack(side='left', padx=10)

        # Inbound status
        inbound_frame = ttk.Frame(status_frame)
        inbound_frame.pack(fill='x', pady=5)
        ttk.Label(inbound_frame, text="Inbound Protection:", font=('TkDefaultFont', 10, 'bold')).pack(side='left')
        self.inbound_status_label = ttk.Label(inbound_frame, text="Checking...", foreground='gray')
        self.inbound_status_label.pack(side='left', padx=10)

        # Recommendation frame
        self.recommendation_frame = ttk.LabelFrame(parent, text="Recommendation", padding=10)
        self.recommendation_frame.pack(fill='both', expand=True, padx=10, pady=10)

        self.recommendation_text = scrolledtext.ScrolledText(
            self.recommendation_frame, height=10, wrap=tk.WORD, font=('TkDefaultFont', 9)
        )
        self.recommendation_text.pack(fill='both', expand=True, pady=5)

        # Action buttons
        button_frame = ttk.Frame(self.recommendation_frame)
        button_frame.pack(fill='x', pady=5)

        self.setup_ufw_button = ttk.Button(
            button_frame, text="Install & Configure UFW",
            command=self.setup_inbound_protection, state='disabled'
        )
        self.setup_ufw_button.pack(side='left', padx=5)

        ttk.Button(button_frame, text="Refresh Status", command=self.check_inbound_protection).pack(side='left', padx=5)

        # Initial check
        self.check_inbound_protection()

    def check_inbound_protection(self):
        """Check inbound firewall status"""
        try:
            result = InboundFirewallDetector.detect_firewall()

            if result['has_protection']:
                # Has protection
                firewall_name = result['firewall'].upper() if result['firewall'] else 'Unknown'
                self.inbound_status_label.config(
                    text=f"✅ Active ({firewall_name})",
                    foreground='green'
                )
                self.recommendation_text.delete('1.0', tk.END)
                self.recommendation_text.insert('1.0',
                    f"✅ Your system is protected!\n\n"
                    f"Inbound firewall: {firewall_name}\n"
                    f"Status: {result['status']}\n\n"
                    f"You have complete firewall protection:\n"
                    f"• Outbound: Douane (application-level control)\n"
                    f"• Inbound: {firewall_name} (blocks unsolicited connections)\n\n"
                    f"No action needed."
                )
                self.setup_ufw_button.config(state='disabled')
            else:
                # No protection
                self.inbound_status_label.config(
                    text="⚠️ Not Detected",
                    foreground='orange'
                )
                self.recommendation_text.delete('1.0', tk.END)

                if result['firewall'] == 'ufw' and result['status'] == 'inactive':
                    # UFW installed but not active
                    self.recommendation_text.insert('1.0',
                        "⚠️ UFW is installed but not active\n\n"
                        "Click 'Install & Configure UFW' to enable it with safe defaults:\n\n"
                        "• Deny all NEW inbound connections (blocks port scans, attacks)\n"
                        "• Allow ESTABLISHED/RELATED (responses to your outbound requests)\n"
                        "• Allow all outbound (Douane controls this)\n\n"
                        "This is the recommended server configuration and safe for desktops."
                    )
                    self.setup_ufw_button.config(state='normal', text="Enable UFW")
                else:
                    # No firewall at all
                    self.recommendation_text.insert('1.0',
                        "⚠️ No inbound firewall detected\n\n"
                        "Your system is vulnerable to:\n"
                        "• Port scans\n"
                        "• Unsolicited inbound connections\n"
                        "• Network attacks\n\n"
                        "Click 'Install & Configure UFW' to set up protection with safe defaults:\n\n"
                        "• Deny all NEW inbound connections\n"
                        "• Allow ESTABLISHED/RELATED (responses to your requests)\n"
                        "• Allow all outbound (Douane controls this)\n\n"
                        "This is the standard server configuration and safe for desktops."
                    )
                    self.setup_ufw_button.config(state='normal', text="Install & Configure UFW")

        except Exception as e:
            self.inbound_status_label.config(text=f"❌ Error: {e}", foreground='red')
            self.recommendation_text.delete('1.0', tk.END)
            self.recommendation_text.insert('1.0', f"Error checking firewall status:\n{e}")

    def setup_inbound_protection(self):
        """Install and configure UFW"""
        if not messagebox.askyesno(
            "Confirm UFW Setup",
            "This will install and configure UFW with the following rules:\n\n"
            "• Deny all NEW inbound connections\n"
            "• Allow ESTABLISHED/RELATED connections\n"
            "• Allow all outbound connections\n\n"
            "This is safe and recommended. Continue?"
        ):
            return

        # Show progress
        self.recommendation_text.delete('1.0', tk.END)
        self.recommendation_text.insert('1.0', "Setting up UFW...\nThis may take a minute...\n")
        self.setup_ufw_button.config(state='disabled')
        self.root.update()

        try:
            success, message = InboundFirewallDetector.setup_inbound_protection()

            self.recommendation_text.delete('1.0', tk.END)
            if success:
                self.recommendation_text.insert('1.0', f"✅ {message}")
                messagebox.showinfo("Success", message)
                # Refresh status
                self.check_inbound_protection()
            else:
                self.recommendation_text.insert('1.0', f"❌ {message}")
                messagebox.showerror("Error", message)
                self.setup_ufw_button.config(state='normal')

        except Exception as e:
            error_msg = f"Failed to setup UFW: {e}"
            self.recommendation_text.delete('1.0', tk.END)
            self.recommendation_text.insert('1.0', f"❌ {error_msg}")
            messagebox.showerror("Error", error_msg)
            self.setup_ufw_button.config(state='normal')

    def start_polling(self):
        """Start status polling loop"""
        self.poll_status()

    def poll_status(self):
        """Periodically check status"""
        print("DEBUG: Polling status...")
        self.update_status()
        # Poll every 3 seconds
        self.root.after(3000, self.poll_status)

    def update_status(self):
        """Update firewall status from system"""
        try:
            # Check systemd status
            # systemctl is-active returns the current state keyword (active, inactive, etc.)
            result = subprocess.run(['systemctl', 'is-active', 'douane-firewall'], capture_output=True, text=True)
            status = result.stdout.strip()
            
            if status == 'active':
                self.status_label.config(text="✓ Firewall is RUNNING", foreground='green')
            elif status == 'activating':
                self.status_label.config(text="⟳ Firewall is STARTING...", foreground='orange')
            elif status == 'deactivating':
                self.status_label.config(text="⟳ Firewall is STOPPING...", foreground='orange')
            elif status == 'failed':
                self.status_label.config(text="⚠ Firewall FAILED", foreground='red')
            else:
                # inactive or unknown
                self.status_label.config(text="✗ Firewall is STOPPED", foreground='red')
        except Exception as e:
            self.status_label.config(text=f"ERROR: {str(e)}", foreground='red')

    def refresh_all(self):
        """Refresh all status information"""
        # Reload config from disk to get latest settings
        self.config = self.load_config()
        # Update all displays
        self.update_status()
        self.update_statistics()
        self.update_rules_list()

    def update_statistics(self):
        """Update statistics"""
        stats = f"Total Rules: {len(self.rules)}\n\n"
        stats += f"Operating Mode: {self.config.get('mode', 'learning').title()}\n"
        stats += f"Popup Timeout: {self.config.get('timeout_seconds', 30)} seconds\n\n"

        # Count allowed vs denied
        allowed = sum(1 for v in self.rules.values() if v)
        denied = sum(1 for v in self.rules.values() if not v)
        stats += f"Allowed Rules: {allowed}\n"
        stats += f"Denied Rules: {denied}\n"

        self.stats_text.delete('1.0', tk.END)
        self.stats_text.insert('1.0', stats)

    def update_rules_list(self):
        """Update rules list"""
        # Clear existing items
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)

        # Reload rules
        self.rules = self.load_rules()

        # Add rules to tree
        for cache_key, allow in self.rules.items():
            try:
                # Parse cache key: app_path:port
                parts = cache_key.rsplit(':', 1)
                if len(parts) == 2:
                    app_path, port = parts
                    action = "ALLOW" if allow else "DENY"
                    self.rules_tree.insert('', 'end', values=(app_path, port, action))
            except:
                pass

        self.update_statistics()

    def update_logs(self):
        """Update logs display"""
        try:
            # Try without sudo first (if log file is readable)
            result = subprocess.run(['tail', '-100', '/var/log/douane-daemon.log'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                self.logs_text.delete('1.0', tk.END)
                self.logs_text.insert('1.0', result.stdout)
            else:
                # Try with pkexec for GUI password prompt
                result = subprocess.run(['pkexec', 'tail', '-100', '/var/log/douane-daemon.log'],
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    self.logs_text.delete('1.0', tk.END)
                    self.logs_text.insert('1.0', result.stdout)
                else:
                    self.logs_text.delete('1.0', tk.END)
                    self.logs_text.insert('1.0', "No logs available or permission denied")
        except Exception as e:
            self.logs_text.delete('1.0', tk.END)
            self.logs_text.insert('1.0', f"Error reading logs: {e}")

    def clear_logs(self):
        """Clear daemon logs"""
        if messagebox.askyesno("Confirm", "Clear all daemon logs?"):
            try:
                subprocess.run(['pkexec', 'truncate', '-s', '0', '/var/log/douane-daemon.log'])
                self.update_logs()
                messagebox.showinfo("Success", "Logs cleared")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear logs: {e}")

    def save_settings(self):
        """Save settings"""
        self.config['mode'] = self.mode_var.get()
        self.config['timeout_seconds'] = self.timeout_var.get()
        self.save_config()
        
        # Signal daemon to reload config
        try:
            subprocess.run(['pkill', '-HUP', '-f', 'douane-daemon'], check=False)
        except:
            pass
            
        # Immediately update the statistics display to show new mode
        self.update_statistics()

    def delete_rule(self):
        """Delete selected rule"""
        selection = self.rules_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a rule to delete")
            return

        if messagebox.askyesno("Confirm", "Delete selected rule?"):
            for item in selection:
                values = self.rules_tree.item(item)['values']
                app_path, port = values[0], values[1]
                cache_key = f"{app_path}:{port}"

                # Remove from rules
                if cache_key in self.rules:
                    del self.rules[cache_key]

            # Save rules using pkexec (rules file is owned by root)
            try:
                import tempfile
                import subprocess

                # Write to temporary file
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp:
                    json.dump(self.rules, tmp, indent=2)
                    tmp_path = tmp.name

                # Use pkexec to copy temp file to /etc/douane/rules.json
                result = subprocess.run(
                    ['pkexec', 'cp', tmp_path, str(self.rules_file)],
                    capture_output=True,
                    text=True
                )

                # Clean up temp file
                os.unlink(tmp_path)

                if result.returncode == 0:
                    # Send SIGHUP to daemon to reload rules
                    try:
                        subprocess.run(['pkill', '-HUP', '-f', 'douane-daemon'], check=False)
                    except:
                        pass

                    self.update_rules_list()
                    messagebox.showinfo("Success", "Rule deleted and firewall reloaded!")
                else:
                    messagebox.showerror("Error", f"Failed to save rules: {result.stderr}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete rule: {e}")

    def clear_all_rules(self):
        """Clear all rules"""
        if messagebox.askyesno("Confirm", "Delete ALL rules? This cannot be undone!"):
            try:
                import tempfile
                import subprocess

                self.rules = {}

                # Write to temporary file
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp:
                    json.dump(self.rules, tmp, indent=2)
                    tmp_path = tmp.name

                # Use pkexec to copy temp file to /etc/douane/rules.json
                result = subprocess.run(
                    ['pkexec', 'cp', tmp_path, str(self.rules_file)],
                    capture_output=True,
                    text=True
                )

                # Clean up temp file
                os.unlink(tmp_path)

                if result.returncode == 0:
                    # Send SIGHUP to daemon to reload rules
                    try:
                        subprocess.run(['pkill', '-HUP', '-f', 'douane-daemon'], check=False)
                    except:
                        pass

                    self.update_rules_list()
                    messagebox.showinfo("Success", "All rules cleared and firewall reloaded!")
                else:
                    messagebox.showerror("Error", f"Failed to clear rules: {result.stderr}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear rules: {e}")

    def start_firewall(self):
        """Start the firewall service"""
        self.run_service_command('start')

    def stop_firewall(self):
        """Stop the firewall service"""
        if messagebox.askyesno("Confirm", "Stop the firewall?\n\nYour system will be unprotected."):
            self.run_service_command('stop')

    def restart_firewall(self):
        """Restart the firewall service"""
        if messagebox.askyesno("Confirm", "Restart the firewall?"):
            self.run_service_command('restart')

    def run_service_command(self, action):
        """Run systemctl command via pkexec"""
        try:
            # Create progress dialog
            progress_dialog = tk.Toplevel(self.root)
            progress_dialog.title(f"{action.title()}ing Firewall")
            progress_dialog.geometry("300x100")
            progress_dialog.transient(self.root)
            progress_dialog.grab_set()

            # Center dialog
            progress_dialog.update_idletasks()
            x = (progress_dialog.winfo_screenwidth() // 2) - (300 // 2)
            y = (progress_dialog.winfo_screenheight() // 2) - (100 // 2)
            progress_dialog.geometry(f"300x100+{x}+{y}")

            tk.Label(progress_dialog, text=f"Please wait, {action}ing service...", pady=20).pack()
            progress = ttk.Progressbar(progress_dialog, mode='indeterminate')
            progress.pack(fill='x', padx=20)
            progress.start(10)
            progress_dialog.update()

            # Execute systemctl
            subprocess.run(['pkexec', 'systemctl', action, 'douane-firewall'], check=True)
            
            # Start GUI client if starting
            if action in ['start', 'restart']:
                # The service starts the daemon. The GUI client is per-user and needs to be started manually or via autostart.
                # Check if already running for this user
                gui_running = subprocess.run(['pgrep', '-u', str(os.getuid()), '-f', 'douane-gui-client'], 
                                           capture_output=True).returncode == 0
                                           
                if not gui_running:
                    subprocess.Popen(['/usr/local/bin/douane-gui-client'], 
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Note: We do NOT kill the GUI client on stop anymore. 
            # It will detect the daemon stop and go into "Waiting" mode (Red/Grey icon).

            progress.stop()
            progress_dialog.destroy()
            
            # Force immediate poll
            self.poll_status()
            
            messagebox.showinfo("Success", f"Firewall {action}ed successfully")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to {action} firewall: {e}")
            if 'progress_dialog' in locals():
                progress_dialog.destroy()

    def run(self):
        """Run the control panel"""
        self.root.mainloop()


if __name__ == '__main__':
    app = DouaneControlPanel()
    app.run()

