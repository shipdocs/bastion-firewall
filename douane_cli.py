#!/usr/bin/env python3
"""
Douane CLI - Command-line interface for managing firewall rules.
"""

import sys
import sqlite3
import argparse
from pathlib import Path
from typing import List, Tuple
from tabulate import tabulate

# Configuration
CONFIG_DIR = Path.home() / ".config" / "douane"
DB_PATH = CONFIG_DIR / "rules.db"


class DouaneCLI:
    """Command-line interface for Douane."""
    
    def __init__(self):
        self.db_path = DB_PATH
        
        if not self.db_path.exists():
            print(f"Error: Database not found at {self.db_path}")
            print("The daemon must be run at least once to create the database.")
            sys.exit(1)
    
    def list_rules(self):
        """List all rules."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT executable_path, permission, duration, 
                   datetime(created_at, 'localtime') as created,
                   datetime(updated_at, 'localtime') as updated
            FROM rules 
            ORDER BY updated_at DESC
        """)
        
        rules = cursor.fetchall()
        conn.close()
        
        if not rules:
            print("No rules found.")
            return
        
        # Format for display
        headers = ["Application", "Permission", "Duration", "Created", "Updated"]
        table_data = []
        
        for rule in rules:
            exe_path, permission, duration, created, updated = rule
            app_name = Path(exe_path).name
            table_data.append([
                app_name,
                permission.upper(),
                duration,
                created,
                updated
            ])
        
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nTotal: {len(rules)} rule(s)")
    
    def delete_rule(self, app_path: str):
        """Delete a rule for an application."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM rules WHERE executable_path = ?", (app_path,))
        deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        if deleted > 0:
            print(f"✓ Deleted rule for: {app_path}")
        else:
            print(f"✗ No rule found for: {app_path}")
    
    def add_rule(self, app_path: str, permission: str, duration: str):
        """Add a rule for an application."""
        if permission not in ['allow', 'deny']:
            print("Error: permission must be 'allow' or 'deny'")
            sys.exit(1)
        
        if duration not in ['once', 'always']:
            print("Error: duration must be 'once' or 'always'")
            sys.exit(1)
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO rules (executable_path, permission, duration)
            VALUES (?, ?, ?)
            ON CONFLICT(executable_path) 
            DO UPDATE SET 
                permission = excluded.permission,
                duration = excluded.duration,
                updated_at = CURRENT_TIMESTAMP
        """, (app_path, permission, duration))
        
        conn.commit()
        conn.close()
        
        print(f"✓ Rule added: {app_path} -> {permission} ({duration})")
    
    def show_logs(self, limit: int = 50):
        """Show recent connection logs."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT executable_path, destination, port, protocol, action,
                   datetime(timestamp, 'localtime') as time
            FROM connection_log 
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        
        logs = cursor.fetchall()
        conn.close()
        
        if not logs:
            print("No connection logs found.")
            return
        
        # Format for display
        headers = ["Application", "Destination", "Port", "Protocol", "Action", "Time"]
        table_data = []
        
        for log in logs:
            exe_path, dest, port, protocol, action, time = log
            app_name = Path(exe_path).name
            table_data.append([
                app_name,
                dest,
                port,
                protocol,
                action.upper(),
                time
            ])
        
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nShowing {len(logs)} most recent connection(s)")
    
    def clear_logs(self):
        """Clear connection logs."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM connection_log")
        deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        print(f"✓ Cleared {deleted} log entries")
    
    def stats(self):
        """Show statistics."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Count rules
        cursor.execute("SELECT COUNT(*) FROM rules")
        total_rules = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM rules WHERE permission = 'allow'")
        allowed = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM rules WHERE permission = 'deny'")
        denied = cursor.fetchone()[0]
        
        # Count logs
        cursor.execute("SELECT COUNT(*) FROM connection_log")
        total_connections = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM connection_log WHERE action = 'allow'")
        connections_allowed = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM connection_log WHERE action = 'deny'")
        connections_denied = cursor.fetchone()[0]
        
        conn.close()
        
        print("\n=== Douane Statistics ===\n")
        print(f"Rules:")
        print(f"  Total:   {total_rules}")
        print(f"  Allowed: {allowed}")
        print(f"  Denied:  {denied}")
        print()
        print(f"Connections:")
        print(f"  Total:   {total_connections}")
        print(f"  Allowed: {connections_allowed}")
        print(f"  Denied:  {connections_denied}")
        print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Douane CLI - Manage application firewall rules"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # List rules
    subparsers.add_parser('list', help='List all rules')
    
    # Add rule
    add_parser = subparsers.add_parser('add', help='Add a rule')
    add_parser.add_argument('path', help='Application executable path')
    add_parser.add_argument('permission', choices=['allow', 'deny'], 
                           help='Allow or deny')
    add_parser.add_argument('duration', choices=['once', 'always'], 
                           help='Once or always')
    
    # Delete rule
    delete_parser = subparsers.add_parser('delete', help='Delete a rule')
    delete_parser.add_argument('path', help='Application executable path')
    
    # Show logs
    logs_parser = subparsers.add_parser('logs', help='Show connection logs')
    logs_parser.add_argument('--limit', type=int, default=50, 
                            help='Number of logs to show (default: 50)')
    
    # Clear logs
    subparsers.add_parser('clear-logs', help='Clear connection logs')
    
    # Statistics
    subparsers.add_parser('stats', help='Show statistics')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    cli = DouaneCLI()
    
    if args.command == 'list':
        cli.list_rules()
    elif args.command == 'add':
        cli.add_rule(args.path, args.permission, args.duration)
    elif args.command == 'delete':
        cli.delete_rule(args.path)
    elif args.command == 'logs':
        cli.show_logs(args.limit)
    elif args.command == 'clear-logs':
        cli.clear_logs()
    elif args.command == 'stats':
        cli.stats()


if __name__ == "__main__":
    main()
