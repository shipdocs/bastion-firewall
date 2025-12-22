import subprocess
import os

def check_status():
    print("-" * 20)
    res = subprocess.run(['systemctl', 'is-enabled', 'bastion-firewall'], capture_output=True, text=True)
    print(f"Exit Code: {res.returncode}")
    print(f"Stdout: {repr(res.stdout)}")
    print(f"Stderr: {repr(res.stderr)}")
    is_enabled = res.stdout.strip() == 'enabled'
    print(f"Is Enabled? {is_enabled}")

print("Initial State:")
check_status()

# Simulate Enable
print("\nEnabling via pkexec...")
try:
    # Use sudo non-interactive for testing instead of pkexec which needs GUI/tty
    subprocess.run(['sudo', 'systemctl', 'enable', 'bastion-firewall'], check=True)
    print("Enable command success")
except Exception as e:
    print(f"Enable failed: {e}")

check_status()

# Simulate Disable
print("\nDisabling via pkexec...")
try:
    subprocess.run(['sudo', 'systemctl', 'disable', 'bastion-firewall'], check=True)
    print("Disable command success")
except Exception as e:
    print(f"Disable failed: {e}")

check_status()
