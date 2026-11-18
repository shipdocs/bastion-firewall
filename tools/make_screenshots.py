#!/usr/bin/env python3
"""
Regenerate the website and README screenshots from the real Qt windows.

Renders the control panel pages and the connection popup offscreen with DEMO
data (no real rules, logs or USB devices are read, nothing talks to the
daemon), then writes web-sized PNG + WebP files and a 1200x630 link-preview
card.

    QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=2 PYTHONPATH=. \
        python3 tools/make_screenshots.py

Output: docs/screenshots/ (website) and screenshots/ (README).
Needs PyQt6 and Pillow (with WebP support).
"""
import json, os, sys, subprocess, types
import tempfile
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = tempfile.mkdtemp(prefix="bastion-shots-")
DEMO = os.path.join(OUT, "_demo")
os.makedirs(DEMO, exist_ok=True)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

RULES = {
    "applications": {}, "services": {},
    "/usr/lib/firefox/firefox:443": True,
    "/usr/lib/firefox/firefox:80": True,
    "/usr/lib/thunderbird/thunderbird:993": True,
    "/usr/lib/thunderbird/thunderbird:465": True,
    "/usr/share/code/code:443": True,
    "/usr/bin/git:22": True,
    "/usr/lib/git-core/git-remote-http:443": True,
    "/opt/zoom/zoom:*": True,
    "/usr/bin/curl:443": True,
    "/usr/bin/wget:80": False,
    "/usr/bin/python3.12:8080": False,
    "/usr/bin/gnome-software:443": True,
    "/usr/lib/apt/methods/http:80": True,
    "/snap/spotify/current/usr/share/spotify/spotify:4070": True,
    "/opt/telemetry-agent/agent:443": False,
}
CONFIG = {"mode": "enforcement", "usb_control": True}
json.dump(RULES, open(os.path.join(DEMO, "rules.json"), "w"))
json.dump(CONFIG, open(os.path.join(DEMO, "config.json"), "w"))

def jl(t, msg):  # one journal line in the daemon's format
    return f"Nov 18 {t} workstation bastion-daemon[1234]: [2026-11-18T{t}Z INFO  bastion_daemon] {msg}"
LOG = [
    jl("09:12:03", '[RULE:ALLOW] app="firefox" dst="140.82.112.3:443" user=1000'),
    jl("09:12:05", '[RULE:ALLOW] app="thunderbird" dst="185.70.42.37:993" user=1000'),
    jl("09:12:41", '[POPUP] curl (/usr/bin/curl) -> 104.16.24.34:443'),
    jl("09:12:44", '[USER:ALLOW] app="curl" dst="104.16.24.34:443" user=1000'),
    jl("09:13:10", '[RULE:BLOCK] app="agent" dst="34.117.59.81:443" user=1000'),
    jl("09:13:58", '[RULE:ALLOW] app="code" dst="13.107.42.18:443" user=1000'),
    jl("09:14:22", '[POPUP] wget (/usr/bin/wget) -> 93.184.215.14:80'),
    jl("09:14:30", '[USER:BLOCK] app="wget" dst="93.184.215.14:80" user=1000'),
    jl("09:15:02", '[RULE:ALLOW] app="zoom" dst="170.114.52.2:8801" user=1000'),
    jl("09:15:40", '[SESSION:ALLOW] app="python3" dst="151.101.0.223:443"'),
    jl("09:16:11", '[RULE:BLOCK] app="python3.12" dst="203.0.113.50:8080" user=1000'),
    jl("09:16:45", '[RULE:ALLOW] app="git" dst="140.82.121.4:22" user=1000'),
    jl("09:17:20", '[RULE:ALLOW] app="firefox" dst="142.250.179.206:443" user=1000'),
    jl("09:17:52", '[RULE:ALLOW] app="spotify" dst="35.186.224.25:4070" user=1000'),
    jl("09:18:30", '[RULE:BLOCK] app="agent" dst="34.117.59.81:443" user=1000'),
]
USB = (True, {
    "046d:c52b:*": {"verdict": "allow", "vendor_name": "Logitech", "product_name": "Unifying Receiver", "scope": "model", "added": "2026-11-02"},
    "0781:5583:4C530001": {"verdict": "allow", "vendor_name": "SanDisk", "product_name": "Ultra Fit", "scope": "device", "added": "2026-11-10"},
    "05ac:*:*": {"verdict": "block", "vendor_name": "Apple", "product_name": "", "scope": "vendor", "added": "2026-11-14"},
})

real_run = subprocess.run
def fake_run(cmd, *a, **k):
    if isinstance(cmd, list) and cmd[:2] == ["systemctl", "is-active"]:
        return subprocess.CompletedProcess(cmd, 0, "active\n", "")
    if isinstance(cmd, list) and cmd[:2] == ["systemctl", "is-enabled"]:
        return subprocess.CompletedProcess(cmd, 0, "enabled\n", "")
    if isinstance(cmd, list) and cmd and cmd[0] == "journalctl":
        return subprocess.CompletedProcess(cmd, 0, "\n".join(LOG) + "\n", "")
    return subprocess.CompletedProcess(cmd, 1, "", "disabled for screenshots")
subprocess.run = fake_run

sys.path.insert(0, REPO)
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer
app = QApplication(sys.argv)

import bastion.gui_qt as gq
from pathlib import Path
gq.DaemonStatsClient.start = lambda self: None
gq.InboundFirewallDetector.detect_firewall = staticmethod(
    lambda: {"active": True, "firewall": "UFW", "type": "ufw"})
gq.list_usb_rules = lambda *a, **k: USB
orig_load = gq.DashboardWindow.load_data
def demo_load(self):
    self.rules_path = Path(DEMO, "rules.json")
    self.config_path = Path(DEMO, "config.json")
    orig_load(self)
gq.DashboardWindow.load_data = demo_load

w = gq.DashboardWindow()
w.timer.stop()
w.live_stats.update({"total_connections": 18342, "allowed_connections": 18015,
                     "blocked_connections": 327, "learning_mode": False})
w.resize(1180, 760)
w.show()

def settle(ms=300):
    t = QTimer(); t.setSingleShot(True); t.start(ms)
    while t.isActive():
        app.processEvents()

pages = [("status", "Status"), ("rules", "Rules"), ("logs", "Logs"), ("usb", "USB"), ("settings", "Settings")]
for fname, page in pages:
    btn = [b for b in w.nav_btns if b.text().strip() == page][0]
    w.resize(1180, 520 if page == "Status" else 760)
    btn.click()
    if page == "Status":
        w.update_stats_display()
    settle()
    w.grab().save(os.path.join(OUT, f"{fname}.png"))
    print("saved", fname)

# Connection popup (enforcement mode), with the destination lookup disabled
from bastion.gui.dialogs.firewall_dialog import FirewallDialog
FirewallDialog._lookup_dest_info_async = lambda self, ip, port: None
d = FirewallDialog({"app_name": "curl", "app_path": "/usr/bin/curl", "dest_ip": "104.16.24.34",
                    "dest_port": 443, "protocol": "TCP", "learning_mode": False}, timeout=60)
d.dest_label.setText("registry.npmjs.org (104.16.24.34):443")
d.show(); settle(400)
d.grab().save(os.path.join(OUT, "popup.png"))
print("saved popup")


# --- Web sizes, WebP and the link-preview card ---------------------------------
import shutil
from PIL import Image, ImageDraw, ImageFont

WEB = os.path.join(REPO, "docs", "screenshots")
README = os.path.join(REPO, "screenshots")
os.makedirs(WEB, exist_ok=True)
for name in ["status", "rules", "logs", "usb", "settings", "popup"]:
    im = Image.open(os.path.join(OUT, f"{name}.png")).convert("RGB")
    width = 800 if name == "popup" else 1600
    im = im.resize((width, round(im.height * width / im.width)), Image.LANCZOS)
    im.save(os.path.join(WEB, f"{name}.png"), optimize=True)
    im.save(os.path.join(WEB, f"{name}.webp"), quality=82, method=6)
    shutil.copy(os.path.join(WEB, f"{name}.png"), os.path.join(README, f"{name}.png"))
    print("web", name, im.size)

def font(weight, size):
    for path in (f"/usr/share/fonts/truetype/inter-zorin-os/Inter-{weight}.ttf",
                 f"/usr/share/fonts/truetype/inter/Inter-{weight}.ttf",
                 "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"):
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()

W, H = 1200, 630
card = Image.new("RGB", (W, H))
draw = ImageDraw.Draw(card)
for y in range(H):
    t = y / H
    draw.line([(0, y), (W, y)], fill=(int(15 + 15 * t), int(23 + 18 * t), int(42 + 40 * t)))
draw.text((70, 150), "Bastion Firewall", font=font("ExtraBold", 66), fill="#f1f5f9")
draw.text((70, 250), "Outbound application", font=font("SemiBold", 34), fill="#a5b4fc")
draw.text((70, 292), "firewall for Linux", font=font("SemiBold", 34), fill="#a5b4fc")
draw.text((70, 380), "Asks per program before it", font=font("Regular", 26), fill="#cbd5e1")
draw.text((70, 416), "may connect to the internet.", font=font("Regular", 26), fill="#cbd5e1")
draw.text((70, 490), "Free & open source  \u00b7  Rust + eBPF", font=font("Regular", 26), fill="#94a3b8")
popup = Image.open(os.path.join(OUT, "popup.png")).convert("RGB")
ph = 530
pw = round(popup.width * ph / popup.height)
popup = popup.resize((pw, ph), Image.LANCZOS)
x, y = W - pw - 60, (H - ph) // 2
draw.rounded_rectangle([x - 4, y - 4, x + pw + 3, y + ph + 3], radius=10, outline="#6366f1", width=4)
card.paste(popup, (x, y))
card.save(os.path.join(WEB, "social-card.png"), optimize=True)
print("web social-card", card.size)
shutil.rmtree(OUT, ignore_errors=True)
