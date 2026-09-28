# USB Device Control

Bastion can block new USB devices until you approve them. It is **off by default**.

## How it works

With `usb_control` enabled the daemon:

1. Sets `authorized_default=0` on every USB root hub, so the kernel leaves newly attached devices disabled.
2. Leaves devices that are **already connected** alone (your keyboard keeps working), unless a saved *block* rule matches them.
3. For each new device looks for a saved rule (exact device, then model, then vendor). A match is applied without asking.
4. With no rule it asks the GUI. **No GUI, no answer, or a timeout leaves the device blocked.**

Devices that can type or create network interfaces (keyboards/mice, CDC network and modem adapters, wireless
adapters) are marked with a warning in the prompt.

Decisions are stored in `/etc/bastion/usb_rules.json` (mode `0640`). The control panel's **USB** page lists and
deletes them. Deleting an *allow* rule does not disconnect the device; you are asked the next time it is attached.

## Turning it on

Either tick **Block new USB devices until I approve them** on the control panel's USB page and save, or edit
`/etc/bastion/config.json`:

```json
{
  "usb_control": true,
  "usb_prompt_timeout_secs": 30
}
```

Then restart the service: `sudo systemctl restart bastion-firewall`.
Setting it back to `false` and restarting restores the kernel default, but only if Bastion itself set it.

The prompt is shown by the tray GUI (`bastion-gui`), which must be running for a device to be approved.

## Build and run locally

```bash
# Build dependencies (Debian/Ubuntu)
sudo apt install build-essential pkg-config libudev-dev libnetfilter-queue-dev libpcap-dev \
    libgtk-3-dev libayatana-appindicator3-dev libxdo-dev python3-pyqt6

# Build the daemon
cd bastion-rs && cargo build --release && cd ..

# Run the tests
(cd bastion-rs && cargo test --lib && cargo test --bin bastion-daemon)
python3 -m pytest tests/test_usb_client.py
```

To try it without installing the package:

```bash
sudo groupadd -f bastion && sudo usermod -aG bastion "$USER"   # then log out and in
sudo mkdir -p /etc/bastion /var/run/bastion
echo '{"mode":"learning","usb_control":true}' | sudo tee /etc/bastion/config.json
sudo ./bastion-rs/target/release/bastion-daemon        # terminal 1
python3 bastion-gui.py                                  # terminal 2, as your user
python3 bastion_control_panel.py                        # optional: USB page
```

Plug in a USB stick you have not approved before: the prompt appears. For a full install use
`./build_deb.sh` (needs the eBPF toolchain from the README) and `sudo dpkg -i bastion-firewall_*_amd64.deb`.

## Security notes

- The GUI socket is limited to `root` and the `bastion` group. Only the GUI that owns the prompt channel can answer
  prompts, and each answer must carry the random one-time nonce of a pending request.
- A second GUI (for example the control panel) can only list and delete USB rules; it cannot answer prompts.
- Device names, vendors and serials are untrusted: they are sanitised, shown as plain text, and a serial that had to be
  altered gets a hash suffix so different serials never share a rule.
- Rules use `O_NOFOLLOW` reads and atomic writes. A device-level rule requires a real serial number.

## Known limits

- Toggling `usb_control` needs a service restart.
- The prompt closes itself two seconds before the daemon's `usb_prompt_timeout_secs` and blocks the device.
- Tested with unit tests and mocked sysfs; please check it on real hardware before relying on it.
