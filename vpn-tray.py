#!/usr/bin/env python3
import argparse
import json
import os
import signal
import subprocess
import sys
import threading

_DETACHED = os.environ.get("VPN_TRAY_REEXEC") == "1"

LOG_PATH = os.path.expanduser("~/.cache/vpn-tray.log")


def _maybe_detach_to_background(background, tail_argv):
    """With --background only: re-exec detached (GTK is not fork-safe). Log to LOG_PATH."""
    if _DETACHED or not background:
        return
    log_dir = os.path.dirname(LOG_PATH)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    logf = open(LOG_PATH, "a", buffering=1)
    logf.write("\n--- vpn-tray detached launch ---\n")
    logf.flush()
    env = os.environ.copy()
    env["VPN_TRAY_REEXEC"] = "1"
    subprocess.Popen(
        [sys.executable, __file__, *tail_argv],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=logf,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    print(
        f"vpn-tray: running in background — tray only (window hidden). Log: {LOG_PATH}",
        file=sys.stderr,
        flush=True,
    )
    sys.exit(0)


import gi

gi.require_version("Gtk", "3.0")
try:
    gi.require_version("AppIndicator3", "0.1")
    from gi.repository import AppIndicator3

    HAS_INDICATOR = True
except Exception:
    HAS_INDICATOR = False

from gi.repository import GLib, Gtk

CONFIG_FILE = os.path.expanduser("~/.config/vpn-tray/settings.json")
os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)

VPS_IP = "IP_PLACEHOLDER"  # Yeah put your actual host IP here


def load_cfg():
    try:
        return json.loads(open(CONFIG_FILE).read())
    except Exception:
        return {"kill_switch": False, "auto_connect": False}


def save_cfg(d):
    open(CONFIG_FILE, "w").write(json.dumps(d, indent=2))


def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def is_connected():
    """Detect wg0 without sudo (autostart has no password prompt; sudo wg show often fails)."""
    r = run("ip link show wg0 2>/dev/null")
    if r.returncode != 0:
        return False
    return "LOWER_UP" in (r.stdout or "")


def connect():
    if is_connected():
        return True, ""
    r = run("sudo wg-quick up wg0 2>&1")
    text = (r.stdout or "") + (r.stderr or "")
    if r.returncode == 0:
        return True, text
    low = text.lower()
    if is_connected() and (
        "already exists" in low
        or "file exists" in low
        or ("rtnetlink" in low and "exists" in low)
    ):
        return True, text
    return False, text


def disconnect():
    run("nmcli device disconnect wg0 2>/dev/null")
    r = run("sudo wg-quick down wg0 2>&1")
    return r.returncode == 0, r.stdout + r.stderr


def _nft_ruleset(priority_spec):
    return f"""table inet vpn_tray_ks {{
  chain output {{
    type filter hook output priority {priority_spec};
    policy drop;
    meta oifname "lo" accept;
    meta oifname "wg0" accept;
    ip daddr {VPS_IP} accept;
    ip daddr 192.168.0.0/16 accept;
    ip daddr 10.0.0.0/8 accept;
    ip daddr 172.16.0.0/12 accept;
    ip6 daddr fe80::/10 accept;
    ip6 daddr ff02::/16 accept;
  }}
}}
"""


def _ipv6_suppress():
    """Clamp IPv6 only while VPN is down + kill switch (nft alone may not be enough)."""
    run("sudo sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null")
    run("sudo sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 2>/dev/null")


def _ipv6_restore():
    run("sudo sysctl -q -w net.ipv6.conf.all.disable_ipv6=0 2>/dev/null")
    run("sudo sysctl -q -w net.ipv6.conf.default.disable_ipv6=0 2>/dev/null")


def _strip_legacy_iptables():
    """Remove OUTPUT/INPUT lines from older vpn-tray (iptables-only). Best-effort."""
    v4_out = [
        ("OUTPUT", "-j REJECT"),
        ("OUTPUT", "-o wg0 -j ACCEPT"),
        ("OUTPUT", f"-d {VPS_IP} -j ACCEPT"),
        ("OUTPUT", "-d 172.16.0.0/12 -j ACCEPT"),
        ("OUTPUT", "-d 10.0.0.0/8 -j ACCEPT"),
        ("OUTPUT", "-d 192.168.0.0/16 -j ACCEPT"),
        ("OUTPUT", "-o lo -j ACCEPT"),
    ]
    v4_in = [
        ("INPUT", "-m state --state ESTABLISHED,RELATED -j ACCEPT"),
        ("INPUT", "-i lo -j ACCEPT"),
    ]
    v6_out = [
        ("OUTPUT", "-j REJECT"),
        ("OUTPUT", "-o wg0 -j ACCEPT"),
        ("OUTPUT", "-o lo -j ACCEPT"),
    ]
    v6_in = [
        ("INPUT", "-m state --state ESTABLISHED,RELATED -j ACCEPT"),
        ("INPUT", "-i lo -j ACCEPT"),
    ]
    for chain, spec in v4_out + v4_in:
        run(f"sudo iptables -D {chain} {spec} 2>/dev/null")
    for chain, spec in v6_out + v6_in:
        run(f"sudo ip6tables -D {chain} {spec} 2>/dev/null")


def apply_kill_switch(vpn_up: bool):
    """Load nft rules; clamp IPv6 sysctl only when tunnel is *down* (wg + ::/0 needs IPv6)."""
    _strip_legacy_iptables()
    last_err = ""
    for spec in ("-450", "filter - 150"):
        run("sudo nft delete table inet vpn_tray_ks 2>/dev/null")
        r = subprocess.run(
            ["sudo", "nft", "-f", "-"],
            input=_nft_ruleset(spec),
            text=True,
            capture_output=True,
        )
        if r.returncode == 0:
            break
        last_err = (r.stderr or "") + (r.stdout or "")
    else:
        sys.stderr.write(
            "vpn-tray: nft kill switch failed (tried priority -450 and filter -150).\n"
            + last_err
        )
        return
    if vpn_up:
        _ipv6_restore()
    else:
        _ipv6_suppress()


def remove_kill_switch():
    _ipv6_restore()
    run("sudo nft delete table inet vpn_tray_ks 2>/dev/null")
    _strip_legacy_iptables()


def flush_conntrack():
    run("sudo conntrack -F 2>/dev/null")


class VPNApp:
    def __init__(self):
        self.cfg = load_cfg()
        self.connected = is_connected()
        self.window_visible = False
        self.ind = None
        self.status_icon = None
        self._build_tray()
        self._build_window()
        if self.cfg.get("auto_connect") and not self.connected:
            threading.Thread(target=self._do_connect, daemon=True).start()
        elif self.cfg.get("kill_switch") and self.connected:
            apply_kill_switch(True)
        GLib.timeout_add_seconds(1, self._startup_sync_state)
        GLib.timeout_add_seconds(5, self._poll)


    def _build_window(self):
        self.win = Gtk.Window(title="VPN Manager")
        self.win.set_default_size(300, 220)
        self.win.set_resizable(False)
        self.win.set_border_width(24)
        self.win.connect("delete-event", self._hide_window)

        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self.win.add(vbox)

        self.status_label = Gtk.Label()
        self.status_label.set_halign(Gtk.Align.CENTER)
        vbox.pack_start(self.status_label, False, False, 0)

        self.vpn_btn = Gtk.Button()
        self.vpn_btn.connect("clicked", self._on_vpn_btn)
        vbox.pack_start(self.vpn_btn, False, False, 0)

        vbox.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 4)

        ks_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        ks_lbl = Gtk.Label(label="Kill Switch")
        ks_lbl.set_halign(Gtk.Align.START)
        ks_lbl.set_tooltip_text(
            "Block internet if VPN drops (nft). IPv6 is clamped only while disconnected so WireGuard ::/0 can start."
        )
        self.ks_switch = Gtk.Switch()
        self.ks_switch.set_active(self.cfg.get("kill_switch", False))
        self.ks_switch.connect("notify::active", self._on_ks)
        ks_box.pack_start(ks_lbl, True, True, 0)
        ks_box.pack_end(self.ks_switch, False, False, 0)
        vbox.pack_start(ks_box, False, False, 0)

        ac_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        ac_lbl = Gtk.Label(label="Auto Connect")
        ac_lbl.set_halign(Gtk.Align.START)
        ac_lbl.set_tooltip_text("Connect automatically on launch")
        self.ac_switch = Gtk.Switch()
        self.ac_switch.set_active(self.cfg.get("auto_connect", False))
        self.ac_switch.connect("notify::active", self._on_ac)
        ac_box.pack_start(ac_lbl, True, True, 0)
        ac_box.pack_end(self.ac_switch, False, False, 0)
        vbox.pack_start(ac_box, False, False, 0)

        self.err_label = Gtk.Label(label="")
        self.err_label.set_line_wrap(True)
        self.err_label.set_max_width_chars(36)
        self.err_label.get_style_context().add_class("error")
        vbox.pack_start(self.err_label, False, False, 0)

        css = b"""
        button { padding: 8px; font-size: 14px; }
        label.error { color: #e74c3c; font-size: 12px; }
        """
        provider = Gtk.CssProvider()
        provider.load_from_data(css)
        Gtk.StyleContext.add_provider_for_screen(
            self.win.get_screen(),
            provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )
        self._update_ui()

    def _hide_window(self, *_):
        self.win.hide()
        self.window_visible = False
        return True

    def _show_window(self, *_):
        self.win.show_all()
        self.win.present()
        self.window_visible = True

    def _toggle_window(self, *_):
        if self.win.get_visible():
            self._hide_window()
        else:
            self._show_window()

    def _build_tray(self):
        if HAS_INDICATOR:
            self.ind = AppIndicator3.Indicator.new(
                "vpn-tray",
                "network-vpn-symbolic",
                AppIndicator3.IndicatorCategory.SYSTEM_SERVICES,
            )
            self.ind.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
            menu = Gtk.Menu()
            show_item = Gtk.MenuItem(label="Open VPN Manager")
            show_item.connect("activate", self._show_window)
            menu.append(show_item)
            menu.append(Gtk.SeparatorMenuItem())
            quit_item = Gtk.MenuItem(label="Quit")
            quit_item.connect("activate", self._quit)
            menu.append(quit_item)
            menu.show_all()
            self.ind.set_menu(menu)
            self.ind.connect("scroll-event", lambda *_: self._toggle_window())
        else:
            self.status_icon = Gtk.StatusIcon.new_from_icon_name("network-vpn-symbolic")
            self.status_icon.set_tooltip_text("VPN Manager")
            self.status_icon.connect("activate", self._toggle_window)
            self.status_icon.connect("popup-menu", self._tray_menu)

    def _tray_menu(self, icon, button, time):
        menu = Gtk.Menu()
        quit_item = Gtk.MenuItem(label="Quit")
        quit_item.connect("activate", self._quit)
        menu.append(quit_item)
        menu.show_all()
        menu.popup(None, None, None, None, button, time)

    def _on_vpn_btn(self, _):
        self.vpn_btn.set_sensitive(False)
        self.err_label.set_text("")
        if self.connected:
            threading.Thread(target=self._do_disconnect, daemon=True).start()
        else:
            threading.Thread(target=self._do_connect, daemon=True).start()

    def _startup_sync_state(self):
        """Re-sync after login: first is_connected() can miss before session is ready."""
        prev = self.connected
        self.connected = is_connected()
        if self.connected != prev:
            if not self.connected and self.cfg.get("kill_switch"):
                apply_kill_switch(False)
                flush_conntrack()
            elif self.connected and self.cfg.get("kill_switch"):
                apply_kill_switch(True)
            if self.connected:
                GLib.idle_add(self.err_label.set_text, "")
            GLib.idle_add(self._update_ui)
        return False

    def _do_connect(self):
        if is_connected():
            self.connected = True
            if self.cfg.get("kill_switch"):
                apply_kill_switch(True)
            GLib.idle_add(self.err_label.set_text, "")
            GLib.idle_add(self._update_ui)
            GLib.idle_add(self.vpn_btn.set_sensitive, True)
            return
        if self.cfg.get("kill_switch"):
            _ipv6_restore()
        ok, msg = connect()
        if ok:
            self.connected = True
            if self.cfg.get("kill_switch"):
                apply_kill_switch(True)
        else:
            if self.cfg.get("kill_switch"):
                apply_kill_switch(False)
            GLib.idle_add(self.err_label.set_text, msg.strip()[-120:])
        GLib.idle_add(self._update_ui)
        GLib.idle_add(self.vpn_btn.set_sensitive, True)

    def _do_disconnect(self):
        if not self.cfg.get("kill_switch"):
            remove_kill_switch()
        ok, msg = disconnect()
        if ok:
            self.connected = False
            if self.cfg.get("kill_switch"):
                flush_conntrack()
                apply_kill_switch(False)
        else:
            GLib.idle_add(self.err_label.set_text, msg.strip()[-120:])
        GLib.idle_add(self._update_ui)
        GLib.idle_add(self.vpn_btn.set_sensitive, True)

    def _on_ks(self, switch, _):
        self.cfg["kill_switch"] = switch.get_active()
        save_cfg(self.cfg)
        if self.cfg["kill_switch"]:
            apply_kill_switch(self.connected)
        else:
            remove_kill_switch()

    def _on_ac(self, switch, _):
        self.cfg["auto_connect"] = switch.get_active()
        save_cfg(self.cfg)

    def _update_ui(self):
        if self.connected:
            self.status_label.set_markup(
                "<span size='large' foreground='#2ecc71'><b>● Connected</b></span>"
            )
            self.vpn_btn.set_label("Disconnect")
            if HAS_INDICATOR and self.ind:
                self.ind.set_icon_full("network-vpn-symbolic", "Connected")
        else:
            self.status_label.set_markup("<span size='large'><b>○ Disconnected</b></span>")
            self.vpn_btn.set_label("Connect")
            if HAS_INDICATOR and self.ind:
                self.ind.set_icon_full("network-offline-symbolic", "Disconnected")
        return False

    def _poll(self):
        prev = self.connected
        self.connected = is_connected()
        if self.connected != prev:
            if not self.connected and self.cfg.get("kill_switch"):
                apply_kill_switch(False)
                flush_conntrack()
            GLib.idle_add(self._update_ui)
        return True

    def _shutdown_network(self):
        remove_kill_switch()
        if self.connected:
            disconnect()

    def _quit(self, *_):
        self._shutdown_network()
        Gtk.main_quit()

    def run(self, show_window=True):
        if show_window:
            self._show_window()
        else:
            self.win.show_all()
            self.win.hide()
            self.window_visible = False

        def _glib_sig_quit():
            self._quit()
            return False

        GLib.unix_signal_add(GLib.PRIORITY_HIGH, signal.SIGINT, _glib_sig_quit)
        GLib.unix_signal_add(GLib.PRIORITY_HIGH, signal.SIGTERM, _glib_sig_quit)

        try:
            Gtk.main()
        except KeyboardInterrupt:
            self._shutdown_network()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WireGuard tray (wg0)")
    parser.add_argument(
        "-b",
        "--background",
        action="store_true",
        help="Detach from terminal; tray only; append logs to ~/.cache/vpn-tray.log",
    )
    args, rest = parser.parse_known_args()
    sys.argv = [sys.argv[0]] + rest

    _maybe_detach_to_background(args.background, rest)

    show_window = not (args.background or _DETACHED)
    VPNApp().run(show_window=show_window)
