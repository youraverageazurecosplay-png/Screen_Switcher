import subprocess
from pynput.keyboard import KeyCode, Listener
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import os
import hashlib
import sys


# -----------------------------
# License system (per-device key + hidden role)
# -----------------------------


SECRET_SALT = "20131028"  # must match your key scheme

ROLE_BASIC = 1
ROLE_ADMIN = 2

LICENSE_FILE = "bob_license.dat"  # stores last key + role

current_role = ROLE_BASIC  # default


def get_device_id():
    try:
        out = subprocess.check_output(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            text=True
        )
        for line in out.splitlines():
            line = line.strip()
            if "IOPlatformUUID" in line:
                return line.split('"')[-2]
    except Exception:
        pass
    return "unknown-device"


def generate_raw_bytes(device_id: str, role_code: int) -> bytes:
    data = (device_id + str(role_code) + SECRET_SALT).encode("utf-8")
    return hashlib.sha256(data).digest()


def embed_role_in_hash(digest: bytes, role_code: int) -> bytes:
    first = digest[0]
    first = (first & 0xF0) | (role_code & 0x0F)
    return bytes([first]) + digest[1:]


def expected_key_for_device(device_id: str, role_code: int) -> str:
    d = generate_raw_bytes(device_id, role_code)
    d2 = embed_role_in_hash(d, role_code)
    return d2.hex()[:8].upper()


def role_name(role_code: int) -> str:
    return "Basic" if role_code == ROLE_BASIC else "Admin"


def save_license(key: str, role_code: int):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), LICENSE_FILE)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"{key}\n{role_code}\n")
    except Exception:
        pass


def load_license():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), LICENSE_FILE)
    if not os.path.exists(path):
        return None, None
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().strip().splitlines()
        if len(lines) < 2:
            return None, None
        key = lines[0].strip().upper()
        role_code = int(lines[1].strip())
        return key, role_code
    except Exception:
        return None, None


def clear_license_file():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), LICENSE_FILE)
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def validate_key_for_device(device_id: str, key: str):
    key = key.strip().upper()
    if len(key) != 8 or any(c not in "0123456789ABCDEF" for c in key):
        return None

    for role_code in (ROLE_BASIC, ROLE_ADMIN):
        expected = expected_key_for_device(device_id, role_code)
        if key == expected:
            return role_code
    return None


# -----------------------------
# Config handling
# -----------------------------


CONFIG_FILENAME = "emergency_config.txt"

apps_to_close = ["Roblox", "Geometry"]
switch_to_app = "Comet"
hotkey_close_switch = "["
hotkey_switch_only = "]"
hotkey_config_key = "'"
show_notifications = True


def get_config_path():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, CONFIG_FILENAME)


def load_config():
    global apps_to_close, switch_to_app, hotkey_close_switch, hotkey_switch_only, hotkey_config_key
    global show_notifications

    path = get_config_path()
    if not os.path.exists(path):
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip().lower()
                value = value.strip()

                if key == "apps_to_close":
                    apps_to_close = [a.strip() for a in value.split(",") if a.strip()]
                elif key == "switch_to_app":
                    switch_to_app = value
                elif key == "hotkey_close_switch":
                    hotkey_close_switch = value
                elif key == "hotkey_switch_only":
                    hotkey_switch_only = value
                elif key == "hotkey_config_key":
                    hotkey_config_key = value
                elif key == "show_notifications":
                    show_notifications = (value.lower() == "true")
    except Exception as e:
        print("Failed to load config:", e)


def save_config():
    path = get_config_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Emergency button config\n")
            f.write(f"apps_to_close={', '.join(apps_to_close)}\n")
            f.write(f"switch_to_app={switch_to_app}\n")
            f.write(f"hotkey_close_switch={hotkey_close_switch}\n")
            f.write(f"hotkey_switch_only={hotkey_switch_only}\n")
            f.write(f"hotkey_config_key={hotkey_config_key}\n")
            f.write(f"show_notifications={'true' if show_notifications else 'false'}\n")
    except Exception as e:
        print("Failed to save config:", e)


# -----------------------------
# Core emergency functions
# -----------------------------


def notify(message):
    if not show_notifications:
        return
    subprocess.run([
        "osascript", "-e",
        f'display notification "{message}" with title "Emergency Button"'
    ])


def close_apps_and_switch():
    notify("Bob Initiated: Apps closed, switching.")
    for app in apps_to_close:
        app = app.strip()
        if app:
            subprocess.run([
                "osascript", "-e",
                f'tell application "{app}" to quit'
            ])
    if switch_to_app.strip():
        subprocess.run([
            "osascript", "-e",
            f'tell application "{switch_to_app.strip()}" to activate'
        ])


def switch_to_comet_only():
    notify("Bob Initiated: Switching only.")
    if switch_to_app.strip():
        subprocess.run([
            "osascript", "-e",
            f'tell application "{switch_to_app.strip()}" to activate'
        ])


def hide_terminal_once():
    try:
        subprocess.run([
            "osascript",
            "-e",
            '''
tell application "System Events"
    if exists process "Terminal" then
        set visible of process "Terminal" to false
    end if
end tell
'''
        ])
    except Exception:
        pass


# -----------------------------
# Dev Panel (includes built-in key generator)
# -----------------------------


class DevPanel:
    def __init__(self, parent, device_id):
        self.parent = parent
        self.device_id = device_id
        self.top = tk.Toplevel(parent.root)
        self.top.title("Bob Dev Panel")
        self.top.resizable(False, False)

        frame = ttk.Frame(self.top, padding=10)
        frame.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frame, text=f"Device: {device_id}", foreground="blue").grid(row=0, column=0, sticky="w")
        ttk.Label(frame, text=f"Current role: {role_name(current_role)}").grid(row=1, column=0, sticky="w", pady=(0, 10))

        ttk.Button(frame, text="Clear permissions (log out)", command=self.clear_perms).grid(row=2, column=0, sticky="w", pady=(0, 10))

        sep = ttk.Separator(frame, orient="horizontal")
        sep.grid(row=3, column=0, sticky="ew", pady=(0, 10))

        ttk.Label(frame, text="Generate key for device ID:").grid(row=4, column=0, sticky="w")
        self.dev_entry = ttk.Entry(frame, width=40)
        self.dev_entry.grid(row=5, column=0, sticky="w")
        self.dev_entry.insert(0, device_id)

        self.role_var = tk.IntVar(value=ROLE_BASIC)
        role_frame = ttk.Frame(frame)
        role_frame.grid(row=6, column=0, sticky="w", pady=(5, 5))
        ttk.Label(role_frame, text="Access level:").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(role_frame, text="Basic", variable=self.role_var, value=ROLE_BASIC).grid(row=1, column=0, sticky="w")
        ttk.Radiobutton(role_frame, text="Admin", variable=self.role_var, value=ROLE_ADMIN).grid(row=1, column=1, sticky="w", padx=(10, 0))

        ttk.Button(frame, text="Generate key", command=self.generate_key).grid(row=7, column=0, sticky="w")

        ttk.Label(frame, text="Generated key:").grid(row=8, column=0, sticky="w", pady=(10, 0))
        self.key_entry = ttk.Entry(frame, width=40)
        self.key_entry.grid(row=9, column=0, sticky="w")

        ttk.Button(frame, text="Copy key", command=self.copy_key).grid(row=10, column=0, sticky="e", pady=(5, 0))

    def clear_perms(self):
        clear_license_file()
        messagebox.showinfo("Bob Dev", "Permissions cleared. Next run will ask for a key again.")

    def generate_key(self):
        dev = self.dev_entry.get().strip()
        if not dev:
            messagebox.showerror("Error", "Please enter a device ID.")
            return
        role_code = self.role_var.get()
        key = expected_key_for_device(dev, role_code)
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key)

    def copy_key(self):
        key = self.key_entry.get().strip()
        if not key:
            messagebox.showerror("Error", "No key to copy.")
            return
        self.top.clipboard_clear()
        self.top.clipboard_append(key)
        self.top.update()
        messagebox.showinfo("Copied", "Key copied to clipboard.")


# -----------------------------
# GUI (Tkinter)
# -----------------------------


class EmergencyAppGUI:
    def __init__(self, root, device_id):
        self.root = root
        self.device_id = device_id
        self.root.title("Bob")
        self.root.resizable(False, False)

        self.config_visible = False
        self.panel_visible = False

        self.innocent_frame = ttk.Frame(self.root, padding=10)
        self.innocent_frame.grid(row=0, column=0, sticky="nsew")

        self.bob_label = ttk.Label(self.innocent_frame, text="Bob", font=("Helvetica", 16))
        self.bob_label.grid(row=0, column=0, pady=(0, 10))

        self.status_label = ttk.Label(self.innocent_frame, text="Bob is running. Nothing to see here.")
        self.status_label.grid(row=1, column=0, pady=(0, 10))

        self.panel_frame = ttk.Frame(self.innocent_frame)
        self.panel_config_button = ttk.Button(self.panel_frame, text="Config", command=self.show_config_view)
        self.panel_config_button.grid(row=0, column=0, padx=(0, 5))
        self.panel_hide_button = ttk.Button(self.panel_frame, text="Hide", command=self.hide_window)
        self.panel_hide_button.grid(row=0, column=1, padx=(5, 0))

        self.config_frame = ttk.Frame(self.root, padding=10)

        self.apps_label = ttk.Label(self.config_frame, text="Apps to close (comma-separated):")
        self.apps_label.grid(row=0, column=0, sticky="w")

        self.apps_entry = ttk.Entry(self.config_frame, width=35)
        self.apps_entry.grid(row=1, column=0, pady=(0, 10), sticky="ew")

        self.switch_label = ttk.Label(self.config_frame, text="Switch-to app (e.g. Comet):")
        self.switch_label.grid(row=2, column=0, sticky="w")

        self.switch_entry = ttk.Entry(self.config_frame, width=35)
        self.switch_entry.grid(row=3, column=0, pady=(0, 10), sticky="ew")

        self.hotkey_close_label = ttk.Label(self.config_frame, text="Close+switch hotkey (single key):")
        self.hotkey_close_label.grid(row=4, column=0, sticky="w")

        self.hotkey_close_entry = ttk.Entry(self.config_frame, width=10)
        self.hotkey_close_entry.grid(row=5, column=0, sticky="w", pady=(0, 5))

        self.hotkey_switch_label = ttk.Label(self.config_frame, text="Switch-only hotkey (single key):")
        self.hotkey_switch_label.grid(row=6, column=0, sticky="w")

        self.hotkey_switch_entry = ttk.Entry(self.config_frame, width=10)
        self.hotkey_switch_entry.grid(row=7, column=0, sticky="w", pady=(0, 5))

        self.hotkey_config_label = ttk.Label(self.config_frame, text="Config key (held to show panel):")
        self.hotkey_config_label.grid(row=8, column=0, sticky="w")

        self.hotkey_config_entry = ttk.Entry(self.config_frame, width=10)
        self.hotkey_config_entry.grid(row=9, column=0, sticky="w", pady=(0, 5))

        self.notify_label = ttk.Label(self.config_frame, text="Show notifications (true/false):")
        self.notify_label.grid(row=10, column=0, sticky="w")

        self.notify_entry = ttk.Entry(self.config_frame, width=10)
        self.notify_entry.grid(row=11, column=0, sticky="w", pady=(0, 10))

        self.dev_button = ttk.Button(self.config_frame, text="Dev Panel", command=self.open_dev_panel)
        self.logout_button = ttk.Button(self.config_frame, text="Log out", command=self.log_out)

        self.save_button = ttk.Button(self.config_frame, text="Save", command=self.save_config_gui)
        self.save_button.grid(row=13, column=0, sticky="e")

        self.refresh_entries()
        self.bind_config_key()
        self.show_innocent_view()

    def refresh_entries(self):
        self.apps_entry.delete(0, tk.END)
        self.apps_entry.insert(0, ", ".join(apps_to_close))

        self.switch_entry.delete(0, tk.END)
        self.switch_entry.insert(0, switch_to_app)

        self.hotkey_close_entry.delete(0, tk.END)
        self.hotkey_close_entry.insert(0, hotkey_close_switch)

        self.hotkey_switch_entry.delete(0, tk.END)
        self.hotkey_switch_entry.insert(0, hotkey_switch_only)

        self.hotkey_config_entry.delete(0, tk.END)
        self.hotkey_config_entry.insert(0, hotkey_config_key)

        self.notify_entry.delete(0, tk.END)
        self.notify_entry.insert(0, "true" if show_notifications else "false")

        for w in self.config_frame.grid_slaves(row=12):
            w.grid_forget()

        if current_role == ROLE_ADMIN:
            self.dev_button.grid(row=12, column=0, sticky="w", pady=(0, 5))
        self.logout_button.grid(row=12, column=0, sticky="e", pady=(0, 5))

    def show_innocent_view(self):
        self.config_frame.grid_forget()
        self.config_visible = False
        self.innocent_frame.grid(row=0, column=0, sticky="nsew")
        self.hide_panel()

    def show_config_view(self):
        self.innocent_frame.grid_forget()
        self.config_frame.grid(row=0, column=0, sticky="nsew")
        self.config_visible = True

    def show_panel(self):
        if not self.panel_visible:
            self.panel_frame.grid(row=2, column=0, pady=(0, 5))
            self.panel_visible = True

    def hide_panel(self):
        if self.panel_visible:
            self.panel_frame.grid_forget()
            self.panel_visible = False

    def on_config_key_press(self, event):
        w = self.root.focus_get()
        if isinstance(w, tk.Entry):
            return
        self.show_panel()

    def on_config_key_release(self, event):
        w = self.root.focus_get()
        if isinstance(w, tk.Entry):
            return
        self.hide_panel()

    def bind_config_key(self):
        self.root.bind(f"<KeyPress-{hotkey_config_key}>", self.on_config_key_press)
        self.root.bind(f"<KeyRelease-{hotkey_config_key}>", self.on_config_key_release)

    def hide_window(self):
        self.root.iconify()

    def open_dev_panel(self):
        if current_role != ROLE_ADMIN:
            messagebox.showerror("Bob", "Dev panel is admin only.")
            return
        DevPanel(self, self.device_id)

    def log_out(self):
        clear_license_file()
        messagebox.showinfo("Bob", "Logged out. Restart Bob to enter a new key.")

    def save_config_gui(self):
        global apps_to_close, switch_to_app, hotkey_close_switch, hotkey_switch_only
        global hotkey_config_key, show_notifications

        apps_text = self.apps_entry.get()
        switch_text = self.switch_entry.get()
        hk_close = self.hotkey_close_entry.get()
        hk_switch = self.hotkey_switch_entry.get()
        hk_config = self.hotkey_config_entry.get()
        notify_text = self.notify_entry.get().strip().lower()

        apps_to_close = [a.strip() for a in apps_text.split(",") if a.strip()]
        switch_to_app = switch_text.strip() or "Comet"

        hotkey_close_switch = (hk_close or "[")[0]
        hotkey_switch_only = (hk_switch or "]")[0]
        hotkey_config_key = (hk_config or "'")[0]

        show_notifications = (notify_text == "true")

        save_config()
        self.bind_config_key()
        self.show_innocent_view()


# -----------------------------
# License wrapper for GUI
# -----------------------------


class LicenseAndMainApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Bob License")
        self.root.resizable(False, False)

        self.licensed = False
        self.device_id = get_device_id()

        self.try_auto_license()
        if not self.licensed:
            self.build_license_ui()

    def try_auto_license(self):
        global current_role
        saved_key, saved_role = load_license()
        if not saved_key or saved_role not in (ROLE_BASIC, ROLE_ADMIN):
            return
        role_code = validate_key_for_device(self.device_id, saved_key)
        if role_code is None or role_code != saved_role:
            return
        current_role = role_code
        self.licensed = True
        self.build_main_ui()

    def build_license_ui(self):
        for w in self.root.winfo_children():
            w.destroy()

        frame = ttk.Frame(self.root, padding=10)
        frame.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frame, text="Your device ID:").grid(row=0, column=0, sticky="w")
        dev_label = ttk.Label(frame, text=self.device_id, wraplength=320, foreground="blue")
        dev_label.grid(row=1, column=0, sticky="w", pady=(0, 5))

        def copy_device_id():
            self.root.clipboard_clear()
            self.root.clipboard_append(self.device_id)
            self.root.update()
            messagebox.showinfo("Copied", "Device ID copied to clipboard.")

        ttk.Button(frame, text="Copy device ID", command=copy_device_id).grid(row=2, column=0, sticky="w", pady=(0, 10))

        ttk.Label(frame, text="Enter access key:").grid(row=3, column=0, sticky="w")
        self.key_entry = ttk.Entry(frame, width=30, show="*")
        self.key_entry.grid(row=4, column=0, sticky="w", pady=(0, 10))

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=5, column=0, sticky="e")

        def on_submit():
            global current_role
            key = self.key_entry.get().strip().upper()
            if not key:
                messagebox.showerror("License", "Please enter a key.")
                return

            role_code = validate_key_for_device(self.device_id, key)
            if role_code is None:
                messagebox.showerror("License", "Invalid key for this device.")
                return

            current_role = role_code
            save_license(key, role_code)
            self.licensed = True
            messagebox.showinfo("License", f"Access granted ({role_name(current_role)}).")
            self.build_main_ui()

        def on_quit():
            self.licensed = False
            self.root.quit()

        ttk.Button(btn_frame, text="OK", command=on_submit).grid(row=0, column=0, padx=(0, 5))
        ttk.Button(btn_frame, text="Quit", command=on_quit).grid(row=0, column=1)

    def build_main_ui(self):
        for w in self.root.winfo_children():
            w.destroy()
        self.root.title("Bob")
        EmergencyAppGUI(self.root, self.device_id)

    def run(self):
        self.root.mainloop()
        return self.licensed


# -----------------------------
# Keyboard listener (pynput)
# -----------------------------


running = True


def on_press(key):
    if not running:
        return False

    try:
        if isinstance(key, KeyCode) and key.char is not None:
            ch = key.char
        else:
            return
    except AttributeError:
        return

    if ch == hotkey_close_switch:
        close_apps_and_switch()
    elif ch == hotkey_switch_only:
        switch_to_comet_only()


def keyboard_thread():
    with Listener(on_press=on_press) as listener:
        listener.join()


# -----------------------------
# Main
# -----------------------------


def main():
    load_config()

    app = LicenseAndMainApp()
    licensed = app.run()
    if not licensed:
        return

    notify("Bob Initiated")
    hide_terminal_once()

    t_keys = threading.Thread(target=keyboard_thread, daemon=True)
    t_keys.start()

    global running
    running = False


if __name__ == "__main__":
    main()
