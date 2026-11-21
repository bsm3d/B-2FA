"""B-2FA window (tkinter). Black and white, one red."""

import copy
import ctypes
import hashlib
import os
import subprocess
import sys
import time
import tkinter as tk
from ctypes import wintypes
from tkinter import filedialog, font as tkfont, messagebox

from . import APP_NAME, AUTHOR, REPOSITORY, WEBSITE, __version__, captureguard, paths, pinlock, twofas, winclip
from .captureguard import CaptureGuard
from .icons import TILE, IconStore, initials
from .totp import OtpError, current_code, group_digits, otp_params, parse_otpauth
from .vault import (MIN_EXPORT_CHARS, MIN_MASTER_CHARS, Vault, VaultError,
                    WrongMasterPassword, make_service)

BG, PANEL, FG, DIM, RED = "#ffffff", "#ffffff", "#111111", "#7a7a7a", "#e10600"
LINE = "#d6d6d6"        # fields
HAIRLINE = "#ebebeb"    # separators between accounts
HOVER = "#f7f7f7"       # row under the pointer
BTN, BTN_HOVER, FIELD, ON_RED, RED_HOVER = "#f0f0f0", "#e4e4e4", "#ffffff", "#ffffff", "#ff3a33"
TILE_BG = "#efefef"
MONO = ("Consolas", 17)
UI = ("Segoe UI", 9)
UI_BOLD = ("Segoe UI Semibold", 10)
SMALL = ("Segoe UI", 8)
AUTOLOCK_SECONDS = 5 * 60
CLIPBOARD_CLEAR_SECONDS = 30
EXPECTED_ERRORS = (VaultError, OtpError, twofas.BackupError, pinlock.PinError, OSError)
_MUTEX = None  # keeps the single-instance mutex alive


def button(parent, text, command, red=False, **kw):
    return tk.Button(parent, text=text, command=command, font=UI, relief="flat", bd=0,
                     padx=11, pady=3, cursor="hand2",
                     bg=RED if red else BTN, fg=ON_RED if red else FG,
                     activebackground=RED_HOVER if red else BTN_HOVER,
                     activeforeground=ON_RED if red else FG, **kw)


def entry(parent, show=None, width=30):
    return tk.Entry(parent, show=show, width=width, font=("Segoe UI", 10), bg=FIELD, fg=FG,
                    insertbackground=FG, relief="flat", highlightthickness=1,
                    highlightbackground=LINE, highlightcolor=RED)


class Dialog(tk.Toplevel):
    """Modal dark dialog base."""

    def __init__(self, parent, title):
        super().__init__(parent)
        self.configure(bg=BG, padx=22, pady=18)
        self.title(title)
        self.resizable(False, False)
        self.transient(parent)
        self.result = None
        self.bind("<Escape>", lambda e: self.destroy())

    def run(self):
        self.update_idletasks()
        guard = getattr(self.master, "guard", None)
        if guard is not None:
            guard.protect(self)  # dialogs can show a secret: keep them out of captures too
        px, py = self.master.winfo_rootx(), self.master.winfo_rooty()
        pw = self.master.winfo_width()
        self.geometry("+%d+%d" % (px + max(0, (pw - self.winfo_width()) // 2), py + 60))
        self.grab_set()
        self.wait_window()
        return self.result


class PasswordDialog(Dialog):
    def __init__(self, parent, title, prompt, confirm=False, min_len=0, digits_only=False):
        super().__init__(parent, title)
        self.confirm, self.min_len, self.digits_only = confirm, min_len, digits_only
        tk.Label(self, text=prompt, bg=BG, fg=FG, font=UI, justify="left", wraplength=380).pack(anchor="w")
        self.e1 = entry(self, show="*")
        self.e1.pack(fill="x", pady=(10, 4))
        self.e2 = None
        if confirm:
            tk.Label(self, text="Repeat it", bg=BG, fg=DIM, font=UI).pack(anchor="w")
            self.e2 = entry(self, show="*")
            self.e2.pack(fill="x", pady=(2, 4))
        self.msg = tk.Label(self, text="", bg=BG, fg=RED, font=UI)
        self.msg.pack(anchor="w")
        row = tk.Frame(self, bg=BG)
        row.pack(fill="x", pady=(8, 0))
        button(row, "OK", self.ok, red=True).pack(side="right")
        button(row, "Cancel", self.destroy).pack(side="right", padx=(0, 8))
        self.bind("<Return>", lambda e: self.ok())
        self.e1.focus_set()

    def ok(self):
        pw = self.e1.get()
        if not pw:
            return
        if self.digits_only and not (pw.isascii() and pw.isdigit()):
            self.msg.config(text="Digits only")
            return
        if len(pw) < self.min_len:
            self.msg.config(text="At least %d %s" % (self.min_len, "digits" if self.digits_only else "characters"))
            return
        if self.confirm and pw != self.e2.get():
            self.msg.config(text="The two passwords differ")
            return
        self.result = pw
        self.destroy()


def ask_password(parent, title, prompt, confirm=False, min_len=0, digits_only=False):
    return PasswordDialog(parent, title, prompt, confirm, min_len, digits_only).run()


class AboutDialog(Dialog):
    """Version, licence, what the app is not, and the AI transparency note."""

    def __init__(self, parent):
        super().__init__(parent, "About %s" % APP_NAME)
        tk.Label(self, text=APP_NAME, bg=BG, fg=FG, font=("Segoe UI Semibold", 16)).pack(anchor="w")
        tk.Label(self, text="Version %s" % __version__, bg=BG, fg=DIM, font=UI).pack(anchor="w")
        tk.Frame(self, height=1, bg=HAIRLINE).pack(fill="x", pady=10)

        def para(text, fg=FG, bold=False):
            tk.Label(self, text=text, bg=BG, fg=fg, font=UI_BOLD if bold else UI, justify="left",
                     anchor="w", wraplength=400).pack(anchor="w", pady=(0, 8))

        para("Your 2FAS codes on your PC, without your phone.")
        para("By %s (%s)\n%s" % (AUTHOR, WEBSITE, REPOSITORY), fg=DIM)
        para("Free software under the GNU General Public License v3 or later. It comes with "
             "no warranty.", fg=DIM)
        para("B-2FA is an independent project, not made, endorsed or supported by 2FAS.", fg=DIM)
        para("Security", bold=True)
        para("Not audited by a human security professional. Keep your phone as the reference "
             "copy and use a strong master password.", fg=DIM)
        para("Transparency note", bold=True)
        para("Designed and directed by %s, written with the help of an AI coding assistant "
             "(Claude Code, Anthropic). It is covered by automated tests and an automated "
             "review, and may still contain errors." % AUTHOR, fg=DIM)
        para("Your data: %s" % paths.data_dir(), fg=DIM)
        btns = tk.Frame(self, bg=BG)
        btns.pack(fill="x", pady=(4, 0))
        button(btns, "Close", self.destroy, red=True).pack(side="right")
        self.bind("<Return>", lambda e: self.destroy())


class AccountDialog(Dialog):
    """Add an account, or edit a COPY of one (the caller stores the result)."""

    def __init__(self, parent, service=None):
        super().__init__(parent, "Edit account" if service else "Add account")
        self.service = service
        self.issuer, self.counter = "", 0
        try:
            p = otp_params(service) if service else None
        except OtpError:
            p = None
        p = p or {"type": "TOTP", "digits": 6, "period": 30, "algorithm": "SHA1", "counter": 0}
        otp = (service or {}).get("otp") if isinstance((service or {}).get("otp"), dict) else {}
        self.vars = {}

        if not service:
            tk.Label(self, text="Paste an otpauth:// link (optional)", bg=BG, fg=DIM, font=UI).pack(anchor="w")
            self.uri = entry(self, width=46)
            self.uri.pack(fill="x", pady=(2, 8))
            self.uri.bind("<KeyRelease>", self.fill_from_uri)

        def field(label, key, value, show=None):
            tk.Label(self, text=label, bg=BG, fg=DIM, font=UI).pack(anchor="w")
            e = entry(self, width=46, show=show)
            e.insert(0, value)
            e.pack(fill="x", pady=(2, 8 if key != "secret" else 2))
            self.vars[key] = e

        field("Service name", "name", (service or {}).get("name", ""))
        field("Account (login, email)", "account", otp.get("account") or "")
        field("Secret key (base32)", "secret", (service or {}).get("secret", ""), show="*")
        self.show_secret = tk.BooleanVar(value=False)
        tk.Checkbutton(self, text="Show the secret", variable=self.show_secret, command=self.toggle_secret,
                       bg=BG, fg=DIM, selectcolor=FIELD, activebackground=BG, activeforeground=FG,
                       font=UI).pack(anchor="w", pady=(0, 8))

        # the technical settings are hidden: nearly every service uses the defaults
        # (TOTP, SHA1, 6 digits, 30 s), shown only on request or when the account differs
        row = tk.Frame(self, bg=BG)
        self.adv_row = row
        self.type = tk.StringVar(value=p["type"])
        self.algo = tk.StringVar(value=p["algorithm"])
        self.digits = tk.StringVar(value=str(p["digits"]))
        self.period = tk.StringVar(value=str(p["period"]))
        for label, var, values in (("Type", self.type, ("TOTP", "HOTP", "STEAM")),
                                   ("Algorithm", self.algo, ("SHA1", "SHA256", "SHA512")),
                                   ("Digits", self.digits, ("6", "7", "8")),
                                   ("Period", self.period, ("30", "60", "15"))):
            col = tk.Frame(row, bg=BG)
            col.pack(side="left", padx=(0, 10))
            tk.Label(col, text=label, bg=BG, fg=DIM, font=UI).pack(anchor="w")
            m = tk.OptionMenu(col, var, *values)
            m.config(bg=BTN, fg=FG, activebackground=BTN_HOVER, activeforeground=FG,
                     highlightthickness=0, relief="flat", font=UI, width=7)
            m["menu"].config(bg=FIELD, fg=FG, activebackground=RED, activeforeground=ON_RED, font=UI)
            m.pack()

        self.adv_btn = tk.Button(self, text="Advanced options", command=self.toggle_advanced, font=UI,
                                 bg=BG, fg=DIM, activebackground=BG, activeforeground=FG,
                                 relief="flat", bd=0, cursor="hand2")
        self.adv_btn.pack(anchor="w", pady=(0, 6))
        self.msg = tk.Label(self, text="", bg=BG, fg=RED, font=UI, wraplength=420, justify="left")
        self.msg.pack(anchor="w")
        self.adv_shown = False
        if (p["type"], p["algorithm"], p["digits"], p["period"]) != ("TOTP", "SHA1", 6, 30):
            self.toggle_advanced()
        btns = tk.Frame(self, bg=BG)
        btns.pack(fill="x", pady=(8, 0))
        button(btns, "Save", self.save, red=True).pack(side="right")
        button(btns, "Cancel", self.destroy).pack(side="right", padx=(0, 8))
        self.bind("<Return>", lambda e: self.save())
        (self.uri if not service else self.vars["name"]).focus_set()

    def toggle_advanced(self):
        self.adv_shown = not self.adv_shown
        if self.adv_shown:
            self.adv_row.pack(fill="x", pady=(0, 6), before=self.adv_btn)
            self.adv_btn.config(text="Hide advanced options")
        else:
            self.adv_row.pack_forget()
            self.adv_btn.config(text="Advanced options")

    def toggle_secret(self):
        self.vars["secret"].config(show="" if self.show_secret.get() else "*")

    def fill_from_uri(self, _event=None):
        text = self.uri.get().strip()
        if not text.startswith("otpauth://"):
            return
        try:
            d = parse_otpauth(text)
        except ValueError as exc:  # OtpError is a ValueError
            self.msg.config(text=str(exc))
            return
        self.msg.config(text="")
        for key in ("name", "account", "secret"):
            self.vars[key].delete(0, "end")
            self.vars[key].insert(0, d[key])
        self.type.set(d["type"])
        self.algo.set(d["algorithm"])
        self.digits.set(str(d["digits"]))
        self.period.set(str(d["period"]))
        self.issuer, self.counter = d["issuer"], d["counter"]

    def save(self):
        name = self.vars["name"].get().strip()
        account = self.vars["account"].get().strip()
        secret = self.vars["secret"].get()
        try:
            new = make_service(name, secret, self.issuer or name, account, self.type.get(),
                               self.digits.get(), self.period.get(), self.algo.get(), self.counter)
            current_code(new)
        except (OtpError, ValueError) as exc:
            self.msg.config(text=str(exc))
            return
        if self.service is None:
            self.result = new
        else:  # edit: keep icon, group, order, issuer, counter and every field we do not touch
            s = self.service
            s["name"], s["secret"] = new["name"], new["secret"]
            if not isinstance(s.get("otp"), dict):
                s["otp"] = {}
            s["otp"].update({k: new["otp"][k] for k in
                             ("label", "account", "digits", "period", "algorithm", "tokenType")})
            if new["otp"]["tokenType"] == "HOTP" and s["otp"].get("counter") is None:
                s["otp"]["counter"] = 0
            self.result = s
        self.destroy()


class Row:
    """One account line: name, account, code, countdown bar."""

    def __init__(self, app, parent, service):
        self.app, self.service = app, service
        self._code_text, self._secs_state = None, None
        try:
            kind = otp_params(service)["type"]
        except OtpError:
            kind = None
        self.frame = tk.Frame(parent, bg=PANEL, cursor="hand2", padx=6, pady=7)
        self.frame.pack(fill="x")
        self.sep = tk.Frame(parent, height=1, bg=HAIRLINE)
        self.sep.pack(fill="x")
        self.icon = tk.Canvas(self.frame, width=TILE, height=TILE, bg=PANEL, highlightthickness=0)
        self.icon.pack(side="left", padx=(0, 12))
        self.draw_icon()
        left = tk.Frame(self.frame, bg=PANEL)
        left.pack(side="left", fill="x", expand=True)
        name = str(service.get("name", ""))[:80]
        self.name = tk.Label(left, text=name, bg=PANEL, fg=FG, font=UI_BOLD, anchor="w")
        self.name.pack(fill="x")
        otp = service.get("otp") if isinstance(service.get("otp"), dict) else {}
        self.account = tk.Label(left, text=str(otp.get("account") or "")[:80], bg=PANEL, fg=DIM,
                                font=UI, anchor="w")
        self.account.pack(fill="x")
        # code and seconds are text items of one canvas: a canvas is double-buffered, so changing
        # the text does not flash (a Label erases its background, then draws, and blinks)
        self._fc, self._fs = tkfont.Font(font=MONO), tkfont.Font(font=SMALL)
        self._lc, self._ls = self._fc.metrics("linespace"), self._fs.metrics("linespace")
        self._width = self._fc.measure("0000 0000") + 4
        right = tk.Canvas(self.frame, width=self._width, height=self._lc + self._ls, bg=PANEL,
                          highlightthickness=0)
        right.pack(side="right")
        self.code = right.create_text(self._width - 2, self._lc // 2, text="", fill=FG, font=MONO, anchor="e")
        self.secs = right.create_text(self._width - 2, self._lc + self._ls // 2, text="", fill=DIM,
                                      font=SMALL, anchor="e")
        self.right = right
        if kind == "HOTP":
            tk.Button(self.frame, text="Next", command=self.next_hotp, font=UI, bg=BTN, fg=FG,
                      activebackground=BTN_HOVER, activeforeground=FG, relief="flat", bd=0,
                      padx=8).pack(side="right", padx=8)
        self.surfaces = (self.frame, self.icon, left, self.name, self.account, right)
        for w in self.surfaces:
            w.bind("<Button-1>", self.copy)
            w.bind("<Button-3>", self.menu)
            w.bind("<Enter>", lambda e: self.paint(HOVER))
            w.bind("<Leave>", lambda e: self.paint(PANEL))

    def paint(self, color):
        """Soft hover: tint the whole line."""
        try:
            for w in self.surfaces:
                w.config(bg=color)
        except tk.TclError:
            pass  # the row was rebuilt under the pointer

    def draw_icon(self):
        """The service logo from the local 2FAS pack, or a letter tile."""
        self.icon.delete("all")
        img = self.app.icons.image(self.service)
        if img is not None:
            self.icon.image = img  # keep a reference
            self.icon.create_image(TILE // 2, TILE // 2, image=img)
            return
        self.icon.create_rectangle(0, 0, TILE, TILE, fill=TILE_BG, width=0)
        self.icon.create_text(TILE // 2, TILE // 2, text=initials(str(self.service.get("name", ""))),
                              fill=DIM, font=("Segoe UI Semibold", 10))

    def destroy(self):
        self.frame.destroy()
        self.sep.destroy()

    def refresh(self, now):
        try:
            code, left, period = current_code(self.service, now)
        except Exception:
            if self._code_text != "invalid":
                self._code_text, self._secs_state = "invalid", ("", DIM)
                self.right.itemconfigure(self.code, text="invalid", fill=RED)
                self.right.itemconfigure(self.secs, text="")
            return
        # touch an item only when its value really differs: no needless repaint
        text = group_digits(code)
        if text != self._code_text:
            self._code_text = text
            need = self._fc.measure(text) + 4
            if need > self._width:  # long codes (up to 10 digits) widen the box once
                self._width = need
                self.right.config(width=need)
                self.right.coords(self.code, need - 2, self._lc // 2)
                self.right.coords(self.secs, need - 2, self._lc + self._ls // 2)
            self.right.itemconfigure(self.code, text=text, fill=FG)
        # seconds left, small: grey, red only in the last 5 s (the code itself never changes colour)
        secs = ("%d s" % left if period else "", RED if left <= 5 else DIM)
        if secs != self._secs_state:
            self._secs_state = secs
            self.right.itemconfigure(self.secs, text=secs[0], fill=secs[1])

    def copy(self, _event=None):
        try:
            code, _, _ = current_code(self.service)
        except OtpError:
            return
        self.app.copy_to_clipboard(code, str(self.service.get("name", ""))[:40])

    def next_hotp(self):
        try:
            self.app.vault.bump_counter(self.service)
        except EXPECTED_ERRORS as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self.app)
        self.refresh(time.time())

    def menu(self, event):
        m = tk.Menu(self.app, tearoff=0, bg=FIELD, fg=FG, activebackground=RED, activeforeground=ON_RED)
        m.add_command(label="Copy code", command=self.copy)
        m.add_command(label="Edit...", command=lambda: self.app.edit_account(self.service))
        m.add_separator()
        m.add_command(label="Delete...", command=lambda: self.app.delete_account(self.service))
        m.tk_popup(event.x_root, event.y_root)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("%s %s" % (APP_NAME, __version__))
        self.configure(bg=BG)
        self.geometry("520x680")
        self.minsize(420, 400)
        self.vault = Vault()
        self.pins = pinlock.PinStore()
        self.icons = IconStore()
        self.pin_mode = True  # show the PIN screen first when a PIN is set
        self._pin_screen = False
        self.rows: list[Row] = []
        self.view = None
        self.last_activity = time.monotonic()
        self._clip_token = 0
        self._clip_text = None
        self._reporting = False
        for ev in ("<Motion>", "<Key>", "<Button>"):
            self.bind_all(ev, self.touch, add="+")
        self.bind("<Unmap>", self.on_unmap)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(250, self.tick)
        self.show_unlock()
        self.guard = CaptureGuard(self)
        self.capture_block = tk.BooleanVar(value=True)
        self.after(150, self.guard.enable)  # needs the window to exist on screen

    # ---- helpers -----------------------------------------------------------
    def touch(self, _event=None):
        self.last_activity = time.monotonic()

    def report_callback_exception(self, exc, val, tb):
        """Show unexpected errors instead of failing silently (no stderr under pythonw).

        Only the message of our own error types is shown, never a traceback or any data.
        """
        if self._reporting:
            return
        self._reporting = True
        try:
            text = str(val) if isinstance(val, EXPECTED_ERRORS) else type(val).__name__
            messagebox.showerror(APP_NAME, "Something went wrong:\n%s" % text, parent=self)
            if self.vault.unlocked:
                self.rebuild()
        except Exception:
            pass
        finally:
            self._reporting = False

    def clear_view(self):
        if self.view is not None:
            self.view.destroy()
        self.rows = []
        self.view = tk.Frame(self, bg=BG)
        self.view.pack(fill="both", expand=True)
        return self.view

    def status(self, text, red=False):
        label = getattr(self, "status_label", None)
        if label is not None and label.winfo_exists():
            label.config(text=text, fg=RED if red else DIM)

    def copy_to_clipboard(self, text, label=""):
        if not winclip.set_text(text):  # also keeps it out of Win+V history and cloud sync
            self.clipboard_clear()
            self.clipboard_append(text)
        self._clip_text = text
        self._clip_token += 1
        token = self._clip_token
        self.status("Copied %s. Clipboard clears in %d s." % (label, CLIPBOARD_CLEAR_SECONDS))
        self.after(CLIPBOARD_CLEAR_SECONDS * 1000, lambda: self._clip_timeout(token))

    def _clip_timeout(self, token):
        if token == self._clip_token:
            self._wipe_clipboard()
            self.status("")

    def _wipe_clipboard(self):
        """Empty the clipboard, but only if it still holds the code we put there."""
        text, self._clip_text = self._clip_text, None
        if text is None:
            return
        try:
            current = self.clipboard_get()
        except tk.TclError:
            return
        if current == text and not winclip.clear():
            self.clipboard_clear()

    def on_unmap(self, event):
        if event.widget is self and self.vault.unlocked and self.state() == "iconic":
            self.lock()

    def on_close(self):
        try:
            self._wipe_clipboard()
            if self.vault.unlocked:
                self.vault.lock()
        finally:
            self.destroy()

    # ---- unlock / create ---------------------------------------------------
    def show_unlock(self):
        v = self.clear_view()
        creating = not self.vault.exists
        use_pin = (not creating) and self.pin_mode and self.pins.enabled
        self._pin_screen = use_pin
        box = tk.Frame(v, bg=BG)
        box.place(relx=0.5, rely=0.4, anchor="center")
        tk.Label(box, text=APP_NAME, bg=BG, fg=FG, font=("Segoe UI Light", 26)).pack()
        tk.Label(box, text="Your 2FAS codes, on this PC", bg=BG, fg=DIM, font=UI).pack(pady=(0, 20))
        if use_pin:
            tk.Label(box, text="PIN", bg=BG, fg=DIM, font=UI).pack()
        if creating:
            tk.Label(box, text="Choose a master password (%d characters minimum,\n"
                               "a passphrase works well). It cannot be recovered.\n"
                               "Keep your phone backup too." % MIN_MASTER_CHARS,
                     bg=BG, fg=DIM, font=UI, justify="center").pack(pady=(0, 10))
        self.pw1 = entry(box, show="*", width=12 if use_pin else 28)
        self.pw1.pack(pady=4)
        self.pw2 = None
        if creating:
            self.pw2 = entry(box, show="*", width=28)
            self.pw2.pack(pady=4)
            tk.Label(box, text="Repeat the password", bg=BG, fg=DIM, font=UI).pack()
        self.unlock_msg = tk.Label(box, text="", bg=BG, fg=RED, font=UI, wraplength=360)
        self.unlock_msg.pack(pady=4)
        button(box, "Create vault" if creating else "Unlock", self.do_unlock, red=True).pack(pady=6)
        if use_pin:
            tk.Button(box, text="Use the master password", command=self.use_master_password, font=UI,
                      bg=BG, fg=DIM, relief="flat", bd=0, activebackground=BG, activeforeground=FG,
                      cursor="hand2").pack(pady=(10, 0))
        self.pw1.focus_set()
        self.bind("<Return>", lambda e: self.do_unlock())

    def use_master_password(self):
        self.pin_mode = False
        self.show_unlock()

    def unlock_with_pin(self, pin):
        try:
            self.unlock_msg.config(text="Checking...")
            self.update_idletasks()
            self.vault.unlock(self.pins.unlock(pin))
        except pinlock.WrongPin as exc:
            self.unlock_msg.config(text=str(exc))
            self.pw1.delete(0, "end")
            return
        except pinlock.PinDisabled as exc:
            self.pin_mode = False
            self.show_unlock()
            self.unlock_msg.config(text=str(exc))
            return
        except WrongMasterPassword:  # the master password changed behind the PIN's back
            self.pins.disable()
            self.pin_mode = False
            self.show_unlock()
            self.unlock_msg.config(text="The PIN was out of date and was removed. Use the master password.")
            return
        except (VaultError, OSError) as exc:
            self.unlock_msg.config(text=str(exc))
            return
        self.unbind("<Return>")
        self.show_main()

    def do_unlock(self):
        pw = self.pw1.get()
        if self._pin_screen:
            return self.unlock_with_pin(pw)
        created = False
        try:
            if not self.vault.exists:
                if pw != self.pw2.get():
                    self.unlock_msg.config(text="The two passwords differ")
                    return
                self.unlock_msg.config(text="Creating...")
                self.update_idletasks()
                self.vault.create(pw)
                created = True
            else:
                self.unlock_msg.config(text="Checking...")
                self.update_idletasks()
                self.vault.unlock(pw)
        except WrongMasterPassword:
            self.unlock_msg.config(text="Wrong master password")
            self.pw1.delete(0, "end")
            return
        except (VaultError, OSError) as exc:
            self.unlock_msg.config(text=str(exc))
            return
        self.unbind("<Return>")
        self.pin_mode = True
        self.show_main()
        if created and self.pins.available():
            self.after(200, self.offer_pin)

    def offer_pin(self):
        if messagebox.askyesno(APP_NAME, "Set a PIN for quick unlock on this PC?\n\n"
                                         "(You can do it later from More.)", parent=self):
            self.setup_pin()

    def setup_pin(self):
        if not self.pins.available():
            messagebox.showinfo(APP_NAME, "A PIN needs Windows.", parent=self)
            return
        pin = ask_password(
            self, "PIN", "Choose a PIN (%d to %d digits) to unlock on this PC.\n\n"
                         "A short PIN is weak by nature. It only works with this Windows account, and "
                         "is erased after %d wrong tries. Your master password stays the real key."
                         % (pinlock.PIN_MIN, pinlock.PIN_MAX, pinlock.MAX_ATTEMPTS),
            confirm=True, min_len=pinlock.PIN_MIN, digits_only=True)
        if not pin:
            return
        try:
            self.pins.enable(pin, self.vault.master_password())
        except EXPECTED_ERRORS as exc:
            return self.fail(exc)
        self.status("PIN set. It unlocks B-2FA on this PC only.")

    def remove_pin(self):
        self.pins.disable()
        self.status("PIN removed. The master password is needed to unlock.")

    def lock(self):
        for w in self.winfo_children():  # close any open dialog (it may show a secret)
            if isinstance(w, tk.Toplevel):
                w.destroy()
        self.vault.lock()
        self._wipe_clipboard()
        self.show_unlock()

    # ---- main view ---------------------------------------------------------
    def show_main(self):
        v = self.clear_view()
        bar = tk.Frame(v, bg=BG, padx=14, pady=12)
        bar.pack(fill="x")
        self.search = entry(bar, width=8)  # grows with the window; a small request width keeps the buttons visible
        self.search.pack(side="left", fill="x", expand=True, ipady=3)
        self.search.bind("<KeyRelease>", lambda e: self.rebuild())
        button(bar, "+ Add", self.add_account, red=True).pack(side="left", padx=(6, 0))
        button(bar, "Import", self.import_backup).pack(side="left", padx=(6, 0))
        button(bar, "Export", self.export_backup).pack(side="left", padx=(6, 0))
        mb = tk.Menubutton(bar, text="More", font=UI, bg=BTN, fg=FG, relief="flat",
                           activebackground=BTN_HOVER, activeforeground=FG, padx=12, pady=5)
        menu = tk.Menu(mb, tearoff=0, bg=FIELD, fg=FG, activebackground=RED, activeforeground=ON_RED)
        menu.add_command(label="Open backups folder", command=self.open_backups)
        menu.add_command(label="Backup now", command=self.backup_now)
        menu.add_command(label="Change master password...", command=self.change_password)
        if self.pins.available():
            menu.add_command(label="Set or change PIN...", command=self.setup_pin)
            menu.add_command(label="Remove PIN", command=self.remove_pin)
        if captureguard.supported():
            menu.add_checkbutton(label="Block screen capture", variable=self.capture_block,
                                 command=self.toggle_capture_block)
        menu.add_separator()
        menu.add_command(label="About B-2FA", command=lambda: AboutDialog(self).run())
        menu.add_command(label="Lock", command=self.lock)
        mb["menu"] = menu
        mb.pack(side="left", padx=(6, 0))

        holder = tk.Frame(v, bg=BG)
        holder.pack(fill="both", expand=True, padx=14)
        self.canvas = tk.Canvas(holder, bg=BG, highlightthickness=0)
        self.list_frame = tk.Frame(self.canvas, bg=BG)
        self.win = self.canvas.create_window((0, 0), window=self.list_frame, anchor="nw")
        self.canvas.pack(fill="both", expand=True)
        self.list_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self.win, width=e.width))
        self.bind_all("<MouseWheel>", self.on_wheel)

        self.status_label = tk.Label(v, text="", bg=BG, fg=DIM, font=UI, anchor="w", padx=14, pady=6)
        self.status_label.pack(fill="x")
        self.rebuild()
        self.search.focus_set()

    def on_wheel(self, event):
        canvas = getattr(self, "canvas", None)
        if self.vault.unlocked and canvas is not None and canvas.winfo_exists():
            canvas.yview_scroll(int(-event.delta / 120) * 2, "units")

    def rebuild(self):
        if not self.vault.unlocked or not hasattr(self, "list_frame"):
            return
        for r in self.rows:
            r.destroy()
        self.rows = []
        for w in self.list_frame.winfo_children():
            w.destroy()
        query = self.search.get().strip().lower()
        shown = 0
        for s in self.vault.sorted_services():
            otp = s.get("otp") if isinstance(s.get("otp"), dict) else {}
            hay = "%s %s" % (s.get("name", ""), otp.get("account") or "")
            if query and query not in hay.lower():
                continue
            self.rows.append(Row(self, self.list_frame, s))
            shown += 1
        if not shown:
            text = ("No match." if query else
                    "No accounts yet.\n\nImport your 2FAS backup (.2fas)\nfrom the phone, or add an account.")
            tk.Label(self.list_frame, text=text, bg=BG, fg=DIM, font=UI, pady=60).pack(fill="x")
        self.update_idletasks()
        self.tick_rows()

    def tick_rows(self):
        now = time.time()
        for r in self.rows:
            try:
                r.refresh(now)
            except tk.TclError:
                pass  # row destroyed during a rebuild

    def tick(self):
        try:
            if self.vault.unlocked:
                if time.monotonic() - self.last_activity > AUTOLOCK_SECONDS:
                    self.lock()
                else:
                    self.tick_rows()
                    self.vault.flush_backup()
            self.guard.keep_behind()
        finally:
            self.after(250, self.tick)

    # ---- actions -----------------------------------------------------------
    def fail(self, exc):
        messagebox.showerror(APP_NAME, str(exc), parent=self)
        self.rebuild()

    def add_account(self):
        s = AccountDialog(self).run()
        if not s:
            return
        try:
            self.vault.add(s)
        except EXPECTED_ERRORS as exc:
            return self.fail(exc)
        self.rebuild()
        self.status("Added %s" % s["name"])

    def edit_account(self, service):
        edited = AccountDialog(self, copy.deepcopy(service)).run()
        if not edited:
            return
        try:
            self.vault.update(edited)
        except EXPECTED_ERRORS as exc:
            return self.fail(exc)
        self.rebuild()

    def delete_account(self, service):
        if not messagebox.askyesno(
                APP_NAME, "Delete %s?\n\nIt is removed from this vault and from the automatic "
                          "backups (they are rewritten). Make sure it is still in your phone or in "
                          "an exported backup, or you may lose access to that account."
                          % str(service.get("name", ""))[:60], icon="warning", parent=self):
            return
        try:
            self.vault.delete(service)
        except EXPECTED_ERRORS as exc:
            return self.fail(exc)
        self.rebuild()

    def import_backup(self):
        path = filedialog.askopenfilename(
            parent=self, title="Import a 2FAS backup",
            filetypes=[("2FAS backup", "*.2fas *.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            content = twofas.read_backup(path)
            if twofas.is_encrypted(content):
                while True:
                    pw = ask_password(self, "Encrypted backup",
                                      "Password of this backup (the one you set in 2FAS):")
                    if pw is None:
                        return
                    try:
                        content = twofas.decrypt_backup(content, pw)
                        break
                    except twofas.WrongPassword:
                        messagebox.showwarning(APP_NAME, "Wrong password. Try again.", parent=self)
            else:
                content = twofas.decrypt_backup(content, "")
            added, skipped = self.vault.merge(content)
        except EXPECTED_ERRORS as exc:
            return self.fail(exc)
        self.rebuild()
        messagebox.showinfo(APP_NAME, "%d account(s) added, %d already here or skipped." % (added, skipped),
                            parent=self)

    def export_backup(self):
        if not self.vault.services:
            messagebox.showinfo(APP_NAME, "Nothing to export yet.", parent=self)
            return
        pw = ask_password(
            self, "Export a 2FAS backup",
            "Password for the .2fas file (%d characters minimum, different from the master "
            "password).\n\nThe 2FAS format protects a password far less than the vault does, "
            "so choose a long passphrase." % MIN_EXPORT_CHARS, confirm=True, min_len=MIN_EXPORT_CHARS)
        if not pw:
            return
        path = filedialog.asksaveasfilename(
            parent=self, title="Export a 2FAS backup", defaultextension=".2fas",
            initialfile="B-2FA-export-%s.2fas" % time.strftime("%Y%m%d"),
            filetypes=[("2FAS backup", "*.2fas")])
        if not path:
            return
        try:
            self.vault.export_backup(path, pw)
        except EXPECTED_ERRORS as exc:
            return self.fail(exc)
        self.status("Exported %s" % os.path.basename(path))

    def backup_now(self):
        try:
            target = self.vault.auto_backup()
        except EXPECTED_ERRORS as exc:
            return self.fail(exc)
        self.status("Backup written: %s" % target.name if target else "Nothing to back up yet.")

    def toggle_capture_block(self):
        if self.capture_block.get():
            self.guard.enable()
            self.status("Screen capture is blocked.")
        else:
            self.guard.disable()
            self.status("Screen capture is allowed until you restart B-2FA.")

    def open_backups(self):
        folder = paths.backups_dir()
        if not open_folder(folder):
            messagebox.showinfo(APP_NAME, "Could not open the folder. It is here:\n\n%s" % folder, parent=self)

    def change_password(self):
        old = ask_password(self, "Master password", "Current master password:")
        if not old:
            return
        new = ask_password(self, "Master password",
                           "New master password (%d characters minimum).\n\nOlder backups made with "
                           "the old password are deleted and rewritten." % MIN_MASTER_CHARS,
                           confirm=True, min_len=MIN_MASTER_CHARS)
        if not new:
            return
        try:
            self.vault.change_password(old, new)
        except EXPECTED_ERRORS as exc:
            return self.fail(exc)
        self.pins.disable()  # the PIN wraps the OLD password: it must be set again
        self.status("Master password changed. The PIN was removed: set it again from More.")


def open_folder(folder) -> bool:
    """Open a folder in Explorer. Creates it if missing, retries once, then falls back to
    explorer.exe. Returns False if nothing worked (the caller shows the path instead)."""
    if sys.platform != "win32":
        return False
    path = os.path.normpath(os.path.abspath(str(folder)))
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        return False
    for attempt in range(2):
        try:
            os.startfile(path)
            return True
        except OSError:
            time.sleep(0.3)  # a just-created folder can take a moment to be visible to the shell
    try:
        subprocess.Popen(["explorer.exe", path])
        return True
    except OSError:
        return False


def acquire_single_instance() -> bool:
    """One window per vault: two writers would silently overwrite each other."""
    global _MUTEX
    if sys.platform != "win32":
        return True
    try:
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        k.CreateMutexW.restype = ctypes.c_void_p
        key = hashlib.sha1(str(paths.vault_path()).lower().encode("utf-8")).hexdigest()[:16]
        _MUTEX = k.CreateMutexW(None, False, "Local\\B2FA-" + key)
        return ctypes.get_last_error() != 183  # ERROR_ALREADY_EXISTS
    except Exception:
        return True


def main():
    if sys.platform == "win32":
        try:  # crisp text on high-DPI screens
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    if not acquire_single_instance():
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo(APP_NAME, "B-2FA is already running.")
        root.destroy()
        return
    App().mainloop()
