// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "app.h"

#include <commdlg.h>
#include <shellapi.h>
#include <windowsx.h>

#include <algorithm>
#include <cmath>
#include <ctime>
#include <memory>
#include <typeinfo>

#include "captureguard.h"
#include "dialogs.h"
#include "fileio.h"
#include "icons.h"
#include "paths.h"
#include "pinlock.h"
#include "settings.h"
#include "twofas.h"
#include "ui.h"
#include "vault.h"
#include "version.h"
#include "winclip.h"

namespace b2 {

using namespace ui;

namespace {

constexpr uint64_t kAutoLockMs = 5 * 60 * 1000;
constexpr UINT kClipboardClearMs = 30 * 1000;
const wchar_t kMainClass[] = L"B2FAMain";
const wchar_t kListClass[] = L"B2FAList";

enum : int {
    ID_PW1 = 1001, ID_PW2, ID_UNLOCK, ID_USE_MASTER,
    ID_SEARCH = 1201, ID_ADD, ID_IMPORT, ID_EXPORT, ID_MORE,
    ID_PAD = 1400,
    CMD_OPEN_BACKUPS = 2001, CMD_BACKUP_NOW, CMD_CHANGE_PW, CMD_SET_PIN, CMD_REMOVE_PIN, CMD_SECURE_KEYPAD, CMD_BLOCK_CAPTURE,
    CMD_ABOUT, CMD_LOCK,
    CMD_ROW_COPY = 2101, CMD_ROW_EDIT, CMD_ROW_DELETE,
};
enum : UINT_PTR { TIMER_TICK = 1, TIMER_CLIPBOARD = 2 };

std::wstring wide(const std::string& s) { return widen(s); }

std::string todayStamp() {
    char buf[16];
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_s(&tm, &t);
    std::strftime(buf, sizeof(buf), "%Y%m%d", &tm);
    return buf;
}

// ---- the account list rows ---------------------------------------------------------------------------------------
struct Row {
    std::string id;
    std::wstring name, account, code, secs;
    std::string codeText;           // for change detection
    bool hotp = false, invalid = false, secsRed = false;
    HBITMAP icon = nullptr;
};

class App {
public:
    int run(HINSTANCE instance, int show);

private:
    HINSTANCE inst_ = nullptr;
    HWND hwnd_ = nullptr, list_ = nullptr, search_ = nullptr, pw1_ = nullptr, pw2_ = nullptr;
    Vault vault_;
    PinStore pins_;
    Settings settings_;
    IconStore icons_;
    std::unique_ptr<CaptureGuard> guard_;
    Surface surface_;
    std::vector<HWND> viewControls_;
    std::unique_ptr<SecureInput> pad_;

    enum class View { Unlock, Main } view_ = View::Unlock;
    bool pinMode_ = true, pinScreen_ = false, creating_ = false;
    std::wstring unlockMsg_, status_;
    bool statusRed_ = false;
    int unlockMsgIndex_ = -1, statusIndex_ = -1;
    std::string clipText_, menuRow_;

    std::vector<Row> rows_;
    int hover_ = -1, hoverNext_ = -1, scroll_ = 0;
    bool tracking_ = false;

    static LRESULT CALLBACK mainProc(HWND, UINT, WPARAM, LPARAM);
    static LRESULT CALLBACK listProc(HWND, UINT, WPARAM, LPARAM);
    LRESULT onMessage(UINT, WPARAM, LPARAM);
    LRESULT onListMessage(HWND, UINT, WPARAM, LPARAM);

    // views
    void clearView();
    void showUnlock();
    void showMain();
    void layout();
    void layoutUnlock(int w, int h);
    void layoutMain(int w, int h);
    void setUnlockMessage(const std::wstring& text);
    void setStatus(const std::wstring& text, bool red = false);

    // unlocking
    void doUnlock();
    void unlockWithPin(const Secret& pin);
    void offerPin();
    void setupPin();
    void removePin();
    void lock();

    // list
    void rebuildRows();
    void refreshRows();
    int rowHeight() const { return dp(60); }
    int contentHeight() const { return static_cast<int>(rows_.size()) * rowHeight(); }
    void updateScroll();
    void paintList(HWND list);
    int rowAt(int y) const;
    RECT nextButtonRect(int row, int width) const;
    void copyCode(int row);
    void nextHotp(int row);
    void rowMenu(int row, POINT screen);

    // actions
    void addAccount();
    void editAccount(const std::string& id);
    void deleteAccount(const std::string& id);
    void importBackup();
    void exportBackup();
    void backupNow();
    void changePassword();
    void openBackups();
    void moreMenu();
    void toggleSecureKeypad();
    void toggleCaptureBlock();
    void tick();

    // helpers
    void copyToClipboard(const std::string& text, const std::wstring& label);
    void wipeClipboard();
    void fail(const std::exception& e);
    void report(const std::exception& e);
    template <class F>
    void guarded(F&& f) {
        try {
            f();
        } catch (const std::exception& e) {
            report(e);
        }
    }
    bool openFileDialog(std::wstring& path, const wchar_t* title, const wchar_t* filter);
    bool saveFileDialog(std::wstring& path, const wchar_t* title, const wchar_t* filter, const wchar_t* defExt, const std::wstring& initial);
};

// ---- window setup ---------------------------------------------------------------------------------------------------
int App::run(HINSTANCE instance, int show) {
    inst_ = instance;
    setDpi(GetDpiForSystem());
    touchActivity();

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = &App::mainProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = kMainClass;
    wc.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(1));
    wc.hIconSm = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(1), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0));
    RegisterClassExW(&wc);
    WNDCLASSEXW lc{};
    lc.cbSize = sizeof(lc);
    lc.lpfnWndProc = &App::listProc;
    lc.hInstance = instance;
    lc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    lc.lpszClassName = kListClass;
    RegisterClassExW(&lc);

    int w = dp(520), h = dp(680);
    int sx = GetSystemMetrics(SM_CXSCREEN), sy = GetSystemMetrics(SM_CYSCREEN);
    std::wstring title = std::wstring(kAppName) + L" " + kVersion;
    hwnd_ = CreateWindowExW(0, kMainClass, title.c_str(), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, (sx - w) / 2, std::max(0, (sy - h) / 3), w, h, nullptr,
                            nullptr, instance, this);
    if (!hwnd_) return 1;
    guard_ = std::make_unique<CaptureGuard>(hwnd_);
    setModalHook([this](HWND dlg) { if (guard_) guard_->protect(dlg); });
    SetTimer(hwnd_, TIMER_TICK, 250, nullptr);
    showUnlock();
    ShowWindow(hwnd_, show);
    UpdateWindow(hwnd_);
    // `--allow-capture` starts with the screen capture protection off, like More > Block screen capture does
    // for a session (used to take screenshots of the program)
    if (!wcsstr(GetCommandLineW(), L"--allow-capture")) guard_->enable();   // needs the window to exist on screen
    while (pump(hwnd_)) {
    }
    return 0;
}

LRESULT CALLBACK App::mainProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    App* self = nullptr;
    if (m == WM_NCCREATE) {
        self = static_cast<App*>(reinterpret_cast<CREATESTRUCTW*>(l)->lpCreateParams);
        SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        self->hwnd_ = h;
    } else {
        self = reinterpret_cast<App*>(GetWindowLongPtrW(h, GWLP_USERDATA));
    }
    if (self) return self->onMessage(m, w, l);
    return DefWindowProcW(h, m, w, l);
}

LRESULT App::onMessage(UINT m, WPARAM w, LPARAM l) {
    switch (m) {
        case WM_PAINT:
            surface_.paint(hwnd_);
            return 0;
        case WM_ERASEBKGND:
            return 1;
        case WM_SIZE:
            if (w == SIZE_MINIMIZED) {
                if (vault_.unlocked()) lock();   // minimising locks
                return 0;
            }
            layout();
            return 0;
        case WM_GETMINMAXINFO: {
            auto* mm = reinterpret_cast<MINMAXINFO*>(l);
            RECT r{0, 0, dp(420), dp(420)};
            AdjustWindowRectExForDpi(&r, WS_OVERLAPPEDWINDOW, FALSE, 0, dpi());
            mm->ptMinTrackSize.x = r.right - r.left;
            mm->ptMinTrackSize.y = r.bottom - r.top;
            return 0;
        }
        case WM_WINDOWPOSCHANGED:
            if (guard_) guard_->onPosChanged();
            break;   // DefWindowProc turns it into WM_SIZE / WM_MOVE
        case WM_SHOWWINDOW:
            if (guard_) guard_->onPosChanged();
            break;
        case WM_ENTERSIZEMOVE:
            if (guard_) guard_->onEnterSizeMove();
            break;
        case WM_EXITSIZEMOVE:
            if (guard_) guard_->onExitSizeMove();
            break;
        case WM_DPICHANGED: {
            setDpi(HIWORD(w));
            refreshFonts(hwnd_);
            icons_.clearImages();
            const RECT* r = reinterpret_cast<RECT*>(l);
            SetWindowPos(hwnd_, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
            if (view_ == View::Main) rebuildRows();
            layout();
            if (guard_) guard_->onDpiChanged();
            return 0;
        }
        case WM_DRAWITEM:
            drawButton(reinterpret_cast<DRAWITEMSTRUCT*>(l));
            return TRUE;
        case WM_CTLCOLOREDIT: case WM_CTLCOLORSTATIC: case WM_CTLCOLORBTN:
            return ctlColor(m, reinterpret_cast<HDC>(w), reinterpret_cast<HWND>(l));
        case WM_TIMER:
            if (w == TIMER_TICK) {
                tick();
            } else if (w == TIMER_CLIPBOARD) {
                KillTimer(hwnd_, TIMER_CLIPBOARD);
                wipeClipboard();
                setStatus(L"");
            }
            return 0;
        case WM_COMMAND: {
            int id = LOWORD(w), code = HIWORD(w);
            HWND ctl = reinterpret_cast<HWND>(l);
            guarded([&] {
                if (code == EN_SETFOCUS || code == EN_KILLFOCUS) {
                    surface_.invalidateField(hwnd_, ctl);
                    if (code == EN_SETFOCUS && pad_) pad_->onEditFocus(ctl);
                    return;
                }
                if (id == ID_SEARCH && code == EN_CHANGE) { rebuildRows(); return; }
                if (id == IDOK && view_ == View::Unlock) { doUnlock(); return; }
                if (code != BN_CLICKED) return;
                if (pad_ && id >= ID_PAD && id < ID_PAD + SecureInput::kIdCount) { pad_->onCommand(id); return; }
                switch (id) {
                    case ID_UNLOCK: doUnlock(); break;
                    case ID_USE_MASTER: pinMode_ = false; showUnlock(); break;
                    case ID_ADD: addAccount(); break;
                    case ID_IMPORT: importBackup(); break;
                    case ID_EXPORT: exportBackup(); break;
                    case ID_MORE: moreMenu(); break;
                    // menu commands (the menus post WM_COMMAND, so they can also be driven from outside)
                    case CMD_OPEN_BACKUPS: openBackups(); break;
                    case CMD_BACKUP_NOW: backupNow(); break;
                    case CMD_CHANGE_PW: changePassword(); break;
                    case CMD_SET_PIN: setupPin(); break;
                    case CMD_REMOVE_PIN: removePin(); break;
                    case CMD_SECURE_KEYPAD: toggleSecureKeypad(); break;
                    case CMD_BLOCK_CAPTURE: toggleCaptureBlock(); break;
                    case CMD_ABOUT: showAbout(hwnd_); break;
                    case CMD_LOCK: lock(); break;
                    case CMD_ROW_COPY: case CMD_ROW_EDIT: case CMD_ROW_DELETE: {
                        int row = -1;
                        for (size_t i = 0; i < rows_.size(); ++i) if (rows_[i].id == menuRow_) row = static_cast<int>(i);
                        if (row < 0) break;
                        if (id == CMD_ROW_COPY) copyCode(row);
                        else if (id == CMD_ROW_EDIT) editAccount(menuRow_);
                        else deleteAccount(menuRow_);
                        break;
                    }
                }
            });
            return 0;
        }
        case WM_CLOSE:
            wipeClipboard();
            if (vault_.unlocked()) vault_.lock();
            DestroyWindow(hwnd_);
            return 0;
        case WM_DESTROY:
            KillTimer(hwnd_, TIMER_TICK);
            guard_.reset();
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd_, m, w, l);
}

// ---- views ------------------------------------------------------------------------------------------------------------
void App::clearView() {
    pad_.reset();
    for (HWND c : viewControls_) {
        if (GetWindowLongPtrW(c, GWL_STYLE) & ES_PASSWORD) wipeEdit(c);
        DestroyWindow(c);
    }
    viewControls_.clear();
    if (list_) { DestroyWindow(list_); list_ = nullptr; }
    pw1_ = pw2_ = search_ = nullptr;
    surface_.clear();
    rows_.clear();
    hover_ = hoverNext_ = -1;
    scroll_ = 0;
}

void App::showUnlock() {
    clearView();
    view_ = View::Unlock;
    creating_ = !vault_.exists();
    pinScreen_ = !creating_ && pinMode_ && pins_.enabled();
    pw1_ = makeEdit(hwnd_, ID_PW1, true);
    viewControls_.push_back(pw1_);
    std::vector<HWND> edits{pw1_};
    if (creating_) {
        pw2_ = makeEdit(hwnd_, ID_PW2, true);
        viewControls_.push_back(pw2_);
        edits.push_back(pw2_);
    }
    pad_ = std::make_unique<SecureInput>(hwnd_, edits, pinScreen_, pinScreen_ && settings_.secureKeypad(), ID_PAD);
    pad_->onLayoutChanged = [this] { layout(); };
    HWND unlock = makeButton(hwnd_, ID_UNLOCK, creating_ ? L"Create vault" : L"Unlock", BtnStyle::Primary);
    viewControls_.push_back(unlock);
    if (pinScreen_) viewControls_.push_back(makeButton(hwnd_, ID_USE_MASTER, L"Use the master password", BtnStyle::Link));
    // the keypad owns its own buttons; they are destroyed with it
    layout();
    SetFocus(pw1_);
}

void App::showMain() {
    clearView();
    view_ = View::Main;
    search_ = makeEdit(hwnd_, ID_SEARCH, false);
    viewControls_.push_back(search_);
    viewControls_.push_back(makeButton(hwnd_, ID_ADD, L"+ Add", BtnStyle::Primary));
    viewControls_.push_back(makeButton(hwnd_, ID_IMPORT, L"Import", BtnStyle::Normal));
    viewControls_.push_back(makeButton(hwnd_, ID_EXPORT, L"Export", BtnStyle::Normal));
    viewControls_.push_back(makeButton(hwnd_, ID_MORE, L"More", BtnStyle::Normal));
    list_ = CreateWindowExW(0, kListClass, L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_CLIPSIBLINGS, 0, 0, 10, 10, hwnd_, nullptr, inst_, this);
    layout();
    rebuildRows();
    SetFocus(search_);
}

void App::layout() {
    RECT rc;
    GetClientRect(hwnd_, &rc);
    if (rc.right <= 0 || rc.bottom <= 0) return;
    if (view_ == View::Unlock) layoutUnlock(rc.right, rc.bottom);
    else layoutMain(rc.right, rc.bottom);
    InvalidateRect(hwnd_, nullptr, FALSE);
}

void App::layoutUnlock(int W, int H) {
    surface_.clear();
    int colW = dp(300), x = (W - colW) / 2;
    int y = std::max(dp(24), H / 8);
    y = surface_.addLabel(kAppName, Role::Title, kFg, 0, y, W, DT_CENTER | DT_SINGLELINE | DT_NOPREFIX);
    y = surface_.addLabel(L"Your 2FAS codes, on this PC", Role::Body, kDim, 0, y, W, DT_CENTER | DT_SINGLELINE | DT_NOPREFIX) + dp(20);
    if (creating_) {
        wchar_t text[256];
        swprintf_s(text, L"Choose a master password (%d characters minimum,\na passphrase works well). It cannot be recovered.\nKeep your phone backup too.",
                   static_cast<int>(kMinMasterChars));
        y = surface_.addLabel(text, Role::Body, kDim, x - dp(40), y, colW + dp(80), DT_CENTER | DT_WORDBREAK | DT_NOPREFIX) + dp(12);
    }
    int fw = pinScreen_ ? dp(150) : colW, fx = (W - fw) / 2;
    if (pinScreen_) y = surface_.addLabel(L"PIN", Role::Body, kDim, 0, y, W, DT_CENTER | DT_SINGLELINE | DT_NOPREFIX) + dp(4);
    surface_.placeField(pw1_, fx, y, fw);
    y += Surface::fieldHeight() + dp(8);
    if (pw2_) {
        surface_.placeField(pw2_, fx, y, fw);
        y += Surface::fieldHeight() + dp(4);
        y = surface_.addLabel(L"Repeat the password", Role::Body, kDim, 0, y, W, DT_CENTER | DT_SINGLELINE | DT_NOPREFIX) + dp(6);
    }
    y += pad_->layout(x, y, colW) + dp(4);
    unlockMsgIndex_ = static_cast<int>(surface_.labels.size());
    y = surface_.addLabel(unlockMsg_.empty() ? L" " : unlockMsg_, Role::Body, kRed, x - dp(40), y, colW + dp(80), DT_CENTER | DT_WORDBREAK | DT_NOPREFIX);
    surface_.labels.back().text = unlockMsg_;
    y += dp(8);
    int bw = dp(130), bh = dp(32);
    HWND unlock = GetDlgItem(hwnd_, ID_UNLOCK);
    SetWindowPos(unlock, nullptr, (W - bw) / 2, y, bw, bh, SWP_NOZORDER | SWP_NOACTIVATE);
    y += bh + dp(10);
    if (HWND link = GetDlgItem(hwnd_, ID_USE_MASTER)) SetWindowPos(link, nullptr, (W - dp(190)) / 2, y, dp(190), dp(26), SWP_NOZORDER | SWP_NOACTIVATE);
}

void App::layoutMain(int W, int H) {
    surface_.clear();
    int pad = dp(14), top = dp(12), bh = dp(30), gap = dp(6);
    int widths[4] = {dp(66), dp(72), dp(72), dp(64)};
    int ids[4] = {ID_ADD, ID_IMPORT, ID_EXPORT, ID_MORE};
    int total = 0;
    for (int wv : widths) total += wv + gap;
    int x = W - pad;
    for (int i = 3; i >= 0; --i) {
        x -= widths[i];
        SetWindowPos(GetDlgItem(hwnd_, ids[i]), nullptr, x, top, widths[i], bh, SWP_NOZORDER | SWP_NOACTIVATE);
        x -= gap;
    }
    surface_.placeField(search_, pad, top, W - 2 * pad - total);
    int statusH = dp(28);
    SetWindowPos(list_, nullptr, pad, top + bh + dp(12), W - 2 * pad, std::max(10, H - (top + bh + dp(12)) - statusH), SWP_NOZORDER | SWP_NOACTIVATE);
    statusIndex_ = static_cast<int>(surface_.labels.size());
    surface_.addLabel(status_.empty() ? L" " : status_, Role::Body, statusRed_ ? kRed : kDim, pad, H - statusH + dp(5), W - 2 * pad,
                      DT_LEFT | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
    surface_.labels.back().text = status_;
    updateScroll();
}

void App::setUnlockMessage(const std::wstring& text) {
    unlockMsg_ = text;
    if (view_ == View::Unlock && unlockMsgIndex_ >= 0) {
        surface_.labels[static_cast<size_t>(unlockMsgIndex_)].text = text;
        RECT r = surface_.labels[static_cast<size_t>(unlockMsgIndex_)].box;
        InvalidateRect(hwnd_, &r, FALSE);
        UpdateWindow(hwnd_);
    }
}

void App::setStatus(const std::wstring& text, bool red) {
    status_ = text;
    statusRed_ = red;
    if (view_ == View::Main && statusIndex_ >= 0 && statusIndex_ < static_cast<int>(surface_.labels.size())) {
        Label& l = surface_.labels[static_cast<size_t>(statusIndex_)];
        l.text = text;
        l.color = red ? kRed : kDim;
        RECT r = l.box;
        InvalidateRect(hwnd_, &r, FALSE);
    }
}

// ---- unlocking ---------------------------------------------------------------------------------------------------------
void App::doUnlock() {
    Secret pw = readSecret(pw1_);
    if (pinScreen_) return unlockWithPin(pw);
    bool created = false;
    HCURSOR old = SetCursor(LoadCursorW(nullptr, IDC_WAIT));
    try {
        if (!vault_.exists()) {
            if (!pw.equals(readSecret(pw2_))) {
                SetCursor(old);
                return setUnlockMessage(L"The two passwords differ");
            }
            setUnlockMessage(L"Creating...");
            vault_.create(pw);
            created = true;
        } else {
            setUnlockMessage(L"Checking...");
            vault_.unlock(pw);
        }
    } catch (const WrongMasterPassword&) {
        SetCursor(old);
        setUnlockMessage(L"Wrong master password");
        wipeEdit(pw1_);
        return;
    } catch (const std::exception& e) {
        SetCursor(old);
        return setUnlockMessage(wide(e.what()));
    }
    SetCursor(old);
    unlockMsg_.clear();
    pinMode_ = true;
    showMain();
    if (created) guarded([&] { offerPin(); });   // offered right after the account screen is up
}

void App::unlockWithPin(const Secret& pin) {
    HCURSOR old = SetCursor(LoadCursorW(nullptr, IDC_WAIT));
    setUnlockMessage(L"Checking...");
    try {
        Secret master = pins_.unlock(pin);
        vault_.unlock(master);
    } catch (const WrongPin& e) {
        SetCursor(old);
        setUnlockMessage(wide(e.what()));
        wipeEdit(pw1_);
        return;
    } catch (const PinDisabled& e) {
        SetCursor(old);
        pinMode_ = false;
        showUnlock();
        return setUnlockMessage(wide(e.what()));
    } catch (const WrongMasterPassword&) {   // the master password changed behind the PIN's back
        SetCursor(old);
        pins_.disable();
        pinMode_ = false;
        showUnlock();
        return setUnlockMessage(L"The PIN was out of date and was removed. Use the master password.");
    } catch (const std::exception& e) {
        SetCursor(old);
        return setUnlockMessage(wide(e.what()));
    }
    SetCursor(old);
    unlockMsg_.clear();
    showMain();
}

void App::offerPin() {
    if (MessageBoxW(hwnd_, L"Set a PIN for quick unlock on this PC?\n\n(You can do it later from More.)", kAppName, MB_YESNO | MB_ICONQUESTION) == IDYES)
        setupPin();
}

void App::setupPin() {
    Secret pin;
    wchar_t prompt[512];
    swprintf_s(prompt,
               L"Choose a PIN (%d to %d digits) to unlock on this PC.\n\nA short PIN is weak by nature. It only works with this Windows account, and is "
               L"erased after %d wrong tries. Your master password stays the real key.",
               static_cast<int>(kPinMin), static_cast<int>(kPinMax), kPinMaxAttempts);
    if (!askPassword(hwnd_, L"PIN", prompt, pin, true, kPinMin, true, settings_.secureKeypad())) return;
    try {
        pins_.enable(pin, vault_.masterPassword());
    } catch (const std::exception& e) {
        return fail(e);
    }
    setStatus(L"PIN set. It unlocks B-2FA on this PC only.");
}

void App::removePin() {
    pins_.disable();
    setStatus(L"PIN removed. The master password is needed to unlock.");
}

void App::lock() {
    Modal::closeAll();   // an open dialog may show a secret
    vault_.lock();
    wipeClipboard();
    showUnlock();
}

// ---- the list ---------------------------------------------------------------------------------------------------------------
void App::rebuildRows() {
    if (!vault_.unlocked() || !list_) return;
    std::string query = lowerUnicode(trim(readText(search_)));
    rows_.clear();
    int px = dp(32);
    for (Json* s : vault_.sortedServices()) {
        Row r;
        r.id = serviceId(*s);
        r.name = wide(truncateChars(s->stringOr("name"), 80));
        std::string account;
        bool hotp = false;
        if (const Json* otp = s->get("otp"); otp && otp->isObject()) {
            const Json* a = otp->get("account");
            if (a && a->isString()) account = a->asString();
            hotp = otp->stringOr("tokenType") == "HOTP";
        }
        std::string hay = lowerUnicode(s->stringOr("name") + " " + account);
        if (!query.empty() && hay.find(query) == std::string::npos) continue;
        r.account = wide(truncateChars(account, 80));
        r.hotp = hotp;
        r.icon = icons_.image(*s, px);
        rows_.push_back(std::move(r));
    }
    hover_ = hoverNext_ = -1;
    refreshRows();
    updateScroll();
    InvalidateRect(list_, nullptr, FALSE);
}

void App::refreshRows() {
    if (!list_) return;
    double now = nowSeconds();
    RECT client;
    GetClientRect(list_, &client);
    for (size_t i = 0; i < rows_.size(); ++i) {
        Row& r = rows_[i];
        Json* s = vault_.find(r.id);
        std::string code;
        std::wstring secs;
        bool red = false, invalid = false;
        try {
            if (!s) throw OtpError("gone");
            OtpCode c = currentCode(*s, now);
            code = groupDigits(c.code);
            secs = c.period ? std::to_wstring(c.secondsLeft) + L" s" : L"";
            red = c.period && c.secondsLeft <= 5;
        } catch (const std::exception&) {
            code = "invalid";
            invalid = true;
        }
        // repaint only what changed: no flicker
        if (code != r.codeText || secs != r.secs || red != r.secsRed || invalid != r.invalid) {
            r.codeText = code;
            r.code = wide(code);
            r.secs = secs;
            r.secsRed = red;
            r.invalid = invalid;
            RECT rr{client.right / 2, static_cast<int>(i) * rowHeight() - scroll_, client.right, static_cast<int>(i + 1) * rowHeight() - scroll_};
            InvalidateRect(list_, &rr, FALSE);
        }
    }
}

void App::updateScroll() {
    if (!list_) return;
    RECT rc;
    GetClientRect(list_, &rc);
    int page = rc.bottom;
    int maxScroll = std::max(0, contentHeight() - page);
    scroll_ = std::min(std::max(scroll_, 0), maxScroll);
    SCROLLINFO si{sizeof(si), SIF_RANGE | SIF_PAGE | SIF_POS, 0, std::max(0, contentHeight() - 1), static_cast<UINT>(page), scroll_, 0};
    SetScrollInfo(list_, SB_VERT, &si, TRUE);
}

int App::rowAt(int y) const {
    int i = (y + scroll_) / rowHeight();
    return (y + scroll_ >= 0 && i >= 0 && i < static_cast<int>(rows_.size())) ? i : -1;
}

RECT App::nextButtonRect(int row, int width) const {
    int top = row * rowHeight() - scroll_;
    int right = width - dp(10);
    int codeW = dp(120);
    int bw = dp(52), bh = dp(26);
    return RECT{right - codeW - dp(12) - bw, top + (rowHeight() - bh) / 2, right - codeW - dp(12), top + (rowHeight() - bh) / 2 + bh};
}

void App::paintList(HWND list) {
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(list, &ps);
    RECT rc;
    GetClientRect(list, &rc);
    HDC mem = CreateCompatibleDC(dc);
    HBITMAP bmp = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
    HGDIOBJ oldBmp = SelectObject(mem, bmp);
    HBRUSH white = CreateSolidBrush(kBg);
    FillRect(mem, &rc, white);
    DeleteObject(white);
    SetBkMode(mem, TRANSPARENT);
    int rh = rowHeight();
    if (rows_.empty()) {
        bool searching = view_ == View::Main && search_ && GetWindowTextLengthW(search_) > 0;
        std::wstring text = searching ? L"No match."
                                      : L"No accounts yet.\n\nImport your 2FAS backup (.2fas)\nfrom the phone, or add an account.";
        RECT r{0, dp(60), rc.right, rc.bottom};
        SelectObject(mem, font(Role::Body));
        SetTextColor(mem, kDim);
        DrawTextW(mem, text.c_str(), -1, &r, DT_CENTER | DT_WORDBREAK | DT_NOPREFIX);
    }
    int first = std::max(0, scroll_ / rh), last = std::min(static_cast<int>(rows_.size()) - 1, static_cast<int>((scroll_ + rc.bottom) / rh));
    for (int i = first; i <= last; ++i) {
        const Row& r = rows_[static_cast<size_t>(i)];
        int top = i * rh - scroll_;
        RECT row{0, top, rc.right, top + rh};
        if (i == hover_) {
            HBRUSH hb = CreateSolidBrush(kHover);
            FillRect(mem, &row, hb);
            DeleteObject(hb);
        }
        // icon
        int tile = dp(32), ix = dp(6), iy = top + (rh - tile) / 2;
        if (r.icon) {
            HDC src = CreateCompatibleDC(mem);
            HGDIOBJ o = SelectObject(src, r.icon);
            BLENDFUNCTION bf{AC_SRC_OVER, 0, 255, AC_SRC_ALPHA};
            AlphaBlend(mem, ix, iy, tile, tile, src, 0, 0, tile, tile, bf);
            SelectObject(src, o);
            DeleteDC(src);
        } else {
            RECT t{ix, iy, ix + tile, iy + tile};
            HBRUSH tb = CreateSolidBrush(kTile);
            FillRect(mem, &t, tb);
            DeleteObject(tb);
            SelectObject(mem, font(Role::Bold));
            SetTextColor(mem, kDim);
            std::wstring ini = wide(initials(narrow(r.name)));
            DrawTextW(mem, ini.c_str(), -1, &t, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        }
        // name and account
        int tx = ix + tile + dp(12);
        int codeLeft = rc.right - dp(10) - dp(130);
        RECT nr{tx, top + dp(9), std::max(tx + 10, codeLeft - (r.hotp ? dp(70) : 0)), top + dp(29)};
        SelectObject(mem, font(Role::Bold));
        SetTextColor(mem, kFg);
        DrawTextW(mem, r.name.c_str(), -1, &nr, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        RECT ar{tx, top + dp(30), nr.right, top + dp(48)};
        SelectObject(mem, font(Role::Body));
        SetTextColor(mem, kDim);
        DrawTextW(mem, r.account.c_str(), -1, &ar, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        // code and seconds, right aligned
        int right = rc.right - dp(10);
        RECT cr{right - dp(130), top + dp(5), right, top + dp(34)};
        SelectObject(mem, font(Role::Mono));
        SetTextColor(mem, r.invalid ? kRed : kFg);
        DrawTextW(mem, r.code.c_str(), -1, &cr, DT_RIGHT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
        if (!r.secs.empty()) {
            RECT sr{right - dp(130), top + dp(35), right, top + dp(52)};
            SelectObject(mem, font(Role::Small));
            SetTextColor(mem, r.secsRed ? kRed : kDim);
            DrawTextW(mem, r.secs.c_str(), -1, &sr, DT_RIGHT | DT_SINGLELINE | DT_NOPREFIX);
        }
        if (r.hotp) {
            RECT nb = nextButtonRect(i, rc.right);
            HBRUSH bb = CreateSolidBrush(i == hoverNext_ ? kBtnHover : kBtn);
            FillRect(mem, &nb, bb);
            DeleteObject(bb);
            SelectObject(mem, font(Role::Body));
            SetTextColor(mem, kFg);
            DrawTextW(mem, L"Next", -1, &nb, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        }
        // hairline between accounts
        RECT sep{0, top + rh - 1, rc.right, top + rh};
        HBRUSH hl = CreateSolidBrush(kHairline);
        FillRect(mem, &sep, hl);
        DeleteObject(hl);
    }
    BitBlt(dc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
    SelectObject(mem, oldBmp);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(list, &ps);
}

LRESULT CALLBACK App::listProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    App* self = nullptr;
    if (m == WM_NCCREATE) {
        self = static_cast<App*>(reinterpret_cast<CREATESTRUCTW*>(l)->lpCreateParams);
        SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        return DefWindowProcW(h, m, w, l);
    }
    self = reinterpret_cast<App*>(GetWindowLongPtrW(h, GWLP_USERDATA));
    if (self && self->list_ == h) return self->onListMessage(h, m, w, l);
    return DefWindowProcW(h, m, w, l);
}

LRESULT App::onListMessage(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
        case WM_PAINT: paintList(h); return 0;
        case WM_ERASEBKGND: return 1;
        case WM_SIZE: updateScroll(); return 0;
        case WM_MOUSEWHEEL: {
            int delta = GET_WHEEL_DELTA_WPARAM(w);
            scroll_ -= delta * rowHeight() / 120 * 2 / 2;
            updateScroll();
            InvalidateRect(h, nullptr, FALSE);
            return 0;
        }
        case WM_VSCROLL: {
            SCROLLINFO si{sizeof(si), SIF_ALL};
            GetScrollInfo(h, SB_VERT, &si);
            int pos = si.nPos;
            switch (LOWORD(w)) {
                case SB_LINEUP: pos -= rowHeight() / 2; break;
                case SB_LINEDOWN: pos += rowHeight() / 2; break;
                case SB_PAGEUP: pos -= static_cast<int>(si.nPage); break;
                case SB_PAGEDOWN: pos += static_cast<int>(si.nPage); break;
                case SB_THUMBTRACK: case SB_THUMBPOSITION: pos = si.nTrackPos; break;
            }
            scroll_ = pos;
            updateScroll();
            InvalidateRect(h, nullptr, FALSE);
            return 0;
        }
        case WM_MOUSEMOVE: {
            int y = GET_Y_LPARAM(l), x = GET_X_LPARAM(l);
            int row = rowAt(y), nextRow = -1;
            RECT rc;
            GetClientRect(h, &rc);
            if (row >= 0 && rows_[static_cast<size_t>(row)].hotp) {
                RECT nb = nextButtonRect(row, rc.right);
                POINT p{x, y};
                if (PtInRect(&nb, p)) nextRow = row;
            }
            if (row != hover_ || nextRow != hoverNext_) {
                hover_ = row;
                hoverNext_ = nextRow;
                InvalidateRect(h, nullptr, FALSE);
            }
            if (!tracking_) {
                TRACKMOUSEEVENT t{sizeof(t), TME_LEAVE, h, 0};
                TrackMouseEvent(&t);
                tracking_ = true;
            }
            return 0;
        }
        case WM_MOUSELEAVE:
            tracking_ = false;
            hover_ = hoverNext_ = -1;
            InvalidateRect(h, nullptr, FALSE);
            return 0;
        case WM_SETCURSOR:
            if (hover_ >= 0) { SetCursor(LoadCursorW(nullptr, IDC_HAND)); return TRUE; }
            break;
        case WM_LBUTTONDOWN: {
            int row = rowAt(GET_Y_LPARAM(l));
            if (row < 0) return 0;
            guarded([&] {
                if (hoverNext_ == row) nextHotp(row);
                else copyCode(row);
            });
            return 0;
        }
        case WM_RBUTTONUP: {
            int row = rowAt(GET_Y_LPARAM(l));
            if (row < 0) return 0;
            POINT p{GET_X_LPARAM(l), GET_Y_LPARAM(l)};
            ClientToScreen(h, &p);
            guarded([&] { rowMenu(row, p); });
            return 0;
        }
    }
    return DefWindowProcW(h, m, w, l);
}

void App::copyCode(int row) {
    const Row& r = rows_[static_cast<size_t>(row)];
    Json* s = vault_.find(r.id);
    if (!s) return;
    try {
        OtpCode c = currentCode(*s, nowSeconds());
        copyToClipboard(c.code, wide(truncateChars(narrow(r.name), 40)));
    } catch (const OtpError&) {
    }
}

void App::nextHotp(int row) {
    std::string id = rows_[static_cast<size_t>(row)].id;
    try {
        vault_.bumpCounter(id);
    } catch (const std::exception& e) {
        MessageBoxW(hwnd_, wide(e.what()).c_str(), kAppName, MB_OK | MB_ICONERROR);
    }
    refreshRows();
}

void App::rowMenu(int row, POINT screen) {
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, CMD_ROW_COPY, L"Copy code");
    AppendMenuW(menu, MF_STRING, CMD_ROW_EDIT, L"Edit...");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, CMD_ROW_DELETE, L"Delete...");
    menuRow_ = rows_[static_cast<size_t>(row)].id;
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, screen.x, screen.y, 0, hwnd_, nullptr);   // the choice arrives as WM_COMMAND
    DestroyMenu(menu);
}

// ---- actions ----------------------------------------------------------------------------------------------------------------------
void App::report(const std::exception& e) {
    static bool reporting = false;
    if (reporting) return;
    reporting = true;
    std::string name = typeid(e).name();
    bool ours = dynamic_cast<const VaultError*>(&e) || dynamic_cast<const OtpError*>(&e) || dynamic_cast<const twofas::BackupError*>(&e) ||
                dynamic_cast<const PinError*>(&e) || dynamic_cast<const IoError*>(&e);
    std::wstring text = ours ? wide(e.what()) : L"Something went wrong:\n" + wide(name);
    MessageBoxW(hwnd_, text.c_str(), kAppName, MB_OK | MB_ICONERROR);
    reporting = false;
    if (vault_.unlocked() && view_ == View::Main) rebuildRows();
}

void App::fail(const std::exception& e) {
    report(e);
}

void App::addAccount() {
    Json s;
    if (!b2::editAccount(hwnd_, nullptr, s)) return;
    try {
        vault_.add(std::move(s));
    } catch (const std::exception& e) {
        return fail(e);
    }
    rebuildRows();
    setStatus(L"Added");
}

void App::editAccount(const std::string& id) {
    Json* s = vault_.find(id);
    if (!s) return;
    Json copy = *s, edited;
    if (!b2::editAccount(hwnd_, &copy, edited)) return;
    try {
        vault_.update(edited);
    } catch (const std::exception& e) {
        return fail(e);
    }
    rebuildRows();
}

void App::deleteAccount(const std::string& id) {
    Json* s = vault_.find(id);
    if (!s) return;
    std::wstring text = L"Delete " + wide(truncateChars(s->stringOr("name"), 60)) +
                        L"?\n\nIt is removed from this vault and from the automatic backups (they are rewritten). Make sure it is still in your phone or in "
                        L"an exported backup, or you may lose access to that account.";
    if (MessageBoxW(hwnd_, text.c_str(), kAppName, MB_YESNO | MB_ICONWARNING) != IDYES) return;
    try {
        vault_.remove(id);
    } catch (const std::exception& e) {
        return fail(e);
    }
    rebuildRows();
}

bool App::openFileDialog(std::wstring& path, const wchar_t* title, const wchar_t* filter) {
    wchar_t buf[MAX_PATH * 4] = {};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = buf;
    ofn.nMaxFile = static_cast<DWORD>(std::size(buf));
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    if (!GetOpenFileNameW(&ofn)) return false;
    path = buf;
    return true;
}

bool App::saveFileDialog(std::wstring& path, const wchar_t* title, const wchar_t* filter, const wchar_t* defExt, const std::wstring& initial) {
    wchar_t buf[MAX_PATH * 4] = {};
    wcsncpy_s(buf, initial.c_str(), _TRUNCATE);
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = buf;
    ofn.nMaxFile = static_cast<DWORD>(std::size(buf));
    ofn.lpstrTitle = title;
    ofn.lpstrDefExt = defExt;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    if (!GetSaveFileNameW(&ofn)) return false;
    path = buf;
    return true;
}

void App::importBackup() {
    std::wstring path;
    if (!openFileDialog(path, L"Import a 2FAS backup", L"2FAS backup (*.2fas;*.json)\0*.2fas;*.json\0All files\0*.*\0\0")) return;
    Json content;
    try {
        content = twofas::readBackup(path);
        if (twofas::isEncrypted(content)) {
            while (true) {
                Secret pw;
                if (!askPassword(hwnd_, L"Encrypted backup", L"Password of this backup (the one you set in 2FAS):", pw)) return;
                try {
                    content = twofas::decryptBackup(content, pw);
                    break;
                } catch (const twofas::WrongPassword&) {
                    MessageBoxW(hwnd_, L"Wrong password. Try again.", kAppName, MB_OK | MB_ICONWARNING);
                }
            }
        } else {
            content = twofas::decryptBackup(content, Secret());
        }
        auto [added, skipped] = vault_.merge(content);
        rebuildRows();
        std::wstring msg = std::to_wstring(added) + L" account(s) added, " + std::to_wstring(skipped) + L" already here or skipped.";
        MessageBoxW(hwnd_, msg.c_str(), kAppName, MB_OK | MB_ICONINFORMATION);
    } catch (const std::exception& e) {
        fail(e);
    }
}

void App::exportBackup() {
    if (vault_.services.empty()) {
        MessageBoxW(hwnd_, L"Nothing to export yet.", kAppName, MB_OK | MB_ICONINFORMATION);
        return;
    }
    Secret pw;
    wchar_t prompt[512];
    swprintf_s(prompt,
               L"Password for the .2fas file (%d characters minimum, different from the master password).\n\nThe 2FAS format protects a password far less than "
               L"the vault does, so choose a long passphrase.",
               static_cast<int>(kMinExportChars));
    if (!askPassword(hwnd_, L"Export a 2FAS backup", prompt, pw, true, kMinExportChars)) return;
    std::wstring path;
    if (!saveFileDialog(path, L"Export a 2FAS backup", L"2FAS backup (*.2fas)\0*.2fas\0\0", L"2fas", wide("B-2FA-export-" + todayStamp() + ".2fas"))) return;
    try {
        vault_.exportBackup(path, pw);
    } catch (const std::exception& e) {
        return fail(e);
    }
    setStatus(L"Exported " + std::filesystem::path(path).filename().wstring());
}

void App::backupNow() {
    try {
        auto target = vault_.autoBackup();
        setStatus(target ? L"Backup written: " + target->filename().wstring() : L"Nothing to back up yet.");
    } catch (const std::exception& e) {
        fail(e);
    }
}

void App::changePassword() {
    Secret oldPw, newPw;
    if (!askPassword(hwnd_, L"Master password", L"Current master password:", oldPw)) return;
    wchar_t prompt[256];
    swprintf_s(prompt, L"New master password (%d characters minimum).\n\nOlder backups made with the old password are deleted and rewritten.",
               static_cast<int>(kMinMasterChars));
    if (!askPassword(hwnd_, L"Master password", prompt, newPw, true, kMinMasterChars)) return;
    HCURSOR old = SetCursor(LoadCursorW(nullptr, IDC_WAIT));
    try {
        vault_.changePassword(oldPw, newPw);
    } catch (const std::exception& e) {
        SetCursor(old);
        return fail(e);
    }
    SetCursor(old);
    pins_.disable();   // the PIN wraps the OLD password: it must be set again
    setStatus(L"Master password changed. The PIN was removed: set it again from More.");
}

void App::openBackups() {
    std::filesystem::path folder = paths::backupsDir();
    std::error_code ec;
    std::filesystem::create_directories(folder, ec);
    HINSTANCE r = ShellExecuteW(hwnd_, L"open", folder.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(r) <= 32) {
        std::wstring arg = L"\"" + folder.wstring() + L"\"";
        r = ShellExecuteW(hwnd_, L"open", L"explorer.exe", arg.c_str(), nullptr, SW_SHOWNORMAL);
    }
    if (reinterpret_cast<INT_PTR>(r) <= 32) {
        std::wstring text = L"Could not open the folder. It is here:\n\n" + folder.wstring();
        MessageBoxW(hwnd_, text.c_str(), kAppName, MB_OK | MB_ICONINFORMATION);
    }
}

void App::toggleSecureKeypad() {
    settings_.setSecureKeypad(!settings_.secureKeypad());
    setStatus(settings_.secureKeypad() ? L"PIN entry: always the shuffled on-screen keypad." : L"PIN entry: physical keyboard (keypad on demand).");
}

void App::toggleCaptureBlock() {
    if (!guard_) return;
    if (guard_->enabled()) {
        guard_->disable();
        setStatus(L"Screen capture is allowed until you restart B-2FA.");
    } else {
        guard_->enable();
        setStatus(L"Screen capture is blocked.");
    }
}

void App::moreMenu() {
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, CMD_OPEN_BACKUPS, L"Open backups folder");
    AppendMenuW(menu, MF_STRING, CMD_BACKUP_NOW, L"Backup now");
    AppendMenuW(menu, MF_STRING, CMD_CHANGE_PW, L"Change master password...");
    AppendMenuW(menu, MF_STRING, CMD_SET_PIN, L"Set or change PIN...");
    AppendMenuW(menu, MF_STRING, CMD_REMOVE_PIN, L"Remove PIN");
    AppendMenuW(menu, MF_STRING | (settings_.secureKeypad() ? MF_CHECKED : 0), CMD_SECURE_KEYPAD, L"Always use the keypad for the PIN");
    if (CaptureGuard::supported())
        AppendMenuW(menu, MF_STRING | ((guard_ && guard_->enabled()) ? MF_CHECKED : 0), CMD_BLOCK_CAPTURE, L"Block screen capture");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, CMD_ABOUT, L"About B-2FA");
    AppendMenuW(menu, MF_STRING, CMD_LOCK, L"Lock");
    HWND button = GetDlgItem(hwnd_, ID_MORE);
    RECT r;
    GetWindowRect(button, &r);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RIGHTALIGN, r.right, r.bottom, 0, hwnd_, nullptr);   // WM_COMMAND follows
    DestroyMenu(menu);
}

void App::tick() {
    if (!vault_.unlocked()) return;
    if (GetTickCount64() - lastActivity() > kAutoLockMs) {
        lock();
        return;
    }
    if (view_ == View::Main) refreshRows();
    vault_.flushBackup();
}

// ---- clipboard ---------------------------------------------------------------------------------------------------------------------
void App::copyToClipboard(const std::string& text, const std::wstring& label) {
    if (!clip::setText(text)) {
        setStatus(L"The clipboard is busy. Try again.", true);
        return;
    }
    clipText_ = text;
    SetTimer(hwnd_, TIMER_CLIPBOARD, kClipboardClearMs, nullptr);   // a new copy restarts the 30 s
    setStatus(L"Copied " + label + L". Clipboard clears in " + std::to_wstring(kClipboardClearMs / 1000) + L" s.");
}

void App::wipeClipboard() {
    // empty the clipboard, but only if it still holds the code we put there
    if (clipText_.empty()) return;
    std::string current;
    if (clip::getText(current) && current == clipText_) clip::clear();
    secureZero(clipText_.data(), clipText_.size());
    clipText_.clear();
    secureZero(current.data(), current.size());
}

}  // namespace

int runApp(HINSTANCE instance, int showCommand) {
    App app;
    return app.run(instance, showCommand);
}

}  // namespace b2
