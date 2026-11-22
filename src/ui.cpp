// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "ui.h"

#include <commctrl.h>

#include <algorithm>
#include <atomic>
#include <unordered_map>

#include "keypad_layout.h"

namespace b2::ui {

namespace {

HFONT g_fonts[7] = {};
UINT g_dpi = 96;
std::atomic<uint64_t> g_activity{0};
std::vector<Modal*> g_modals;
std::function<void(HWND)> g_modalHook;
HBRUSH g_whiteBrush = nullptr;

const wchar_t kPropRole[] = L"b2role";
const wchar_t kPropStyle[] = L"b2style";
const wchar_t kPropHover[] = L"b2hover";
const wchar_t kPropLock[] = L"b2lock";
std::unordered_map<HWND, wchar_t> g_keyChars;   // keypad labels live in this program's memory only

HFONT makeFont(const wchar_t* face, int pt, int weight) {
    return CreateFontW(-MulDiv(pt, static_cast<int>(g_dpi), 72), 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, face);
}

}  // namespace

// ---- fonts and dpi ---------------------------------------------------------------------------
void setDpi(UINT d) {
    g_dpi = d ? d : 96;
    for (HFONT& f : g_fonts) if (f) DeleteObject(f);
    g_fonts[static_cast<int>(Role::Body)] = makeFont(L"Segoe UI", 9, FW_NORMAL);
    g_fonts[static_cast<int>(Role::Bold)] = makeFont(L"Segoe UI Semibold", 10, FW_NORMAL);
    g_fonts[static_cast<int>(Role::Small)] = makeFont(L"Segoe UI", 8, FW_NORMAL);
    g_fonts[static_cast<int>(Role::Mono)] = makeFont(L"Consolas", 17, FW_NORMAL);
    g_fonts[static_cast<int>(Role::Title)] = makeFont(L"Segoe UI Light", 26, FW_NORMAL);
    g_fonts[static_cast<int>(Role::Heading)] = makeFont(L"Segoe UI Semibold", 16, FW_NORMAL);
    g_fonts[static_cast<int>(Role::Key)] = makeFont(L"Segoe UI", 11, FW_NORMAL);
}

UINT dpi() { return g_dpi; }
int dp(int px) { return MulDiv(px, static_cast<int>(g_dpi), 96); }
HFONT font(Role r) { return g_fonts[static_cast<int>(r)]; }

void applyFont(HWND w, Role r) {
    SetPropW(w, kPropRole, reinterpret_cast<HANDLE>(static_cast<INT_PTR>(static_cast<int>(r) + 1)));
    SendMessageW(w, WM_SETFONT, reinterpret_cast<WPARAM>(font(r)), TRUE);
}

void refreshFonts(HWND root) {
    EnumChildWindows(root, [](HWND h, LPARAM) -> BOOL {
        INT_PTR role = reinterpret_cast<INT_PTR>(GetPropW(h, kPropRole));
        if (role > 0) SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(font(static_cast<Role>(role - 1))), TRUE);
        return TRUE;
    }, 0);
}

// ---- activity and the message loop -------------------------------------------------------------
uint64_t lastActivity() { return g_activity.load(); }
void touchActivity() { g_activity.store(GetTickCount64()); }

bool pump(HWND dialog) {
    MSG msg;
    BOOL got = GetMessageW(&msg, nullptr, 0, 0);
    if (got == 0) {
        PostQuitMessage(static_cast<int>(msg.wParam));
        return false;
    }
    if (got < 0) return false;
    switch (msg.message) {
        case WM_MOUSEMOVE: case WM_LBUTTONDOWN: case WM_RBUTTONDOWN: case WM_KEYDOWN: case WM_MOUSEWHEEL: {
            // Only a person at the keyboard or mouse counts: a message another program posts to this window does
            // not reset the auto-lock (the system records the last REAL input).
            LASTINPUTINFO li{sizeof(li), 0};
            if (GetLastInputInfo(&li) && static_cast<DWORD>(GetTickCount() - li.dwTime) < 2000) touchActivity();
            break;
        }
    }
    if (dialog && (msg.hwnd == dialog || IsChild(dialog, msg.hwnd))) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE) {
            PostMessageW(dialog, WM_COMMAND, IDCANCEL, 0);
            return true;
        }
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN) {
            wchar_t cls[16] = {};
            GetClassNameW(msg.hwnd, cls, 16);
            if (lstrcmpiW(cls, L"Button") != 0) {   // Enter on a button presses it; elsewhere it means OK
                PostMessageW(dialog, WM_COMMAND, IDOK, 0);
                return true;
            }
        }
        if (IsDialogMessageW(dialog, &msg)) return true;
    }
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
    return true;
}

void setModalHook(std::function<void(HWND)> hook) { g_modalHook = std::move(hook); }

// ---- buttons ---------------------------------------------------------------------------------------
namespace {

LRESULT CALLBACK buttonProc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR) {
    switch (m) {
        case WM_MOUSEMOVE:
            if (!GetPropW(h, kPropHover)) {
                SetPropW(h, kPropHover, reinterpret_cast<HANDLE>(1));
                TRACKMOUSEEVENT t{sizeof(t), TME_LEAVE, h, 0};
                TrackMouseEvent(&t);
                InvalidateRect(h, nullptr, FALSE);
            }
            break;
        case WM_MOUSELEAVE:
            RemovePropW(h, kPropHover);
            InvalidateRect(h, nullptr, FALSE);
            break;
        case WM_SETCURSOR:
            SetCursor(LoadCursorW(nullptr, IDC_HAND));
            return TRUE;
        case WM_LBUTTONDBLCLK:
            // a second quick click arrives as a double click, which a button turns into BN_DOUBLECLICKED:
            // the keypad would drop the repeated letter. Treat it as one more ordinary click.
            return DefSubclassProc(h, WM_LBUTTONDOWN, w, l);
        case WM_NCDESTROY:
            g_keyChars.erase(h);
            RemovePropW(h, kPropHover);
            RemovePropW(h, kPropStyle);
            RemovePropW(h, kPropRole);
            RemoveWindowSubclass(h, buttonProc, id);
            break;
    }
    return DefSubclassProc(h, m, w, l);
}

}  // namespace

HWND makeButton(HWND parent, int id, const std::wstring& text, BtnStyle style, bool tabStop) {
    HWND h = CreateWindowExW(0, L"BUTTON", text.c_str(), WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | (tabStop ? WS_TABSTOP : 0), 0, 0, 10, 10,
                             parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
    SetPropW(h, kPropStyle, reinterpret_cast<HANDLE>(static_cast<INT_PTR>(static_cast<int>(style) + 1)));
    applyFont(h, style == BtnStyle::Key ? Role::Key : Role::Body);
    SetWindowSubclass(h, buttonProc, 1, 0);
    return h;
}

void setKeyLabel(HWND button, wchar_t ch) {
    g_keyChars[button] = ch;   // not a window property and not window text: other programs can read both
    SetWindowTextW(button, L"");
    InvalidateRect(button, nullptr, FALSE);
}

void setButtonText(HWND button, const std::wstring& text) {
    SetWindowTextW(button, text.c_str());
    InvalidateRect(button, nullptr, FALSE);
}

void drawButton(const DRAWITEMSTRUCT* d) {
    BtnStyle style = static_cast<BtnStyle>(reinterpret_cast<INT_PTR>(GetPropW(d->hwndItem, kPropStyle)) - 1);
    bool hover = GetPropW(d->hwndItem, kPropHover) != nullptr || (d->itemState & ODS_SELECTED);
    COLORREF fill, text;
    switch (style) {
        case BtnStyle::Primary: fill = hover ? kRedHover : kRed; text = RGB(255, 255, 255); break;
        case BtnStyle::Link: case BtnStyle::LinkLeft: fill = kBg; text = hover ? kFg : kDim; break;
        default: fill = hover ? kBtnHover : kBtn; text = kFg; break;
    }
    if (d->itemState & ODS_DISABLED) text = kLine;
    HBRUSH br = CreateSolidBrush(fill);
    FillRect(d->hDC, &d->rcItem, br);
    DeleteObject(br);
    wchar_t buf[128];
    auto keyIt = g_keyChars.find(d->hwndItem);
    wchar_t keyChar = keyIt == g_keyChars.end() ? L'\0' : keyIt->second;
    if (keyChar) {
        buf[0] = keyChar;
        buf[1] = 0;
    } else {
        GetWindowTextW(d->hwndItem, buf, 128);
    }
    HGDIOBJ old = SelectObject(d->hDC, reinterpret_cast<HFONT>(SendMessageW(d->hwndItem, WM_GETFONT, 0, 0)));
    SetBkMode(d->hDC, TRANSPARENT);
    SetTextColor(d->hDC, text);
    RECT r = d->rcItem;
    DrawTextW(d->hDC, buf, -1, &r, (style == BtnStyle::LinkLeft ? DT_LEFT : DT_CENTER) | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(d->hDC, old);
    if ((d->itemState & ODS_FOCUS) && !(d->itemState & ODS_NOFOCUSRECT) && style != BtnStyle::Key) {
        RECT f = d->rcItem;
        InflateRect(&f, -dp(2), -dp(2));
        DrawFocusRect(d->hDC, &f);
    }
}

// ---- text fields ----------------------------------------------------------------------------------------
namespace {

LRESULT CALLBACK editProc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR) {
    bool locked = GetPropW(h, kPropLock) != nullptr;
    if (locked) {
        // typed characters are ignored (a keylogger sees keystrokes, not mouse clicks on a shuffled pad);
        // paste (a password manager), Tab, Enter and Escape still work
        if (m == WM_CHAR && (w >= 32 || w == 8)) return 0;
        if (m == WM_KEYDOWN && (w == VK_DELETE)) return 0;
        if (m == WM_IME_CHAR || m == WM_UNICHAR) return 0;
    }
    if (m == WM_NCDESTROY) {
        RemovePropW(h, kPropLock);
        RemovePropW(h, kPropRole);
        RemoveWindowSubclass(h, editProc, id);
    }
    return DefSubclassProc(h, m, w, l);
}

}  // namespace

HWND makeEdit(HWND parent, int id, bool password) {
    HWND h = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | (password ? ES_PASSWORD : 0), 0, 0, 10,
                             10, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
    applyFont(h, Role::Body);
    SendMessageW(h, EM_LIMITTEXT, 1024, 0);
    if (password) SendMessageW(h, EM_SETPASSWORDCHAR, 0x25CF, 0);
    SetWindowSubclass(h, editProc, 2, 0);
    return h;
}

void lockPhysicalKeyboard(HWND edit, bool locked) {
    if (locked) SetPropW(edit, kPropLock, reinterpret_cast<HANDLE>(1));
    else RemovePropW(edit, kPropLock);
}

std::string readText(HWND edit) {
    int n = GetWindowTextLengthW(edit);
    std::vector<wchar_t, ZeroAllocator<wchar_t>> buf(static_cast<size_t>(n) + 1);
    GetWindowTextW(edit, buf.data(), n + 1);
    std::string s = narrow(std::wstring_view(buf.data(), static_cast<size_t>(n)));
    return s;
}

Secret readSecret(HWND edit) {
    std::string t = readText(edit);
    Secret s{std::string_view(t)};
    secureZero(t.data(), t.size());
    return s;
}

void setText(HWND edit, const std::string& utf8) { SetWindowTextW(edit, widen(utf8).c_str()); }

void wipeEdit(HWND edit) {
    // overwrite the control's buffer with filler of the same length first, then empty it
    int n = GetWindowTextLengthW(edit);
    if (n > 0) SetWindowTextW(edit, std::wstring(static_cast<size_t>(n), L'0').c_str());
    SetWindowTextW(edit, L"");
}

// ---- surface -------------------------------------------------------------------------------------------------
int Surface::measure(const std::wstring& text, Role role, int w) {
    HDC dc = GetDC(nullptr);
    HGDIOBJ old = SelectObject(dc, font(role));
    RECT r{0, 0, w, 0};
    DrawTextW(dc, text.empty() ? L" " : text.c_str(), -1, &r, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
    SelectObject(dc, old);
    ReleaseDC(nullptr, dc);
    return r.bottom;
}

int Surface::addLabel(const std::wstring& text, Role role, COLORREF color, int x, int y, int w, UINT format) {
    Label l;
    l.text = text;
    l.role = role;
    l.color = color;
    l.format = format;
    int h = measure(text, role, w);
    l.box = RECT{x, y, x + w, y + h};
    labels.push_back(std::move(l));
    return y + h;
}

void Surface::placeField(HWND edit, int x, int y, int w) {
    int fh = fieldHeight();
    HFONT f = font(Role::Body);
    HDC dc = GetDC(nullptr);
    HGDIOBJ old = SelectObject(dc, f);
    TEXTMETRICW tm{};
    GetTextMetricsW(dc, &tm);
    SelectObject(dc, old);
    ReleaseDC(nullptr, dc);
    int eh = tm.tmHeight + 2;
    SetWindowPos(edit, nullptr, x + dp(8), y + (fh - eh) / 2, w - dp(16), eh, SWP_NOZORDER | SWP_NOACTIVATE);
    RECT frame{x, y, x + w, y + fh};
    for (Field& fld : fields) {
        if (fld.edit == edit) { fld.frame = frame; return; }
    }
    fields.push_back(Field{edit, frame});
}

void Surface::invalidateField(HWND window, HWND edit) {
    for (const Field& f : fields) {
        if (f.edit == edit) {
            RECT r = f.frame;
            InflateRect(&r, 2, 2);
            InvalidateRect(window, &r, FALSE);
        }
    }
}

void Surface::paint(HWND window, const std::function<void(HDC, const RECT&)>& extra) {
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(window, &ps);
    RECT rc;
    GetClientRect(window, &rc);
    HDC mem = CreateCompatibleDC(dc);
    HBITMAP bmp = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
    HGDIOBJ oldBmp = SelectObject(mem, bmp);
    HBRUSH bg = CreateSolidBrush(background);
    FillRect(mem, &rc, bg);
    DeleteObject(bg);
    SetBkMode(mem, TRANSPARENT);
    for (const Label& l : labels) {
        if (l.text.empty()) continue;
        HGDIOBJ old = SelectObject(mem, font(l.role));
        SetTextColor(mem, l.color);
        RECT b = l.box;
        DrawTextW(mem, l.text.c_str(), -1, &b, l.format);
        SelectObject(mem, old);
    }
    for (const Field& f : fields) {
        bool focus = GetFocus() == f.edit;
        HBRUSH br = CreateSolidBrush(focus ? kRed : kLine);
        FrameRect(mem, &f.frame, br);
        DeleteObject(br);
    }
    if (extra) extra(mem, rc);
    BitBlt(dc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
    SelectObject(mem, oldBmp);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(window, &ps);
}

LRESULT ctlColor(UINT, HDC dc, HWND) {
    if (!g_whiteBrush) g_whiteBrush = CreateSolidBrush(kBg);
    SetTextColor(dc, kFg);
    SetBkColor(dc, kBg);
    return reinterpret_cast<LRESULT>(g_whiteBrush);
}

// ---- modal windows ---------------------------------------------------------------------------------------------
namespace {
const wchar_t kModalClass[] = L"B2FAModal";

void registerModalClass(WNDPROC proc) {
    static bool done = false;
    if (done) return;
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = proc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = kModalClass;
    wc.hIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(1));
    RegisterClassExW(&wc);
    done = true;
}
}  // namespace

LRESULT CALLBACK Modal::proc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(l);
        SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        static_cast<Modal*>(cs->lpCreateParams)->hwnd_ = h;
    }
    auto* self = reinterpret_cast<Modal*>(GetWindowLongPtrW(h, GWLP_USERDATA));
    if (self) return self->handle(m, w, l);
    return DefWindowProcW(h, m, w, l);
}

LRESULT Modal::handle(UINT m, WPARAM w, LPARAM l) {
    switch (m) {
        case WM_PAINT: surface_.paint(hwnd_); return 0;
        case WM_ERASEBKGND: return 1;
        case WM_CLOSE: onClose(); return 0;
        case WM_DRAWITEM: drawButton(reinterpret_cast<DRAWITEMSTRUCT*>(l)); return TRUE;
        case WM_CTLCOLOREDIT: case WM_CTLCOLORSTATIC: case WM_CTLCOLORLISTBOX: case WM_CTLCOLORBTN:
            return ctlColor(m, reinterpret_cast<HDC>(w), reinterpret_cast<HWND>(l));
        case WM_COMMAND: {
            int id = LOWORD(w), code = HIWORD(w);
            HWND ctl = reinterpret_cast<HWND>(l);
            if (code == EN_SETFOCUS || code == EN_KILLFOCUS) surface_.invalidateField(hwnd_, ctl);
            if (id == IDCANCEL && !ctl) { onClose(); return 0; }
            onCommand(id, code, ctl);
            return 0;
        }
        case WM_DPICHANGED: return 0;
    }
    return DefWindowProcW(hwnd_, m, w, l);
}

int Modal::run() {
    registerModalClass(&Modal::proc);
    DWORD style = WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN;
    DWORD ex = WS_EX_DLGMODALFRAME;
    clientWidth_ = dp(widthDp());
    RECT rc{0, 0, clientWidth_, dp(100)};
    AdjustWindowRectExForDpi(&rc, style, FALSE, ex, dpi());
    hwnd_ = CreateWindowExW(ex, kModalClass, title_.c_str(), style, CW_USEDEFAULT, CW_USEDEFAULT, rc.right - rc.left, rc.bottom - rc.top,
                            owner_, nullptr, GetModuleHandleW(nullptr), this);
    if (!hwnd_) return 0;
    g_modals.push_back(this);
    try {
        build();
    } catch (...) {
        g_modals.erase(std::remove(g_modals.begin(), g_modals.end(), this), g_modals.end());   // never leave a dangling pointer behind
        DestroyWindow(hwnd_);
        hwnd_ = nullptr;
        throw;
    }
    if (g_modalHook) g_modalHook(hwnd_);
    // centred over the owner, a little high
    RECT o{}, d{};
    GetWindowRect(owner_ ? owner_ : GetDesktopWindow(), &o);
    GetWindowRect(hwnd_, &d);
    int x = o.left + ((o.right - o.left) - (d.right - d.left)) / 2;
    int y = o.top + dp(60);
    SetWindowPos(hwnd_, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    ShowWindow(hwnd_, SW_SHOW);
    if (owner_) EnableWindow(owner_, FALSE);
    SetForegroundWindow(hwnd_);
    // first field gets the focus
    for (const Field& f : surface_.fields) { SetFocus(f.edit); break; }
    while (!done_) {
        if (!pump(hwnd_)) break;
    }
    if (owner_) EnableWindow(owner_, TRUE);
    DestroyWindow(hwnd_);
    g_modals.erase(std::remove(g_modals.begin(), g_modals.end(), this), g_modals.end());
    if (owner_) SetForegroundWindow(owner_);
    hwnd_ = nullptr;
    return result_;
}

void Modal::close(int result) {
    result_ = result;
    done_ = true;
    if (hwnd_) PostMessageW(hwnd_, WM_NULL, 0, 0);   // wake the loop
}

void Modal::closeAll() {
    std::vector<Modal*> copy = g_modals;
    for (Modal* m : copy) m->onClose();   // each dialog wipes its fields before it goes
}

HWND Modal::current() { return g_modals.empty() ? nullptr : g_modals.back()->hwnd_; }

void Modal::setClientHeight(int h) {
    RECT rc{0, 0, clientWidth_, h};
    AdjustWindowRectExForDpi(&rc, WS_POPUP | WS_CAPTION | WS_SYSMENU, FALSE, WS_EX_DLGMODALFRAME, dpi());
    SetWindowPos(hwnd_, nullptr, 0, 0, rc.right - rc.left, rc.bottom - rc.top, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
}

int Modal::addMessageLabel(int x, int y, int w) {
    msgLabel_ = static_cast<int>(surface_.labels.size());
    return surface_.addLabel(L" ", Role::Body, kRed, x, y, w);
}

void Modal::setMessage(const std::wstring& text) {
    if (msgLabel_ < 0) return;
    surface_.labels[static_cast<size_t>(msgLabel_)].text = text;
    RECT r = surface_.labels[static_cast<size_t>(msgLabel_)].box;
    InvalidateRect(hwnd_, &r, FALSE);
}

HWND Modal::button(int id, const std::wstring& text, BtnStyle style, int x, int y, int w, int h) {
    HWND b = makeButton(hwnd_, id, text, style);
    SetWindowPos(b, nullptr, x, y, w, h, SWP_NOZORDER | SWP_NOACTIVATE);
    return b;
}

// ---- the shuffled keypad ----------------------------------------------------------------------------------------
namespace {
const std::wstring kBack = L"back", kClear = L"clear", kSpace = L"space";
const std::wstring kPageAbc = L"abc", kPageUpper = L"ABC", kPageSym = L"123";
bool isToken(const std::wstring& s) { return !s.empty() && s[0] == 0xE000; }
}  // namespace

SecureInput::SecureInput(HWND parent, std::vector<HWND> edits, bool digits, bool always, int idBase)
    : parent_(parent), edits_(std::move(edits)), focus_(nullptr), digits_(digits), always_(always), idBase_(idBase) {
    focus_ = edits_.front();
    if (!always_) link_ = makeButton(parent_, idBase_, L"Virtual keyboard", BtnStyle::Link);
    else show();
}

SecureInput::~SecureInput() {
    // the pad belongs to its parent window, which may stay alive (the unlock view is rebuilt)
    for (HWND b : pad_) if (IsWindow(b)) DestroyWindow(b);
    if (link_ && IsWindow(link_)) DestroyWindow(link_);
}

void SecureInput::show() {
    build();
    for (HWND e : edits_) lockPhysicalKeyboard(e, true);
    if (link_) setButtonText(link_, L"Use the keyboard");
}

void SecureInput::hide() {
    for (HWND b : pad_) DestroyWindow(b);
    pad_.clear();
    keys_.clear();
    for (HWND e : edits_) lockPhysicalKeyboard(e, false);
    if (link_) setButtonText(link_, L"Virtual keyboard");
}

void SecureInput::build() {
    for (HWND b : pad_) DestroyWindow(b);
    pad_.clear();
    keys_.clear();
    auto add = [&](const std::wstring& token, const std::wstring& label, BtnStyle style) {
        int id = idBase_ + 1 + static_cast<int>(pad_.size());
        bool secretKey = !isToken(token) && token.size() == 1;   // a character key: its label is kept out of the window text
        HWND b = makeButton(parent_, id, secretKey ? std::wstring() : label, style, false);
        if (secretKey) setKeyLabel(b, token[0]);
        if (isToken(token) && token != kBack) applyFont(b, Role::Small);
        pad_.push_back(b);
        keys_.push_back(token);
    };
    if (digits_) {
        std::vector<wchar_t> d = keypad::shuffled(L"0123456789");
        size_t next = 0;
        for (int slot = 0; slot < 12; ++slot) {
            if (slot == 9) add(kClear, L"Clear", BtnStyle::Key);
            else if (slot == 11) add(kBack, L"<", BtnStyle::Key);
            else {
                std::wstring ch(1, d[next++]);
                add(ch, ch, BtnStyle::Key);
            }
        }
    } else {
        std::wstring pool = page_ == L"abc" ? keypad::kLower : (page_ == L"ABC" ? keypad::kUpper : keypad::kSymbols);
        for (wchar_t c : keypad::shuffled(pool)) add(std::wstring(1, c), std::wstring(1, c), BtnStyle::Key);
        add(kPageAbc, L"abc", page_ == L"abc" ? BtnStyle::Primary : BtnStyle::Normal);
        add(kPageUpper, L"ABC", page_ == L"ABC" ? BtnStyle::Primary : BtnStyle::Normal);
        add(kPageSym, L"123", page_ == L"123" ? BtnStyle::Primary : BtnStyle::Normal);
        add(kSpace, L"Space", BtnStyle::Normal);
        add(kBack, L"<", BtnStyle::Normal);
        add(kClear, L"Clear", BtnStyle::Normal);
    }
    if (width_ > 0) layout(originX_, originY_, width_);
}

int SecureInput::layout(int x, int y, int width) {
    originX_ = x;
    originY_ = y;
    width_ = width;
    int used = 0;
    if (link_) {
        int lw = ui::dp(130), lh = ui::dp(24);
        SetWindowPos(link_, nullptr, x + (width - lw) / 2, y, lw, lh, SWP_NOZORDER | SWP_NOACTIVATE);
        used = lh + dp(4);
    }
    if (pad_.empty()) return used;
    if (digits_) {
        int kw = dp(56), kh = dp(40), gap = dp(6);
        int total = 3 * kw + 2 * gap;
        int x0 = x + (width - total) / 2;
        for (size_t i = 0; i < pad_.size(); ++i) {
            int r = static_cast<int>(i) / 3, c = static_cast<int>(i) % 3;
            SetWindowPos(pad_[i], nullptr, x0 + c * (kw + gap), y + used + r * (kh + gap), kw, kh, SWP_NOZORDER | SWP_NOACTIVATE);
        }
        used += 4 * (kh + gap);
    } else {
        int kw = dp(32), kh = dp(30), gap = dp(3);
        int cols = 10;
        int total = cols * kw + (cols - 1) * gap;
        int x0 = x + (width - total) / 2;
        size_t keys = pad_.size() - 6;
        int rows = static_cast<int>((keys + cols - 1) / cols);
        for (size_t i = 0; i < keys; ++i) {
            int r = static_cast<int>(i) / cols, c = static_cast<int>(i) % cols;
            SetWindowPos(pad_[i], nullptr, x0 + c * (kw + gap), y + used + r * (kh + gap), kw, kh, SWP_NOZORDER | SWP_NOACTIVATE);
        }
        used += rows * (kh + gap) + dp(4);
        int widths[6] = {dp(46), dp(46), dp(46), dp(84), dp(40), dp(54)};
        int sum = 5 * dp(4);
        for (int wv : widths) sum += wv;
        int bx = x + (width - sum) / 2;
        for (int i = 0; i < 6; ++i) {
            SetWindowPos(pad_[keys + static_cast<size_t>(i)], nullptr, bx, y + used, widths[i], dp(28), SWP_NOZORDER | SWP_NOACTIVATE);
            bx += widths[i] + dp(4);
        }
        used += dp(28) + dp(6);
    }
    return used;
}

bool SecureInput::onCommand(int id) {
    if (link_ && id == idBase_) {
        if (visible()) hide(); else show();
        if (onLayoutChanged) onLayoutChanged();
        return true;
    }
    int index = id - idBase_ - 1;
    if (index < 0 || index >= static_cast<int>(pad_.size())) return false;
    press(static_cast<size_t>(index));
    return true;
}

void SecureInput::type(const std::wstring& s) {
    SendMessageW(focus_, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
    SendMessageW(focus_, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(s.c_str()));
}

void SecureInput::backspace() {
    int n = GetWindowTextLengthW(focus_);
    if (n <= 0) return;
    SendMessageW(focus_, EM_SETSEL, static_cast<WPARAM>(n - 1), static_cast<LPARAM>(n));
    SendMessageW(focus_, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(L""));
}

void SecureInput::clearField() { wipeEdit(focus_); }

void SecureInput::press(size_t index) {
    const std::wstring token = keys_[index];
    if (token == kBack) backspace();
    else if (token == kClear) clearField();
    else if (token == kSpace) type(L" ");
    else if (token == kPageAbc || token == kPageUpper || token == kPageSym) {
        page_ = token == kPageAbc ? L"abc" : (token == kPageUpper ? L"ABC" : L"123");
        build();       // a new page is a new shuffle
        if (onLayoutChanged) onLayoutChanged();
    } else {
        type(token);
        if (digits_) shuffleKeys();   // the next digit sits somewhere else
    }
    SetFocus(focus_);
}

void SecureInput::shuffleKeys() {
    std::vector<wchar_t> d = keypad::shuffled(L"0123456789");
    size_t next = 0;
    for (size_t i = 0; i < pad_.size(); ++i) {
        if (isToken(keys_[i]) || keys_[i] == L"<") continue;
        std::wstring ch(1, d[next++]);
        keys_[i] = ch;
        setKeyLabel(pad_[i], ch[0]);
    }
}

}  // namespace b2::ui
