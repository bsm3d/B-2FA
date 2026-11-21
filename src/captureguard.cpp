// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "captureguard.h"

#include <dwmapi.h>

namespace b2 {

namespace {
constexpr DWORD kWdaExcludeFromCapture = 0x11;
constexpr DWORD kMinBuild = 19041;
const wchar_t kShieldClass[] = L"B2FAShield";
const wchar_t kMessage[] = L"No screen capture allowed";
const wchar_t kSubMessage[] = L"B-2FA hides its window from screenshots, recordings and screen sharing.";

DWORD windowsBuild() {
    using Fn = LONG(WINAPI*)(OSVERSIONINFOW*);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto fn = ntdll ? reinterpret_cast<Fn>(GetProcAddress(ntdll, "RtlGetVersion")) : nullptr;
    OSVERSIONINFOW vi{};
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (fn && fn(&vi) == 0) return vi.dwBuildNumber;
    return 0;
}

bool registerShieldClass(WNDPROC proc) {
    static bool done = false;
    if (done) return true;
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = proc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    wc.lpszClassName = kShieldClass;
    done = RegisterClassExW(&wc) != 0;
    return done;
}
}  // namespace

bool CaptureGuard::supported() { return windowsBuild() >= kMinBuild; }

bool CaptureGuard::setExcluded(HWND window, bool on) {
    return supported() && SetWindowDisplayAffinity(window, on ? kWdaExcludeFromCapture : WDA_NONE) != 0;
}

bool CaptureGuard::isExcluded(HWND window) {
    DWORD value = 0;
    return supported() && GetWindowDisplayAffinity(window, &value) && value == kWdaExcludeFromCapture;
}

bool CaptureGuard::enable() {
    if (!supported() || !setExcluded(main_, true)) return false;
    enabled_ = true;
    if (!shield_ && registerShieldClass(&CaptureGuard::shieldProc)) {
        shield_ = CreateWindowExW(WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW, kShieldClass, L"", WS_POPUP, 0, 0, 10, 10, nullptr,
                                  nullptr, GetModuleHandleW(nullptr), nullptr);
        if (shield_) SetWindowLongPtrW(shield_, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
    }
    sync();
    return true;
}

void CaptureGuard::disable() {
    enabled_ = false;
    if (IsWindow(main_)) setExcluded(main_, false);
    if (shield_) {
        DestroyWindow(shield_);
        shield_ = nullptr;
    }
}

void CaptureGuard::protect(HWND dialog) {
    if (enabled_) setExcluded(dialog, true);
}

void CaptureGuard::onPosChanged() {
    if (!enabled_ || moving_) return;
    sync();
}

void CaptureGuard::onEnterSizeMove() {
    moving_ = true;
    // The shield follows one frame late, so a black strip would show behind a moving window.
    if (shield_) ShowWindow(shield_, SW_HIDE);
}

void CaptureGuard::onExitSizeMove() {
    moving_ = false;
    if (enabled_) sync();
}

void CaptureGuard::onDpiChanged() { if (enabled_) sync(); }

void CaptureGuard::sync() {
    if (!enabled_ || !shield_ || !IsWindow(main_)) return;
    if (!IsWindowVisible(main_) || IsIconic(main_)) {
        ShowWindow(shield_, SW_HIDE);
        return;
    }
    // The part of the window the user really sees: Windows 10 gives windows invisible resize borders
    // that the window rectangle counts, so a shield cut to it would show as a black rim. 2 px smaller.
    RECT r{};
    if (FAILED(DwmGetWindowAttribute(main_, DWMWA_EXTENDED_FRAME_BOUNDS, &r, sizeof(r)))) GetWindowRect(main_, &r);
    const int m = 2;
    SetWindowPos(shield_, main_, r.left + m, r.top + m, (r.right - r.left) - 2 * m, (r.bottom - r.top) - 2 * m,
                 SWP_NOACTIVATE | SWP_SHOWWINDOW);   // inserted right after (below) the main window
}

void CaptureGuard::paintShield(HWND h) {
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(h, &ps);
    RECT rc;
    GetClientRect(h, &rc);
    FillRect(dc, &rc, static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
    UINT dpi = GetDpiForWindow(h);
    if (!dpi) dpi = 96;
    HFONT big = CreateFontW(-MulDiv(22, dpi, 72), 0, 0, 0, FW_LIGHT, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0,
                            CLEARTYPE_QUALITY, 0, L"Segoe UI Light");
    HFONT smallFont = CreateFontW(-MulDiv(9, dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0,
                              CLEARTYPE_QUALITY, 0, L"Segoe UI");
    SetBkMode(dc, TRANSPARENT);
    int cy = (rc.bottom - rc.top) / 2;
    HGDIOBJ old = SelectObject(dc, big);
    RECT a{rc.left + 20, cy - MulDiv(60, dpi, 96), rc.right - 20, cy};
    SetTextColor(dc, RGB(255, 255, 255));
    DrawTextW(dc, kMessage, -1, &a, DT_CENTER | DT_BOTTOM | DT_SINGLELINE);
    SelectObject(dc, smallFont);
    RECT b{rc.left + 40, cy + MulDiv(12, dpi, 96), rc.right - 40, cy + MulDiv(80, dpi, 96)};
    SetTextColor(dc, RGB(225, 6, 0));
    DrawTextW(dc, kSubMessage, -1, &b, DT_CENTER | DT_WORDBREAK);
    SelectObject(dc, old);
    DeleteObject(big);
    DeleteObject(smallFont);
    EndPaint(h, &ps);
}

LRESULT CALLBACK CaptureGuard::shieldProc(HWND h, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
        case WM_PAINT: paintShield(h); return 0;
        case WM_ERASEBKGND: return 1;
        case WM_MOUSEACTIVATE: return MA_NOACTIVATE;
    }
    return DefWindowProcW(h, msg, w, l);
}

}  // namespace b2
