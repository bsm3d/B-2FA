// B-2FA, screen capture protection (Windows 10 build 19041 and later).
//
// The window is excluded from every capture the system makes (Print Screen, Snipping Tool, screen
// sharing, recorders, Windows Recall) with SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE).
// Windows then leaves the window out of the picture, which would only show whatever is behind it.
// So a "shield" window sits exactly behind the real one: you never see it (the real window covers
// it), but a capture shows it instead, with the text "No screen capture allowed".
//
// Limits: a photo of the screen, or a capture made by something running in the same session with
// enough rights to read another process, is not stopped by this.
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <windows.h>

namespace b2 {

class CaptureGuard {
public:
    static bool supported();
    static bool isExcluded(HWND window);
    static bool setExcluded(HWND window, bool on);

    explicit CaptureGuard(HWND mainWindow) : main_(mainWindow) {}
    ~CaptureGuard() { disable(); }
    CaptureGuard(const CaptureGuard&) = delete;
    CaptureGuard& operator=(const CaptureGuard&) = delete;

    bool enable();
    void disable();
    bool enabled() const { return enabled_; }
    void protect(HWND dialog);   // dialogs can show a secret: keep them out of captures too

    // Call from the main window procedure.
    void onPosChanged();         // the window moved, was resized, shown or hidden
    void onEnterSizeMove();      // the user starts dragging: hide the shield, it would lag behind
    void onExitSizeMove();
    void onDpiChanged();

private:
    HWND main_;
    HWND shield_ = nullptr;
    bool enabled_ = false;
    bool moving_ = false;

    void sync();
    static LRESULT CALLBACK shieldProc(HWND, UINT, WPARAM, LPARAM);
    static void paintShield(HWND);
};

}  // namespace b2
