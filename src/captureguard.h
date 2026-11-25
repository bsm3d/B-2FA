// B-2FA
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.1
// Fonction du fichier : Declares CaptureGuard, which excludes B-2FA windows from screen capture on Windows 10 build 19041 and later using a shield window.

// Windows 10 build 19041 and later: WDA_EXCLUDEFROMCAPTURE hides the window from captures, and a shield window behind it shows "No screen capture allowed".
// Not stopped: a photo of the screen, or a capture by a process with rights to read other processes.
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
