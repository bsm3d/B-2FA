// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "winclip.h"

#include <windows.h>

#include <cstring>

#include "util.h"

namespace b2::clip {

namespace {

bool openClipboard() {
    for (int i = 0; i < 20; ++i) {
        if (OpenClipboard(nullptr)) return true;
        Sleep(20);
    }
    return false;
}

struct Closer {
    ~Closer() { CloseClipboard(); }
};

bool put(UINT format, const void* data, size_t bytes) {
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!h) return false;
    void* p = GlobalLock(h);
    if (!p) {
        GlobalFree(h);
        return false;
    }
    std::memcpy(p, data, bytes);
    GlobalUnlock(h);
    if (!SetClipboardData(format, h)) {
        GlobalFree(h);
        return false;
    }
    return true;
}

}  // namespace

bool setText(const std::string& utf8) {
    std::wstring w = widen(utf8);
    if (!openClipboard()) return false;
    Closer closer;
    EmptyClipboard();
    bool ok = put(CF_UNICODETEXT, w.c_str(), (w.size() + 1) * sizeof(wchar_t));
    secureZero(w.data(), w.size() * sizeof(wchar_t));
    if (!ok) return false;
    const wchar_t* optOut[] = {L"ExcludeClipboardContentFromMonitorProcessing", L"CanIncludeInClipboardHistory",
                               L"CanUploadToCloudClipboard"};
    DWORD zero = 0;
    for (const wchar_t* name : optOut) {
        UINT fmt = RegisterClipboardFormatW(name);
        if (fmt) put(fmt, &zero, sizeof(zero));
    }
    return true;
}

int getText(std::string& utf8) {
    utf8.clear();
    if (!openClipboard()) return -1;
    Closer closer;
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    if (!h) return 0;
    const wchar_t* p = static_cast<const wchar_t*>(GlobalLock(h));
    if (!p) return 0;
    utf8 = narrow(p);
    GlobalUnlock(h);
    return 1;
}

bool clear() {
    if (!openClipboard()) return false;
    Closer closer;
    return EmptyClipboard() != 0;
}

}  // namespace b2::clip
