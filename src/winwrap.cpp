// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "winwrap.h"

#include <windows.h>
#include <dpapi.h>

namespace b2 {

namespace {

DATA_BLOB blobOf(const Bytes& b) {
    static uint8_t kEmpty = 0;
    DATA_BLOB d;
    d.cbData = static_cast<DWORD>(b.size());
    d.pbData = b.empty() ? &kEmpty : const_cast<uint8_t*>(b.data());
    return d;
}

Bytes takeBlob(DATA_BLOB& out) {
    Bytes r(out.pbData, out.pbData + out.cbData);
    secureZero(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return r;
}

}  // namespace

bool dpapiProtect(const Bytes& data, const Bytes& entropy, const wchar_t* description, Bytes& wrapped, unsigned long& error) {
    DATA_BLOB in = blobOf(data), ent = blobOf(entropy), out{};
    if (!CryptProtectData(&in, description, &ent, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        error = GetLastError();
        return false;
    }
    wrapped = takeBlob(out);
    return true;
}

bool dpapiUnprotect(const Bytes& wrapped, const Bytes& entropy, Bytes& data) {
    DATA_BLOB in = blobOf(wrapped), ent = blobOf(entropy), out{};
    if (!CryptUnprotectData(&in, nullptr, &ent, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) return false;
    data = takeBlob(out);
    return true;
}

}  // namespace b2
