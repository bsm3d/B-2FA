// B-2FA, the shuffle behind the on-screen keypads. A separate header so the tests can check it.
//
// A keylogger records the keys you press. With an on-screen keypad the PIN or password is entered
// with the mouse, on keys in a random order (a new order every time the pad opens, and after every
// digit for the PIN pad). The logger sees mouse clicks at screen positions, and because the window is
// excluded from screen capture it cannot learn which key sits where.
//
// This is NOT what KeyScrambler does: that product installs a keyboard driver that encrypts the
// keystrokes inside the system, which a normal program cannot do. This protects against loggers that
// only record the keyboard (hooks, hardware keyloggers). It does not protect against malware that
// reads the window by other means, reads the memory of the process, or reads the text of the field.
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

#include "util.h"

namespace b2::keypad {

inline const std::wstring kLower = L"abcdefghijklmnopqrstuvwxyz";
inline const std::wstring kUpper = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
inline const std::wstring kSymbols = L"0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

// A number in [0, n) with no bias, from the system random generator.
inline size_t randomBelow(size_t n) {
    if (n <= 1) return 0;
    const uint64_t limit = UINT64_MAX - (UINT64_MAX % n);
    while (true) {
        Bytes b = randomBytes(8);
        uint64_t v = 0;
        for (uint8_t x : b) v = (v << 8) | x;
        if (v < limit) return static_cast<size_t>(v % n);
    }
}

// Fisher-Yates with that generator.
inline std::vector<wchar_t> shuffled(const std::wstring& chars) {
    std::vector<wchar_t> out(chars.begin(), chars.end());
    for (size_t i = out.size(); i > 1; --i) std::swap(out[i - 1], out[randomBelow(i)]);
    return out;
}

}  // namespace b2::keypad
