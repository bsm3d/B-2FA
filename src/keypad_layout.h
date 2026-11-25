// B-2FA
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.1
// Fonction du fichier : Header with the random key shuffle for on-screen keypads, defeating keyloggers that only record clicks.

// Shuffled on-screen keypads: a new order each time the pad opens and after each PIN digit, so a click logger learns no key positions.
// Not KeyScrambler: no keyboard driver here. It does not stop malware that reads the window, the process memory or the field text.
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
