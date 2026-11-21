// B-2FA, quick unlock with a short PIN, on top of the strong master password.
//
// A 4 digit PIN has only 10 000 values, so it can never protect a file that someone can copy:
// anybody could try every PIN offline in minutes. This module therefore does NOT protect the
// vault with the PIN. The vault stays protected by the master password. The PIN only unlocks a
// small side file that holds the master password wrapped by Windows DPAPI:
//
//  - DPAPI ties the file to this Windows account on this PC (a copy on another machine or another
//    account is useless), and the PIN (stretched with scrypt) is added as DPAPI entropy.
//  - Attempts are counted before each try and the side file is deleted after kMaxAttempts wrong
//    PINs, after which only the master password works.
//
// What it does not stop: malware already running as you, which can read the side file and try the
// PINs itself. The same malware could also read the screen and the keyboard, so the master password
// remains the real protection. The PIN is a convenience for an unattended PC, not a second lock.
//
// The file format is the one of the Python edition: a PIN set by either opens in both.
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <filesystem>
#include <stdexcept>

#include "util.h"

namespace b2 {

constexpr int kPinMaxAttempts = 5;
constexpr size_t kPinMin = 4, kPinMax = 8;

struct PinError : std::runtime_error {
    using std::runtime_error::runtime_error;
};
struct PinDisabled : PinError {   // no PIN is set (or it was wiped): use the master password
    using PinError::PinError;
};
struct WrongPin : PinError {
    explicit WrongPin(int left);
    int attemptsLeft;
};

class PinStore {
public:
    explicit PinStore(std::filesystem::path path = {});   // empty: pin.b2fa in the data folder
    bool enabled() const;
    void enable(const Secret& pin, const Secret& masterPassword);
    Secret unlock(const Secret& pin);   // the master password for a correct PIN; counts every attempt
    void disable();
    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

void checkPinFormat(const Secret& pin);   // 4 to 8 ASCII digits, or PinError

}  // namespace b2
