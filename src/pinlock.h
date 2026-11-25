// B-2FA
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.1
// Fonction du fichier : Declares PinStore, the PIN quick unlock that holds the master password in a side file, not as a second vault lock.

// A 4 digit PIN has only 10 000 values, so it never protects the vault: the PIN only unlocks a side file holding the master password, wrapped by DPAPI.
// Wrong PINs are counted and the side file is deleted after kMaxAttempts. A program running as the user can still guess offline: scrypt (512 MiB) only slows it.
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <filesystem>
#include <stdexcept>

#include "util.h"

namespace b2 {

constexpr int kPinMaxAttempts = 5;
constexpr size_t kPinMin = 6, kPinMax = 10;

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

    // scrypt cost of the PIN key: 512 MiB. Lowered by the tests only.
    static uint64_t kdfN;

private:
    std::filesystem::path path_;
};

// 6 to 10 ASCII digits, or PinError
void checkPinFormat(const Secret& pin);

}  // namespace b2
