// B-2FA
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.1
// Fonction du fichier : Declares UnlockGuard, the brake on password and PIN guessing: a few free tries, then a fixed delay between tries.

// Free wrong tries, then one try per fixed delay (30 s by default), kept in a file so restarts do not give tries back. A correct password resets it.
// Stops a person at the keyboard only: a program holding the vault file and guessing offline is stopped by the master password alone.
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <filesystem>

namespace b2 {

class UnlockGuard {
public:
    // empty path: unlock-guard.json in the data folder
    explicit UnlockGuard(std::filesystem::path path = {}, int freeAttempts = 3, int delaySeconds = 30);

    int freeAttempts() const { return free_; }
    int delaySeconds() const { return delay_; }
    int failures() const { return failures_; }
    // Whole seconds to wait before the next try is allowed (0: allowed now).
    int waitSeconds();
    // Tries left before the waiting starts (0 once it has).
    int triesBeforeWait() const { return failures_ >= free_ ? 0 : free_ - failures_; }
    void failure();   // a wrong password or PIN
    void success();   // a right one: everything is forgiven

    // the clock, replaceable by the tests (milliseconds since 1970)
    static int64_t (*clock)();

private:
    std::filesystem::path path_;
    int free_, delay_;
    int failures_ = 0;
    int64_t lastMs_ = 0;
    void load();
    void save() const;
};

}  // namespace b2
