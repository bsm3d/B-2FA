// B-2FA, a brake on guessing at the unlock screen (master password and PIN).
//
// A few wrong tries are free; after that, each new try is only possible a fixed time after the last wrong one
// (30 s by default). The count and the time are kept in a small file, so closing and reopening the program does not
// give the tries back. A correct password resets it.
//
// This stops a person at the keyboard (a colleague at an unattended PC). It does not stop a program that has the
// vault file and tries passwords offline: against that, only the strength of the master password counts.
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
