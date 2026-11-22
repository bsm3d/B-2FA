// B-2FA, small user settings (a JSON file next to the vault). Nothing secret goes in here.
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <filesystem>
#include <string>

namespace b2 {

class Settings {
public:
    explicit Settings(std::filesystem::path path = {});   // empty: settings.json in the data folder

    // Always use the on-screen shuffled keypad to enter the PIN, and ignore the physical keyboard there
    // (default: no, the PIN is typed on the keyboard and the keypad is a "Virtual keyboard" link away).
    bool secureKeypad() const { return secureKeypad_; }
    void setSecureKeypad(bool on);

    // The brake on guessing at the unlock screen: free tries, then this many seconds between tries.
    // Edit settings.json to change them (1 to 10 tries, 5 to 3600 seconds).
    int unlockFreeAttempts() const { return freeAttempts_; }
    int unlockDelaySeconds() const { return delaySeconds_; }

    // The id of the device key of the vault for which a recovery export was made (empty: none yet).
    const std::string& recoveryExportedFor() const { return recoveryFor_; }
    void setRecoveryExportedFor(const std::string& id);

private:
    std::filesystem::path path_;
    bool secureKeypad_ = false;
    std::string recoveryFor_;
    int freeAttempts_ = 3, delaySeconds_ = 30;
    void load();
    void save() const;
};

}  // namespace b2
