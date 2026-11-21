// B-2FA, small user settings (a JSON file next to the vault). Nothing secret goes in here.
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <filesystem>

namespace b2 {

class Settings {
public:
    explicit Settings(std::filesystem::path path = {});   // empty: settings.json in the data folder

    // Use the on-screen shuffled keypad to enter the PIN (default: yes).
    bool secureKeypad() const { return secureKeypad_; }
    void setSecureKeypad(bool on);

private:
    std::filesystem::path path_;
    bool secureKeypad_ = true;
    void load();
    void save() const;
};

}  // namespace b2
