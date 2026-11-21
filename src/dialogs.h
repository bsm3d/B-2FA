// B-2FA, the dialogs: password or PIN entry, add or edit an account, About.
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <windows.h>

#include <string>

#include "json.h"
#include "util.h"

namespace b2 {

// A password (or PIN) prompt. False if cancelled. `confirm` asks twice; `digitsOnly` is for a PIN, with the
// shuffled on-screen keypad when `secureKeypad` is on; otherwise a "Virtual keyboard" link shows a full one.
bool askPassword(HWND owner, const std::wstring& title, const std::wstring& prompt, Secret& out, bool confirm = false,
                 size_t minLen = 0, bool digitsOnly = false, bool secureKeypad = true);

// Add (existing == nullptr) or edit an account. On OK `result` is the new or edited service.
bool editAccount(HWND owner, const Json* existing, Json& result);

void showAbout(HWND owner);

}  // namespace b2
