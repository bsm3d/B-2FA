// B-2FA, the main window: unlock screen, account list, and every action.
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <windows.h>

namespace b2 {

// Runs the program until the window closes. Returns the process exit code.
int runApp(HINSTANCE instance, int showCommand);

}  // namespace b2
