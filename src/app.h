// B-2FA
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.1
// Fonction du fichier : Public entry declaration runApp that runs the B-2FA main window until it closes and returns the exit code.

// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <windows.h>

namespace b2 {

// Runs the program until the window closes. Returns the process exit code.
int runApp(HINSTANCE instance, int showCommand);

}  // namespace b2
