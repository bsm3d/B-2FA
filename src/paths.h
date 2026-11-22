// B-2FA, where the program keeps its data: one folder, %APPDATA%\BSM\B-2FA.
// The B2FA_HOME environment variable overrides it (tests, portable use).
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <filesystem>

namespace b2::paths {

std::filesystem::path dataDir();      // created if missing
std::filesystem::path vaultPath();
std::filesystem::path backupsDir();   // created if missing
std::filesystem::path iconsDir();     // not created: a pack the user put in the data folder (it wins)
std::filesystem::path installedIconsDir();   // icons\ next to the program: the pack the installer or the zip brings

}  // namespace b2::paths
