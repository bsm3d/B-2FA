// B-2FA
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.1
// Fonction du fichier : Implements the data folder lookup: B2FA_HOME override, else the roaming AppData BSM B-2FA folder, created on demand.

// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "paths.h"

#include <windows.h>
#include <knownfolders.h>
#include <shlobj.h>

#include <system_error>

namespace b2::paths {

namespace fs = std::filesystem;

fs::path dataDir() {
    fs::path path;
    wchar_t env[MAX_PATH * 2];
    DWORD n = GetEnvironmentVariableW(L"B2FA_HOME", env, static_cast<DWORD>(std::size(env)));
    if (n > 0 && n < std::size(env)) {
        path = env;
    } else {
        PWSTR roaming = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &roaming)) && roaming) {
            path = fs::path(roaming) / L"BSM" / L"B-2FA";
            CoTaskMemFree(roaming);
        } else {
            path = fs::path(L".") / L"B-2FA-data";
        }
    }
    std::error_code ec;
    fs::create_directories(path, ec);
    return path;
}

fs::path vaultPath() { return dataDir() / L"vault.b2fa"; }

fs::path backupsDir() {
    fs::path p = dataDir() / L"backups";
    std::error_code ec;
    fs::create_directories(p, ec);
    return p;
}

fs::path iconsDir() { return dataDir() / L"icons"; }

fs::path installedIconsDir() {
    wchar_t buf[MAX_PATH * 2];
    DWORD n = GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(std::size(buf)));
    if (n == 0 || n >= std::size(buf)) return {};
    return fs::path(buf).parent_path() / L"icons";
}

}  // namespace b2::paths
