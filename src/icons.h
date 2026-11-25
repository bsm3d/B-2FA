// B-2FA
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.1
// Fonction du fichier : Declares IconStore, which finds a local 2FAS icon for each account and falls back to a letter tile when none exists.

// Local 2FAS icon pack only, never the network: `icons\` next to B-2FA.exe, or %APPDATA%\BSM\B-2FA\icons first. No pack: a letter tile.
// Logo lookup as the 2FAS apps do: icon collection id from the backup, then service type id, then exact name for hand-typed accounts.
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <windows.h>

#include <filesystem>
#include <map>
#include <optional>
#include <string>

#include "json.h"

namespace b2 {

class IconStore {
public:
    explicit IconStore(std::filesystem::path folder = {});   // empty: icons\ in the data folder, else icons\ next to the program
    ~IconStore();
    IconStore(const IconStore&) = delete;
    IconStore& operator=(const IconStore&) = delete;

    bool available() const;
    // Id of the PNG to show for this account, or nothing (then a letter tile is drawn).
    std::optional<std::string> iconId(const Json& service);
    // A pre-multiplied 32 bit bitmap of px x px for this account, or nullptr. Owned by the store.
    HBITMAP image(const Json& service, int px);
    void clearImages();   // after a DPI change

private:
    std::filesystem::path folder_;
    bool loaded_ = false;
    struct Collection { std::string light, dark; };
    std::map<std::string, Collection> collections_;   // collection id -> icon ids
    std::map<std::string, std::string> byService_;    // service type id -> collection id
    std::map<std::string, std::string> byName_;       // lower-case name or issuer -> collection id
    std::map<std::pair<std::string, int>, HBITMAP> images_;

    void load();
    HBITMAP loadPng(const std::string& iconId, int px);
};

// "Ada Lovelace" -> "AL", "github" -> "GI"
std::string initials(const std::string& name);

}  // namespace b2
