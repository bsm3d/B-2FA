// B-2FA, service logos from a local copy of the 2FAS icon pack. Never touches the network.
//
// The pack is the `icons` folder and `services.json` of the 2FAS Android app (github.com/twofasapp). The
// installer and the portable zip bring it in `icons\` next to B-2FA.exe; a pack in
// %APPDATA%\BSM\B-2FA\icons (tools\fetch_icons.ps1 puts one there) is used first. Without any pack the
// app simply draws a letter tile.
//
// An account finds its logo like the 2FAS apps do: through the icon collection id stored in the
// backup, then through its service type id, then (for accounts typed by hand) by an exact name match.
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
