// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "settings.h"

#include "fileio.h"
#include "json.h"
#include "paths.h"

namespace b2 {

Settings::Settings(std::filesystem::path path) : path_(path.empty() ? paths::dataDir() / L"settings.json" : std::move(path)) {
    load();
}

void Settings::load() {
    try {
        std::string text;
        readFile(path_, text, 64 * 1024);
        Json doc = Json::parse(text);
        const Json* v = doc.get("secure_keypad");
        if (v && v->isBool()) secureKeypad_ = v->asBool();   // a wrong type is ignored, not trusted
    } catch (const std::exception&) {
    }
}

void Settings::save() const {
    Json doc = Json::object();
    doc.set("secure_keypad", Json(secureKeypad_));
    std::filesystem::path tmp = path_;
    tmp += L".tmp";
    try {
        writeFileSynced(tmp, doc.dump());
        replaceFile(tmp, path_);
    } catch (const std::exception&) {
        removeFile(tmp);   // a setting that cannot be saved must not stop the app
    }
}

void Settings::setSecureKeypad(bool on) {
    secureKeypad_ = on;
    save();
}

}  // namespace b2
