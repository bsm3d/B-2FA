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
        const Json* r = doc.get("recovery_exported_for");
        if (r && r->isString() && r->asString().size() <= 64) recoveryFor_ = r->asString();
        int64_t n = 0;
        if (const Json* a = doc.get("unlock_free_attempts"); a && a->toInt64(n) && n >= 1 && n <= 10) freeAttempts_ = static_cast<int>(n);
        if (const Json* d = doc.get("unlock_delay_seconds"); d && d->toInt64(n) && n >= 5 && n <= 3600) delaySeconds_ = static_cast<int>(n);
    } catch (const std::exception&) {
    }
}

void Settings::save() const {
    Json doc = Json::object();
    doc.set("secure_keypad", Json(secureKeypad_));
    doc.set("recovery_exported_for", Json(recoveryFor_));
    doc.set("unlock_free_attempts", Json(freeAttempts_));
    doc.set("unlock_delay_seconds", Json(delaySeconds_));
    std::filesystem::path tmp = path_;
    tmp += L".tmp";
    try {
        writeFileSynced(tmp, doc.dump());
        replaceFile(tmp, path_);
    } catch (const std::exception&) {
        removeFile(tmp);   // a setting that cannot be saved must not stop the app
    }
}

void Settings::setRecoveryExportedFor(const std::string& id) {
    recoveryFor_ = id;
    save();
}

void Settings::setSecureKeypad(bool on) {
    secureKeypad_ = on;
    save();
}

}  // namespace b2
