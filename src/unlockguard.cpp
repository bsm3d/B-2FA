// B-2FA
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.1
// Fonction du fichier : Implements the unlock brake that keeps failed tries and waiting time in unlock-guard.json between program runs.

// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "unlockguard.h"

#include <algorithm>

#include "fileio.h"
#include "json.h"
#include "paths.h"
#include "util.h"

namespace b2 {

int64_t (*UnlockGuard::clock)() = &nowMs;

UnlockGuard::UnlockGuard(std::filesystem::path path, int freeAttempts, int delaySeconds)
    : path_(path.empty() ? paths::dataDir() / L"unlock-guard.json" : std::move(path)),
      free_(std::clamp(freeAttempts, 1, 10)),
      delay_(std::clamp(delaySeconds, 5, 3600)) {
    load();
}

void UnlockGuard::load() {
    failures_ = 0;
    lastMs_ = 0;
    try {
        std::string text;
        readFile(path_, text, 4096);
        Json doc = Json::parse(text);
        int64_t f = 0, t = 0;
        const Json* jf = doc.get("failures");
        const Json* jt = doc.get("last_failure_ms");
        if (jf && jt && jf->toInt64(f) && jt->toInt64(t) && f >= 0 && f < 1000000) {
            failures_ = static_cast<int>(f);
            lastMs_ = t;
        }
    } catch (const std::exception&) {   // no file, or a damaged one: a clean start
    }
}

void UnlockGuard::save() const {
    Json doc = Json::object();
    doc.set("failures", Json(failures_));
    doc.set("last_failure_ms", Json(lastMs_));
    std::filesystem::path tmp = path_;
    tmp += L".tmp";
    try {
        writeFileSynced(tmp, doc.dump());
        replaceFile(tmp, path_);
    } catch (const std::exception&) {
        removeFile(tmp);   // the brake still works for this run, only its memory is lost
    }
}

int UnlockGuard::waitSeconds() {
    if (failures_ < free_) return 0;
    int64_t now = clock();
    if (lastMs_ > now) lastMs_ = now;   // a clock set back must not freeze the wait for hours
    int64_t remaining = static_cast<int64_t>(delay_) * 1000 - (now - lastMs_);
    return remaining <= 0 ? 0 : static_cast<int>((remaining + 999) / 1000);
}

void UnlockGuard::failure() {
    if (failures_ < 1000000) ++failures_;
    lastMs_ = clock();
    save();
}

void UnlockGuard::success() {
    failures_ = 0;
    lastMs_ = 0;
    removeFile(path_);
}

}  // namespace b2
