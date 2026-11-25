// B-2FA
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.1
// Fonction du fichier : Declares the 2FAS backup format API: plain and encrypted read and write, schema version and backup error types.

// 2FAS format, from the Android and iOS sources: plain files hold services; encrypted ones leave services empty and use base64 fields with a shared 256-byte salt.
// Key is PBKDF2-HMAC-SHA256 with 10 000 iterations (imposed by the format, weak for short passwords), AES-256-GCM, no associated data.
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <filesystem>
#include <stdexcept>
#include <vector>

#include "json.h"
#include "util.h"

namespace b2::twofas {

struct BackupError : std::runtime_error {
    using std::runtime_error::runtime_error;
};
struct WrongPassword : BackupError {
    WrongPassword() : BackupError("Wrong password") {}
};

constexpr int kSchemaVersion = 4;
constexpr uint32_t kPbkdf2Iterations = 10000;
constexpr size_t kSaltBytes = 256;
constexpr size_t kIvBytes = 12;
constexpr uint64_t kMaxFileBytes = 16ull * 1024 * 1024;   // a real backup of thousands of accounts is far smaller
constexpr size_t kMaxServices = 10000;

// Load a backup file (still encrypted if it was exported with a password). Throws BackupError.
Json readBackup(const std::filesystem::path& path);
bool isEncrypted(const Json& content);
// The backup with its services in clear. Throws WrongPassword or BackupError.
Json decryptBackup(const Json& content, const Secret& password);
Json buildBackup(const std::vector<Json>& services, const std::vector<Json>& groups, const Secret& password);
void writeBackup(const std::filesystem::path& path, const std::vector<Json>& services,
                 const std::vector<Json>& groups, const Secret& password);

}  // namespace b2::twofas
