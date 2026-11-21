// B-2FA, read and write 2FAS backup files (.2fas).
//
// Format, taken from the 2FAS Android and iOS sources:
//  - a JSON object with services, groups, updatedAt, schemaVersion, appOrigin...
//  - plain backup: "services" holds the list.
//  - encrypted backup: "services" is empty, "servicesEncrypted" and "reference" are strings
//    "base64(ciphertext+tag):base64(salt):base64(iv)". Key = PBKDF2-HMAC-SHA256(password, salt,
//    10000 iterations, 32 bytes). Cipher = AES-256-GCM, no associated data. The salt is 256 bytes,
//    shared by both fields. "reference" decrypts to a fixed string, which proves the password.
//
// The 10 000 iterations are imposed by the format: a weak point for short passwords, which is why
// B-2FA only uses it for the manual export, with a long password.
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
constexpr uint64_t kMaxFileBytes = 100ull * 1024 * 1024;
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
