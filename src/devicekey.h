// B-2FA, the device key: a random secret wrapped by Windows (DPAPI) and kept in `device.b2fa` next to the vault.
//
// A vault bound to this PC mixes this secret into its encryption key, so the vault file alone does not open:
// not on another PC, not for another Windows account, not even with the right master password. It protects a
// stolen or copied file (a disk, a backup, a cloud copy). It does not stop a program that runs as you, which
// can unwrap the secret like B-2FA does.
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <filesystem>
#include <stdexcept>
#include <string>

#include "util.h"

namespace b2::devicekey {

struct Error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

constexpr size_t kSecretBytes = 32;

std::filesystem::path pathFor(const std::filesystem::path& vaultPath);   // device.b2fa in the vault's folder
bool exists(const std::filesystem::path& file);
Bytes create(const std::filesystem::path& file);                          // writes it, returns the secret. Throws Error
Bytes load(const std::filesystem::path& file);                            // throws Error with a message fit for the user
std::string idOf(const Bytes& secret);                                    // a short public id (not secret) of this key
Bytes combine(const Bytes& passwordKey, const Bytes& deviceSecret);       // the key the vault is encrypted with

}  // namespace b2::devicekey
