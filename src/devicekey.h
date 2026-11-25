// B-2FA
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.1
// Fonction du fichier : Declares the device key API: a random secret wrapped by DPAPI in device.b2fa, combined with the master password key.

// A random secret wrapped by DPAPI in `device.b2fa`, mixed into the vault key: a copied vault file does not open on another PC or account, even with the right password.
// It does not stop a program running as the user, which can unwrap the secret like B-2FA does.
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
