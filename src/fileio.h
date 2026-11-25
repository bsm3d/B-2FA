// B-2FA
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.1
// Fonction du fichier : Declares the file helpers (IoError, FileSig change signature, readFile, synced writes, atomic replace) used by vault code.

// B-2FA, file helpers: durable writes, atomic replacement, a cheap "did someone change it" signature.
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>

namespace b2 {

struct IoError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct FileSig {
    bool valid = false;
    uint64_t mtime = 0;
    uint64_t size = 0;
    bool operator==(const FileSig& o) const { return valid == o.valid && mtime == o.mtime && size == o.size; }
    bool operator!=(const FileSig& o) const { return !(*this == o); }
};

// Whole file into `out`. Throws IoError if it cannot be read or is bigger than maxBytes.
void readFile(const std::filesystem::path& path, std::string& out, uint64_t maxBytes = 256u * 1024 * 1024);
// Write and flush to disk (FlushFileBuffers). Throws IoError.
void writeFileSynced(const std::filesystem::path& path, std::string_view data);
// Replace dst by src in one step. Throws IoError.
void replaceFile(const std::filesystem::path& src, const std::filesystem::path& dst);
bool copyFileOver(const std::filesystem::path& src, const std::filesystem::path& dst);
bool removeFile(const std::filesystem::path& path);
bool fileExists(const std::filesystem::path& path);
FileSig fileSig(const std::filesystem::path& path);

}  // namespace b2
