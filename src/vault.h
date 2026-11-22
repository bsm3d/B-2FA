// B-2FA, the local vault: accounts stored in 2FAS service format, encrypted with a master password.
//
// File: vault.b2fa (JSON header + AES-256-GCM payload, key from scrypt, header bound to the
// ciphertext as associated data). Writes are atomic. The previous version is kept as
// vault.b2fa.bak. Automatic backups are copies of the vault file (so they keep the scrypt
// protection), written a few seconds after a change. Only the manual export produces a .2fas
// file (PBKDF2 with 10 000 iterations, imposed by the 2FAS format), with a long password.
//
// Anything that copies the old data (the .bak and the automatic backups) is purged when the
// master password changes or an account is deleted, so a stale copy cannot outlive the change.
//
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "fileio.h"
#include "json.h"
#include "totp.h"
#include "util.h"

namespace b2 {

struct VaultError : std::runtime_error {
    using std::runtime_error::runtime_error;
};
struct WrongMasterPassword : VaultError {
    WrongMasterPassword() : VaultError("Wrong master password") {}
};

constexpr uint64_t kScryptN = 1ull << 18;   // 256 MiB with r = 8: the most the format accepts
constexpr uint32_t kScryptR = 8, kScryptP = 1;
constexpr size_t kMinMasterChars = 16;   // a passphrase of 4 or 5 random words
constexpr size_t kMinExportChars = 16;   // the 2FAS file format is weak: only a long password protects an export
constexpr size_t kKeepBackups = 10;
constexpr double kBackupDelaySeconds = 15.0;
constexpr size_t kMaxText = 256;
constexpr size_t kMaxServices = 10000;
constexpr size_t kMaxServiceBytes = 64 * 1024;   // one account, as JSON: imported entries keep unknown fields, so cap them
extern const char* const kDefaultIconCollection;

// ---- services (2FAS format) ---------------------------------------------
// A complete service entry with all the fields the phone apps expect.
Json makeService(const std::string& name, const std::string& secret, const std::string& issuer = "",
                 const std::string& account = "", const std::string& tokenType = "TOTP", int digits = 6,
                 int period = 30, const std::string& algorithm = "SHA1", uint64_t counter = 0,
                 int64_t position = 0);
// Validate a service coming from an imported file. Throws OtpError if unusable.
Json normalizeService(const Json& raw);
std::optional<Json> normalizeGroup(const Json& raw);
int64_t servicePosition(const Json& service);
std::string serviceId(const Json& service);   // the internal "_id" (never exported)

class Vault {
public:
    // An empty path means the default vault in the data folder.
    explicit Vault(std::filesystem::path path = {});

    bool exists() const;
    bool unlocked() const { return unlocked_; }
    void lock();
    const Secret& masterPassword() const;     // only to wrap it behind the PIN
    bool checkPassword(const Secret& password) const;

    // `bind`: also mix a key wrapped by Windows for this account and PC (device.b2fa) into the vault key. A bound
    // vault file does not open anywhere else, not even with the master password.
    void create(const Secret& password, bool bind = true);
    void unlock(const Secret& password);
    void changePassword(const Secret& oldPassword, const Secret& newPassword);
    void save(bool backup = true);

    // automatic backups
    void flushBackup(double delaySeconds = kBackupDelaySeconds);
    std::optional<std::filesystem::path> autoBackup();
    const std::string& lastBackupError() const { return lastBackupError_; }
    const std::filesystem::path& backupsDir() const { return backupsDir_; }
    // Set by create() when it found copies of an earlier vault: they were moved here, not deleted.
    const std::filesystem::path& keptCopiesDir() const { return keptCopies_; }
    const std::filesystem::path& path() const { return path_; }
    bool bound() const { return header_.bound; }             // valid while unlocked
    std::string deviceId() const { return deviceId_; }       // public id of the device key, empty when not bound

    // accounts
    std::vector<Json> services, groups;
    std::vector<Json*> sortedServices();
    Json* find(const std::string& id);
    Json& add(Json service);
    void update(const Json& service);
    void remove(const std::string& id);
    void bumpCounter(const std::string& id);
    std::pair<int, int> merge(const Json& content);   // (added, skipped)

    std::vector<Json> exportableServices() const;
    void exportBackup(const std::filesystem::path& path, const Secret& password);

    // key derivation cost and size limit: lowered by the tests only
    static uint64_t scryptN;
    static uint64_t maxFileBytes;

private:
    struct Header {
        std::string salt;      // base64
        uint64_t n = 0;
        uint32_t r = 0, p = 0;
        bool bound = false;
    };
    std::filesystem::path path_, backupsDir_;
    bool unlocked_ = false;
    Bytes key_;
    Secret password_;
    Header header_;
    FileSig sig_;
    bool backupDue_ = false;
    uint64_t backupDueAt_ = 0;
    std::string lastBackupError_;
    std::filesystem::path keptCopies_;
    Bytes deviceSecret_;
    std::string deviceId_;

    bool verifyWritten();
    void keepCopiesOfEarlierVault();
    Header derive(const Secret& password, Bytes& key) const;
    void purgeCopies();
    std::vector<std::filesystem::path> autoBackups() const;
    void markBackupDue() { backupDue_ = true; backupDueAt_ = monotonicMs(); }
    struct Snapshot;
};

}  // namespace b2
