// B-2FA
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.1
// Fonction du fichier : Creates and loads the device key file that Windows DPAPI wraps, binding the vault to this PC and Windows account.

// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "devicekey.h"

#include "crypto.h"
#include "winwrap.h"
#include "fileio.h"
#include "json.h"

namespace b2::devicekey {

namespace {
const char kLabel[] = "B-2FA device key v1";
Bytes entropy() { return Bytes(kLabel, kLabel + sizeof(kLabel) - 1); }
}  // namespace

std::filesystem::path pathFor(const std::filesystem::path& vaultPath) { return vaultPath.parent_path() / L"device.b2fa"; }

bool exists(const std::filesystem::path& file) { return fileExists(file); }

Bytes create(const std::filesystem::path& file) {
    Bytes secret = randomBytes(kSecretBytes);
    Bytes wrapped;
    unsigned long err = 0;
    if (!dpapiProtect(secret, entropy(), L"B-2FA device key", wrapped, err)) {
        secureZero(secret.data(), secret.size());
        throw Error("Windows could not protect the device key (error " + std::to_string(err) + ")");
    }
    Json doc = Json::object();
    doc.set("version", Json(1));
    doc.set("blob", Json(base64Encode(wrapped)));
    std::filesystem::path tmp = file;
    tmp += L".tmp";
    try {
        writeFileSynced(tmp, doc.dump());
        replaceFile(tmp, file);
    } catch (const std::exception&) {
        removeFile(tmp);
        secureZero(secret.data(), secret.size());
        throw Error("The device key could not be written next to the vault");
    }
    return secret;
}

Bytes load(const std::filesystem::path& file) {
    static const char* kMissing =
        "This vault is bound to the PC and the Windows account that created it, and its device key cannot be used here. "
        "It does not open anywhere else, even with the master password. Create a new vault and import your recovery backup.";
    std::string text;
    try {
        readFile(file, text, 1 << 20);
    } catch (const IoError&) {
        throw Error(kMissing);
    }
    Bytes wrapped, secret;
    try {
        Json doc = Json::parse(text);
        const Json* v = doc.get("version");
        const Json* b = doc.get("blob");
        int64_t version = 0;
        if (!v || !v->toInt64(version) || version != 1 || !b || !b->isString() || !base64Decode(b->asString(), wrapped)) throw JsonError("fields");
    } catch (const std::exception&) {
        throw Error(kMissing);
    }
    if (!dpapiUnprotect(wrapped, entropy(), secret) || secret.size() != kSecretBytes) throw Error(kMissing);
    return secret;
}

std::string idOf(const Bytes& secret) {
    const char label[] = "B-2FA device id";
    Bytes key(label, label + sizeof(label) - 1);
    Bytes mac = hmac(HashAlg::Sha256, key, secret);
    return hexEncode(mac.data(), 8);
}

Bytes combine(const Bytes& passwordKey, const Bytes& deviceSecret) { return hmac(HashAlg::Sha256, deviceSecret, passwordKey); }

}  // namespace b2::devicekey
