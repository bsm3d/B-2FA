// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "pinlock.h"

#include <windows.h>
#include <dpapi.h>

#include "crypto.h"
#include "fileio.h"
#include "json.h"
#include "paths.h"

namespace b2 {

namespace {

DATA_BLOB blobOf(const Bytes& b) {
    static uint8_t kEmpty = 0;
    DATA_BLOB d;
    d.cbData = static_cast<DWORD>(b.size());
    d.pbData = b.empty() ? &kEmpty : const_cast<uint8_t*>(b.data());
    return d;
}

Bytes takeBlob(DATA_BLOB& out) {
    Bytes r(out.pbData, out.pbData + out.cbData);
    secureZero(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return r;
}

Bytes entropyFor(const Secret& pin, const Bytes& salt) {
    return scrypt(reinterpret_cast<const uint8_t*>(pin.data()), pin.size(), salt, 1u << 15, 8, 1, 32);
}

Bytes protect(const Bytes& data, const Bytes& entropy) {
    DATA_BLOB in = blobOf(data), ent = blobOf(entropy), out{};
    if (!CryptProtectData(&in, L"B-2FA PIN", &ent, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        throw PinError("Windows could not protect the PIN data (error " + std::to_string(GetLastError()) + ")");
    return takeBlob(out);
}

bool unprotect(const Bytes& data, const Bytes& entropy, Bytes& result) {
    DATA_BLOB in = blobOf(data), ent = blobOf(entropy), out{};
    if (!CryptUnprotectData(&in, nullptr, &ent, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) return false;
    result = takeBlob(out);
    return true;
}

}  // namespace

WrongPin::WrongPin(int left)
    : PinError("Wrong PIN. " + std::to_string(left) + " tr" + (left == 1 ? "y" : "ies") + " left."), attemptsLeft(left) {}

void checkPinFormat(const Secret& pin) {
    bool ok = pin.size() >= kPinMin && pin.size() <= kPinMax;
    for (char c : pin.view()) if (c < '0' || c > '9') ok = false;
    if (!ok) throw PinError("The PIN must be 4 to 8 digits");
}

PinStore::PinStore(std::filesystem::path path) : path_(path.empty() ? paths::dataDir() / L"pin.b2fa" : std::move(path)) {}

bool PinStore::enabled() const { return fileExists(path_); }

void PinStore::disable() { removeFile(path_); }

static void writeDoc(const std::filesystem::path& path, const std::string& salt, const std::string& blob, int left) {
    Json doc = Json::object();
    doc.set("version", Json(1));
    doc.set("salt", Json(salt));
    doc.set("blob", Json(blob));
    doc.set("attempts_left", Json(left));
    std::filesystem::path tmp = path;
    tmp += L".tmp";
    try {
        writeFileSynced(tmp, doc.dump());
        replaceFile(tmp, path);
    } catch (...) {
        removeFile(tmp);
        throw;
    }
}

void PinStore::enable(const Secret& pin, const Secret& masterPassword) {
    checkPinFormat(pin);
    Bytes salt = randomBytes(16);
    Bytes entropy = entropyFor(pin, salt);
    Bytes master(masterPassword.view().begin(), masterPassword.view().end());
    Bytes wrapped = protect(master, entropy);
    secureZero(master.data(), master.size());
    secureZero(entropy.data(), entropy.size());
    writeDoc(path_, base64Encode(salt), base64Encode(wrapped), kPinMaxAttempts);
}

Secret PinStore::unlock(const Secret& pin) {
    if (!enabled()) throw PinDisabled("No PIN is set");
    Bytes salt, blob;
    int64_t left = 0;
    std::string saltText, blobText;
    try {
        std::string text;
        readFile(path_, text, 1 << 20);
        Json doc = Json::parse(text);
        const Json* s = doc.get("salt");
        const Json* b = doc.get("blob");
        const Json* a = doc.get("attempts_left");
        if (!s || !b || !a || !s->isString() || !b->isString() || !a->toInt64(left)) throw JsonError("fields");
        if (!base64Decode(s->asString(), salt) || !base64Decode(b->asString(), blob)) throw JsonError("base64");
        saltText = s->asString();
        blobText = b->asString();
    } catch (const std::exception&) {
        disable();
        throw PinDisabled("The PIN file is damaged and was removed. Use the master password.");
    }
    if (left <= 0) {
        disable();
        throw PinDisabled("Too many wrong PINs. Use the master password.");
    }
    // counted BEFORE the try, so killing the app does not help
    writeDoc(path_, saltText, blobText, static_cast<int>(left - 1));
    Bytes result;
    bool ok = false;
    try {
        checkPinFormat(pin);
        Bytes entropy = entropyFor(pin, salt);
        ok = unprotect(blob, entropy, result);
        secureZero(entropy.data(), entropy.size());
    } catch (const PinError&) {
        ok = false;
    }
    if (!ok) {
        if (left - 1 <= 0) {
            disable();
            throw PinDisabled("Too many wrong PINs. Use the master password.");
        }
        throw WrongPin(static_cast<int>(left - 1));
    }
    writeDoc(path_, saltText, blobText, kPinMaxAttempts);
    Secret secret{std::string_view(reinterpret_cast<const char*>(result.data()), result.size())};
    secureZero(result.data(), result.size());
    return secret;
}

}  // namespace b2
