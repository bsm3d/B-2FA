// B-2FA
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.1
// Fonction du fichier : Implements the PIN quick unlock: wraps the master password with DPAPI and scrypt, counts wrong PINs and deletes the file after too many.

// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "pinlock.h"

#include <windows.h>

#include "crypto.h"
#include "winwrap.h"
#include "fileio.h"
#include "json.h"
#include "paths.h"

namespace b2 {

uint64_t PinStore::kdfN = 1ull << 19;   // 512 MiB, about 0.7 s: what an offline guess costs

namespace {

constexpr uint64_t kMinN = 1ull << 15, kMaxN = 1ull << 20;  // bounds accepted from a file (it is untrusted input)

Bytes entropyFor(const Secret& pin, const Bytes& salt, uint64_t n) {
    return scrypt(reinterpret_cast<const uint8_t*>(pin.data()), pin.size(), salt, n, 8, 1, 32);
}

Bytes protect(const Bytes& data, const Bytes& entropy) {
    Bytes out;
    unsigned long err = 0;
    if (!dpapiProtect(data, entropy, L"B-2FA PIN", out, err))
        throw PinError("Windows could not protect the PIN data (error " + std::to_string(err) + ")");
    return out;
}

bool unprotect(const Bytes& data, const Bytes& entropy, Bytes& result) { return dpapiUnprotect(data, entropy, result); }

struct Doc {
    uint64_t n = 0;
    std::string salt, blob;
    int64_t left = 0;
};

void writeDoc(const std::filesystem::path& path, const Doc& d) {
    Json doc = Json::object();
    doc.set("version", Json(1));
    doc.set("n", Json(d.n));
    doc.set("r", Json(8));
    doc.set("p", Json(1));
    doc.set("salt", Json(d.salt));
    doc.set("blob", Json(d.blob));
    doc.set("attempts_left", Json(d.left));
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

void wrapInto(Doc& d, const Secret& pin, const Secret& master, uint64_t n) {
    Bytes salt = randomBytes(16);
    Bytes entropy = entropyFor(pin, salt, n);
    Bytes m(master.view().begin(), master.view().end());
    Bytes wrapped = protect(m, entropy);
    secureZero(m.data(), m.size());
    secureZero(entropy.data(), entropy.size());
    d.n = n;
    d.salt = base64Encode(salt);
    d.blob = base64Encode(wrapped);
    d.left = kPinMaxAttempts;
}

}  // namespace

WrongPin::WrongPin(int left)
    : PinError("Wrong PIN. " + std::to_string(left) + " tr" + (left == 1 ? "y" : "ies") + " left."), attemptsLeft(left) {}

void checkPinFormat(const Secret& pin) {
    bool ok = pin.size() >= kPinMin && pin.size() <= kPinMax;
    for (char c : pin.view()) if (c < '0' || c > '9') ok = false;
    if (!ok) throw PinError("The PIN must be " + std::to_string(kPinMin) + " to " + std::to_string(kPinMax) + " digits");
}

PinStore::PinStore(std::filesystem::path path) : path_(path.empty() ? paths::dataDir() / L"pin.b2fa" : std::move(path)) {}

bool PinStore::enabled() const { return fileExists(path_); }

void PinStore::disable() { removeFile(path_); }

void PinStore::enable(const Secret& pin, const Secret& masterPassword) {
    checkPinFormat(pin);   // at least 6 digits: the offline cost of guessing grows with every digit
    Doc d;
    wrapInto(d, pin, masterPassword, kdfN);
    writeDoc(path_, d);
}

Secret PinStore::unlock(const Secret& pin) {
    if (!enabled()) throw PinDisabled("No PIN is set");
    // A text that cannot be a PIN cannot be right either, so it does not cost an attempt (an empty field
    // and the Enter key must not be able to wipe the PIN).
    checkPinFormat(pin);
    Doc d;
    Bytes salt, blob;
    try {
        std::string text;
        try {
            readFile(path_, text, 1 << 20);
        } catch (const IoError&) {
            // a virus scanner or a backup tool may hold the file for a moment: that is not a damaged file
            throw PinError("The PIN file cannot be read right now. Try again.");
        }
        Json doc = Json::parse(text);
        int64_t version = 0;
        const Json* v = doc.get("version");
        const Json* s = doc.get("salt");
        const Json* b = doc.get("blob");
        const Json* a = doc.get("attempts_left");
        if (!v || !v->toInt64(version) || version != 1) throw JsonError("version");
        if (!s || !b || !a || !s->isString() || !b->isString() || !a->toInt64(d.left)) throw JsonError("fields");
        if (!base64Decode(s->asString(), salt) || !base64Decode(b->asString(), blob)) throw JsonError("base64");
        uint64_t n = 0, r = 0, p = 0;
        const Json *jn = doc.get("n"), *jr = doc.get("r"), *jp = doc.get("p");
        if (!jn || !jr || !jp || !jn->toUInt64(n) || !jr->toUInt64(r) || !jp->toUInt64(p)) throw JsonError("kdf");
        if (n < kMinN || n > kMaxN || (n & (n - 1)) != 0 || r != 8 || p != 1) throw JsonError("kdf bounds");   // never let a file pick the cost
        d.n = n;
        d.salt = s->asString();
        d.blob = b->asString();
    } catch (const PinError&) {
        throw;
    } catch (const std::exception&) {
        disable();
        throw PinDisabled("The PIN file is damaged and was removed. Use the master password.");
    }
    if (d.left <= 0) {
        disable();
        throw PinDisabled("Too many wrong PINs. Use the master password.");
    }
    // counted BEFORE the try, so killing the app does not help
    Doc counted = d;
    counted.left = d.left - 1;
    writeDoc(path_, counted);
    Bytes result;
    bool ok = false;
    {
        Bytes entropy = entropyFor(pin, salt, d.n);
        ok = unprotect(blob, entropy, result);
        secureZero(entropy.data(), entropy.size());
    }
    if (!ok) {
        if (d.left - 1 <= 0) {
            disable();
            throw PinDisabled("Too many wrong PINs. Use the master password.");
        }
        throw WrongPin(static_cast<int>(d.left - 1));
    }
    Secret secret{std::string_view(reinterpret_cast<const char*>(result.data()), result.size())};
    secureZero(result.data(), result.size());
    d.left = kPinMaxAttempts;   // a correct PIN gives the attempts back
    try {
        writeDoc(path_, d);
    } catch (const std::exception&) {
    }
    return secret;
}

}  // namespace b2
