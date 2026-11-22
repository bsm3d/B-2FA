// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "twofas.h"

#include "crypto.h"
#include "fileio.h"

namespace b2::twofas {

namespace {

const char kReference[] =
    "tRViSsLKzd86Hprh4ceC2OP7xazn4rrt4xhfEUbOjxLX8Rc3mkISXE0lWbmnWfggogbBJhtYgpK6fMl1D6m"
    "tsy92R3HkdGfwuXbzLebqVFJsR7IZ2w58t938iymwG4824igYy1wi6n2WDpO1Q1P69zwJGs2F5a1qP4MyIiD"
    "SD7NCV2OvidXQCBnDlGfmz0f1BQySRkkt4ryiJeCjD2o4QsveJ9uDBUn8ELyOrESv5R5DMDkD4iAF8TXU7Ky"
    "oJujd";

struct Field {
    Bytes data, salt, iv;
};

Field split(const Json* field) {
    if (!field || !field->isString()) throw BackupError("Unexpected encrypted field");
    const std::string& text = field->asString();
    std::vector<std::string_view> parts;
    size_t start = 0;
    for (size_t i = 0; i <= text.size(); ++i) {
        if (i == text.size() || text[i] == ':') {
            parts.emplace_back(std::string_view(text).substr(start, i - start));
            start = i + 1;
        }
    }
    if (parts.size() != 3) throw BackupError("Unexpected encrypted field layout");
    Field f;
    if (!base64Decode(parts[0], f.data) || !base64Decode(parts[1], f.salt) || !base64Decode(parts[2], f.iv))
        throw BackupError("Encrypted field is not valid base64");
    if (f.data.size() <= 16) throw BackupError("Encrypted field is too short");
    if (f.iv.size() != kIvBytes) throw BackupError("Unexpected initialisation vector size");
    if (f.salt.size() < 8) throw BackupError("Unexpected salt size");
    return f;
}

Bytes deriveKey(const Secret& password, const Bytes& salt) {
    return pbkdf2Sha256(reinterpret_cast<const uint8_t*>(password.data()), password.size(), salt, kPbkdf2Iterations, 32);
}

Bytes decryptField(const Json* field, const Secret& password) {
    Field f = split(field);
    Bytes key = deriveKey(password, f.salt);
    Bytes plain;
    bool ok = aesGcmDecrypt(key, f.iv, f.data.data(), f.data.size(), nullptr, 0, plain);
    secureZero(key.data(), key.size());
    if (!ok) throw WrongPassword();
    return plain;
}

std::string encryptField(const std::string& plain, const Bytes& key, const Bytes& salt) {
    Bytes iv = randomBytes(kIvBytes);
    Bytes data = aesGcmEncrypt(key, iv, reinterpret_cast<const uint8_t*>(plain.data()), plain.size(), nullptr, 0);
    return base64Encode(data) + ":" + base64Encode(salt) + ":" + base64Encode(iv);
}

}  // namespace

Json readBackup(const std::filesystem::path& path) {
    std::string text;
    try {
        readFile(path, text, kMaxFileBytes);
    } catch (const IoError& e) {
        std::string what = e.what();
        if (what == "The file is too big") throw BackupError("File is too big to be a 2FAS backup");
        throw BackupError("Cannot read this file as a backup (" + what + ")");
    }
    Json content;
    try {
        content = Json::parse(text);
    } catch (const JsonError& e) {
        wipeString(text);
        throw BackupError(std::string("Cannot read this file as a backup (") + e.what() + ")");
    }
    wipeString(text);   // an unencrypted backup holds the secrets in clear
    if (!content.isObject() || !(content.get("services") || content.get("servicesEncrypted")))
        throw BackupError("This does not look like a 2FAS backup");
    auto truthy = [](const Json* v) {
        if (!v || v->isNull()) return false;
        if (v->isString()) return !v->asString().empty();
        if (v->isBool()) return v->asBool();
        if (v->isNumber()) return v->numberText() != "0";
        return true;
    };
    if (truthy(content.get("servicesEncrypted")) && !truthy(content.get("reference")))
        throw BackupError("The encrypted backup has no reference field (damaged file)");
    return content;
}

bool isEncrypted(const Json& content) {
    auto nonEmptyString = [](const Json* v) { return v && v->isString() && !v->asString().empty(); };
    return nonEmptyString(content.get("reference")) && nonEmptyString(content.get("servicesEncrypted"));
}

Json decryptBackup(const Json& content, const Secret& password) {
    if (!isEncrypted(content)) {
        const Json* services = content.get("services");
        if (!services || !services->isArray()) throw BackupError("The services of this backup are not a list");
        return content;
    }
    Bytes reference = decryptField(content.get("reference"), password);
    if (std::string(reference.begin(), reference.end()) != kReference) throw WrongPassword();
    Bytes plain = decryptField(content.get("servicesEncrypted"), password);
    Json services;
    try {
        services = Json::parse(std::string_view(reinterpret_cast<const char*>(plain.data()), plain.size()));
    } catch (const JsonError&) {
        secureZero(plain.data(), plain.size());
        throw BackupError("The decrypted services are not valid JSON");
    }
    secureZero(plain.data(), plain.size());
    if (!services.isArray()) throw BackupError("Decrypted services are not a list");
    Json out = content;
    out.set("services", std::move(services));
    out.set("servicesEncrypted", Json());
    out.set("reference", Json());
    return out;
}

Json buildBackup(const std::vector<Json>& services, const std::vector<Json>& groups, const Secret& password) {
    Bytes salt = randomBytes(kSaltBytes);
    Bytes key = deriveKey(password, salt);
    Json list = Json::array();
    for (const Json& s : services) list.push(s);
    std::string plain = list.dump();
    Json out = Json::object();
    out.set("services", Json::array());
    Json g = Json::array();
    for (const Json& x : groups) g.push(x);
    out.set("groups", std::move(g));
    out.set("updatedAt", Json(nowMs()));
    out.set("schemaVersion", Json(kSchemaVersion));
    out.set("appVersionCode", Json(0));
    out.set("appVersionName", Json("B-2FA"));
    out.set("appOrigin", Json("android"));
    out.set("servicesEncrypted", Json(encryptField(plain, key, salt)));
    out.set("reference", Json(encryptField(kReference, key, salt)));
    secureZero(key.data(), key.size());
    secureZero(plain.data(), plain.size());
    return out;
}

void writeBackup(const std::filesystem::path& path, const std::vector<Json>& services,
                 const std::vector<Json>& groups, const Secret& password) {
    std::string text = buildBackup(services, groups, password).dump();
    std::filesystem::path tmp = path;
    tmp += L".tmp";
    try {
        writeFileSynced(tmp, text);
        replaceFile(tmp, path);
    } catch (...) {
        removeFile(tmp);
        throw;
    }
}

}  // namespace b2::twofas
