// B-2FA
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.1
// Fonction du fichier : Implements the encrypted vault: create, unlock, atomic save, automatic backups, master password change and 2FAS export.

// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "vault.h"

#include <windows.h>

#include <algorithm>
#include <ctime>
#include <set>

#include "crypto.h"
#include "devicekey.h"
#include "paths.h"
#include "twofas.h"

namespace b2 {

namespace fs = std::filesystem;

const char* const kDefaultIconCollection = "a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad";
uint64_t Vault::scryptN = kScryptN;
uint64_t Vault::maxFileBytes = 192ull * 1024 * 1024;   // unlock reads up to 256 MiB: never write what cannot be read back

namespace {

constexpr const char* kFormat = "b2fa-vault";
constexpr int kVersion = 2;
constexpr uint64_t kMinN = 1ull << 14, kMaxN = 1ull << 18;
constexpr uint64_t kMaxKdfMemory = 256ull * 1024 * 1024;
const char kAutoPrefix[] = "B-2FA-auto-";

std::string upperUnicode(const std::string& s) {
    std::wstring w = widen(s);
    if (w.empty()) return {};
    CharUpperBuffW(w.data(), static_cast<DWORD>(w.size()));
    return narrow(w);
}

std::string text(const Json* v, const std::string& def = "") {
    if (!v || v->isNull()) return def;
    std::string s;
    if (v->isString()) s = v->asString();
    else if (v->isBool()) s = v->asBool() ? "True" : "False";
    else if (v->isNumber()) s = v->numberText();
    else s = v->dump();
    return truncateChars(s, kMaxText);
}

bool isWholeInt(const Json* v, int64_t& out) {
    return v && v->isNumber() && v->toInt64(out);
}

void checkMasterPassword(const Secret& password) {
    if (password.codepoints() < kMinMasterChars)
        throw VaultError("The master password needs at least " + std::to_string(kMinMasterChars) + " characters");
}

void checkKdfParams(uint64_t n, uint64_t r, uint64_t p) {
    bool ok = n && (n & (n - 1)) == 0 && n >= kMinN && n <= kMaxN && r >= 1 && r <= 16 && p >= 1 && p <= 4;
    ok = ok && 128ull * n * r * p <= kMaxKdfMemory;
    if (!ok) throw VaultError("The vault file has unsupported key settings");
}

// The header, as canonical JSON (keys sorted, no spaces), is the associated data of the encryption: nothing in
// the header can be changed without the vault failing to open.
std::string aadFor(int version, uint64_t n, uint32_t r, uint32_t p, const std::string& salt, bool bound) {
    // "bound" sorts first; it is only written when true, so a vault that is not bound keeps the plain layout
    return std::string(bound ? "{\"bound\":true,\"format\":\"" : "{\"format\":\"") + kFormat + "\",\"kdf\":{\"n\":" + std::to_string(n) +
           ",\"name\":\"scrypt\",\"p\":" + std::to_string(p) + ",\"r\":" + std::to_string(r) + ",\"salt\":\"" + salt +
           "\"},\"version\":" + std::to_string(version) + "}";
}

std::string newId() { return randomHex(16); }

bool matchesAutoName(const std::wstring& n) {
    return n.rfind(widen(kAutoPrefix), 0) == 0 && n.size() > 5 && n.compare(n.size() - 5, 5, L".b2fa") == 0;
}

}  // namespace

// ---- services -----------------------------------------------------------
int64_t servicePosition(const Json& service) {
    const Json* order = service.get("order");
    int64_t pos = 0;
    if (order && order->isObject() && isWholeInt(order->get("position"), pos)) return pos;
    return 0;
}

std::string serviceId(const Json& service) { return service.stringOr("_id"); }

Json makeService(const std::string& nameIn, const std::string& secretIn, const std::string& issuerIn,
                 const std::string& accountIn, const std::string& tokenType, int digits, int period,
                 const std::string& algorithm, uint64_t counter, int64_t position) {
    std::string secret = checkSecret(secretIn);
    OtpParams params = validateParams(tokenType, digits, period, algorithm, counter);
    std::string issuer = trim(truncateChars(issuerIn, kMaxText)), account = trim(truncateChars(accountIn, kMaxText));
    std::string name = trim(truncateChars(nameIn, kMaxText));
    if (name.empty()) name = !issuer.empty() ? issuer : (!account.empty() ? account : "Account");
    std::string label = (!issuer.empty() && !account.empty()) ? issuer + ":" + account
                                                              : (!account.empty() ? account : (!issuer.empty() ? issuer : name));
    bool hotp = params.type == "HOTP";
    Json otp = Json::object();
    otp.set("link", Json());
    otp.set("label", Json(label));
    otp.set("account", Json(account));
    otp.set("issuer", Json(!issuer.empty() ? issuer : name));
    otp.set("digits", Json(params.digits));
    otp.set("period", hotp ? Json() : Json(params.period));
    otp.set("algorithm", Json(params.algorithm));
    otp.set("counter", hotp ? Json(params.counter) : Json());
    otp.set("tokenType", Json(params.type));
    otp.set("source", Json("Manual"));
    Json lab = Json::object();
    lab.set("text", Json(upperUnicode(truncateChars(name, 2))));
    lab.set("backgroundColor", Json("Indigo"));
    Json coll = Json::object();
    coll.set("id", Json(kDefaultIconCollection));
    Json icon = Json::object();
    icon.set("selected", Json("Label"));
    icon.set("brand", Json());
    icon.set("label", std::move(lab));
    icon.set("iconCollection", std::move(coll));
    Json order = Json::object();
    order.set("position", Json(position));
    Json s = Json::object();
    s.set("name", Json(name));
    s.set("secret", Json(secret));
    wipeString(secret);   // the Json holds its own copy now
    s.set("updatedAt", Json(nowMs()));
    s.set("type", Json());
    s.set("serviceTypeID", Json());
    s.set("otp", std::move(otp));
    s.set("order", std::move(order));
    s.set("badge", Json());
    s.set("icon", std::move(icon));
    s.set("groupId", Json());
    return s;
}

Json normalizeService(const Json& raw) {
    if (!raw.isObject()) throw OtpError("Entry is not an object");
    Json s = raw;
    const Json* rawSecret = raw.get("secret");
    s.set("secret", Json(checkSecret(rawSecret ? *rawSecret : Json())));
    Json otp = Json::object();
    if (const Json* ro = raw.get("otp"); ro && ro->isObject()) otp = *ro;
    auto field = [&](const char* k) { const Json* v = otp.get(k); return v ? *v : Json(); };
    OtpParams p = validateParams(field("tokenType"), field("digits"), field("period"), field("algorithm"), field("counter"));
    otp.set("tokenType", Json(p.type));
    otp.set("digits", Json(p.digits));
    otp.set("algorithm", Json(p.algorithm));
    otp.set("period", p.type != "HOTP" ? Json(p.period) : field("period"));
    otp.set("counter", p.type == "HOTP" ? Json(p.counter) : field("counter"));
    for (const char* key : {"link", "label", "account", "issuer", "source"}) {
        const Json* v = otp.get(key);
        otp.set(key, (!v || v->isNull()) ? Json() : Json(text(v)));
    }
    s.set("otp", std::move(otp));
    std::string name = text(raw.get("name"), "Account");
    if (name.empty()) name = "Account";
    s.set("name", Json(name));
    Json order = Json::object();
    order.set("position", Json(servicePosition(raw)));
    s.set("order", std::move(order));
    for (const char* key : {"icon", "badge"}) {
        const Json* v = raw.get(key);
        if (!v || !v->isObject()) s.set(key, Json());
    }
    const Json* icon = s.get("icon");
    if (!icon || icon->isNull()) s.set("icon", *makeService(name, s.get("secret")->asString()).get("icon"));
    for (const char* key : {"groupId", "serviceTypeID", "type"}) {
        const Json* v = raw.get(key);
        if (!v || !v->isString()) s.set(key, Json());
    }
    int64_t ts = 0;
    s.set("updatedAt", isWholeInt(raw.get("updatedAt"), ts) ? Json(ts) : Json(nowMs()));
    return s;
}

std::optional<Json> normalizeGroup(const Json& raw) {
    if (!raw.isObject()) return std::nullopt;
    const Json* id = raw.get("id");
    const Json* name = raw.get("name");
    if (!id || !id->isString() || !name || !name->isString()) return std::nullopt;
    Json g = Json::object();
    g.set("id", Json(truncateChars(id->asString(), 64)));
    g.set("name", Json(truncateChars(name->asString(), kMaxText)));
    const Json* exp = raw.get("isExpanded");
    bool expanded = false;
    if (exp) {
        if (exp->isBool()) expanded = exp->asBool();
        else if (exp->isNumber()) expanded = exp->numberText() != "0";
        else if (exp->isString()) expanded = !exp->asString().empty();
        else if (!exp->isNull()) expanded = true;
    }
    g.set("isExpanded", Json(expanded));
    int64_t ts = 0;
    g.set("updatedAt", isWholeInt(raw.get("updatedAt"), ts) ? Json(ts) : Json(0));
    return g;
}

// ---- vault ----------------------------------------------------------------
struct Vault::Snapshot {
    Vault& v;
    std::vector<Json> services, groups;
    bool committed = false;
    explicit Snapshot(Vault& vault) : v(vault), services(vault.services), groups(vault.groups) {}
    void commit() {
        committed = true;
        wipeJsonList(services);
        wipeJsonList(groups);
    }
    ~Snapshot() {
        if (!committed) {
            wipeJsonList(v.services);   // the half-changed state goes away
            wipeJsonList(v.groups);
            v.services = std::move(services);
            v.groups = std::move(groups);
        }
    }
};

Vault::Vault(fs::path path) {
    if (path.empty()) {
        path_ = paths::vaultPath();
        backupsDir_ = paths::backupsDir();
    } else {
        path_ = std::move(path);
        backupsDir_ = path_.parent_path() / L"backups";
    }
}

bool Vault::exists() const { return fileExists(path_); }

void Vault::lock() {
    flushBackup(0);
    backupDue_ = false;
    unlocked_ = false;
    secureZero(key_.data(), key_.size());
    key_.clear();
    password_.wipe();
    sig_ = FileSig{};
    secureZero(deviceSecret_.data(), deviceSecret_.size());
    deviceSecret_.clear();
    wipeJsonList(services);   // the accounts' secrets are overwritten, not just freed
    wipeJsonList(groups);
}

const Secret& Vault::masterPassword() const {
    if (!unlocked_) throw VaultError("The vault is locked");
    return password_;
}

bool Vault::checkPassword(const Secret& password) const { return unlocked_ && password.equals(password_); }

Vault::Header Vault::derive(const Secret& password, Bytes& key) const {
    Bytes salt = randomBytes(16);
    Header h;
    h.salt = base64Encode(salt);
    h.n = scryptN;
    h.r = kScryptR;
    h.p = kScryptP;
    key = scrypt(reinterpret_cast<const uint8_t*>(password.data()), password.size(), salt, h.n, h.r, h.p, 32);
    return h;
}

// Copies of an EARLIER vault (the .bak and the automatic backups) must not be overwritten or rotated away by the
// new one: they may be the only way back to the old accounts. They go to a folder of their own, untouched.
void Vault::keepCopiesOfEarlierVault() {
    keptCopies_.clear();
    std::vector<fs::path> old;
    fs::path bak = path_;
    bak += L".bak";
    if (fileExists(bak)) old.push_back(bak);
    if (devicekey::exists(devicekey::pathFor(path_))) old.push_back(devicekey::pathFor(path_));   // the key those copies need
    std::error_code ec;
    for (fs::directory_iterator it(backupsDir_, ec), end; !ec && it != end; it.increment(ec)) {
        std::wstring name = it->path().filename().wstring();
        if (it->is_regular_file(ec) && matchesAutoName(name)) old.push_back(it->path());
    }
    if (old.empty()) return;
    char stamp[32];
    std::time_t t = std::time(nullptr);
    std::tm local{};
    localtime_s(&local, &t);
    std::strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &local);
    fs::path dir = backupsDir_ / (std::string("earlier-vault-") + stamp);
    fs::create_directories(dir, ec);
    for (const fs::path& f : old) {
        std::error_code mv;
        fs::rename(f, dir / f.filename(), mv);
    }
    keptCopies_ = dir;
}

void Vault::create(const Secret& password, bool bind) {
    if (exists()) throw VaultError("A vault already exists");
    checkMasterPassword(password);
    keepCopiesOfEarlierVault();
    header_ = derive(password, key_);
    header_.bound = bind;
    if (bind) {
        try {
            deviceSecret_ = devicekey::create(devicekey::pathFor(path_));
        } catch (const devicekey::Error& e) {
            secureZero(key_.data(), key_.size());
            throw VaultError(e.what());
        }
        deviceId_ = devicekey::idOf(deviceSecret_);
        Bytes mixed = devicekey::combine(key_, deviceSecret_);
        secureZero(key_.data(), key_.size());
        key_ = std::move(mixed);
    }
    password_ = password.clone();
    services.clear();
    groups.clear();
    unlocked_ = true;
    try {
        save(false);
    } catch (...) {
        lock();
        if (bind) removeFile(devicekey::pathFor(path_));   // no vault was made: no key either
        throw;
    }
}

void Vault::unlock(const Secret& password) {
    FileSig sigBeforeRead = fileSig(path_);   // taken first: a change between the read and the signature must be seen
    Bytes key;
    Header header;
    std::vector<Json> loadedServices, loadedGroups;
    Bytes deviceSecretLoaded;
    try {
        std::string fileText;
        readFile(path_, fileText, 256ull * 1024 * 1024);
        Json doc = Json::parse(fileText);
        const Json* format = doc.get("format");
        if (!doc.isObject() || !format || !format->isString() || format->asString() != kFormat)
            throw VaultError("This file is not a B-2FA vault");
        int64_t v = 0;
        const Json* ver = doc.get("version");
        if (!ver || !ver->toInt64(v) || v != kVersion) throw VaultError("This vault file has an unsupported format version");
        const Json* kdf = doc.get("kdf");
        if (!kdf || !kdf->isObject()) throw VaultError("The vault file is damaged (KeyError)");
        uint64_t n = 0, r = 0, p = 0;
        const Json *jn = kdf->get("n"), *jr = kdf->get("r"), *jp = kdf->get("p"), *jname = kdf->get("name"), *jsalt = kdf->get("salt");
        if (!jn || !jr || !jp || !jsalt || !jname || !jn->toUInt64(n) || !jr->toUInt64(r) || !jp->toUInt64(p) || !jsalt->isString())
            throw VaultError("The vault file has unsupported key settings");
        if (!jname->isString() || jname->asString() != "scrypt") throw VaultError("The vault file has unsupported key settings");
        checkKdfParams(n, r, p);
        if (const Json* jb = doc.get("bound")) {
            if (!jb->isBool()) throw VaultError("The vault file is damaged (ValueError)");
            header.bound = jb->asBool();
        }
        Bytes salt, nonce, data;
        const Json *jnonce = doc.get("nonce"), *jdata = doc.get("data");
        if (!jnonce || !jdata || !jnonce->isString() || !jdata->isString() || !base64Decode(jsalt->asString(), salt) ||
            !base64Decode(jnonce->asString(), nonce) || !base64Decode(jdata->asString(), data))
            throw VaultError("The vault file is damaged (ValueError)");
        header.salt = jsalt->asString();
        header.n = n;
        header.r = static_cast<uint32_t>(r);
        header.p = static_cast<uint32_t>(p);
        Bytes secret;
        if (header.bound) {
            try {
                secret = devicekey::load(devicekey::pathFor(path_));   // before the slow derivation: a missing key is said at once
            } catch (const devicekey::Error& e) {
                throw VaultError(e.what());
            }
        }
        key = scrypt(reinterpret_cast<const uint8_t*>(password.data()), password.size(), salt, n, header.r, header.p, 32);
        if (header.bound) {
            Bytes mixed = devicekey::combine(key, secret);
            secureZero(key.data(), key.size());
            key = std::move(mixed);
            deviceSecretLoaded = std::move(secret);
        }
        std::string aad = aadFor(kVersion, n, header.r, header.p, header.salt, header.bound);
        Bytes plain;
        if (!aesGcmDecrypt(key, nonce, data.data(), data.size(), reinterpret_cast<const uint8_t*>(aad.data()), aad.size(), plain)) {
            secureZero(key.data(), key.size());
            throw WrongMasterPassword();
        }
        Json payload;
        try {
            payload = Json::parse(std::string_view(reinterpret_cast<const char*>(plain.data()), plain.size()));
        } catch (...) {
            secureZero(plain.data(), plain.size());
            throw;
        }
        secureZero(plain.data(), plain.size());
        const Json* js = payload.get("services");
        const Json* jg = payload.get("groups");
        if (!payload.isObject() || (js && !js->isArray()) || (jg && !jg->isArray())) throw VaultError("The vault file is damaged (ValueError)");
        if (js) for (const Json& s : js->items()) if (s.isObject()) loadedServices.push_back(s);
        if (jg) for (const Json& g : jg->items()) if (g.isObject()) loadedGroups.push_back(g);
        payload.wipe();   // the copies above are the only ones left
    } catch (const VaultError&) {
        secureZero(key.data(), key.size());
        throw;
    } catch (const IoError& e) {
        throw VaultError(std::string("The vault file is damaged (") + e.what() + "). Your backups are in " + backupsDir_.string());
    } catch (const JsonError& e) {
        throw VaultError(std::string("The vault file is damaged (") + e.what() + "). Your backups are in " + backupsDir_.string());
    }
    header_ = header;
    key_ = std::move(key);
    deviceSecret_ = std::move(deviceSecretLoaded);
    deviceId_ = header.bound ? devicekey::idOf(deviceSecret_) : std::string();
    password_ = password.clone();
    unlocked_ = true;
    sig_ = sigBeforeRead;
    services = std::move(loadedServices);
    groups = std::move(loadedGroups);
    for (Json& s : services) s.set("_id", Json(newId()));
}

void Vault::save(bool backup) {
    if (!unlocked_) throw VaultError("The vault is locked");
    Json payload = Json::object();
    Json s = Json::array(), g = Json::array();
    for (const Json& x : services) s.push(x);
    for (const Json& x : groups) g.push(x);
    payload.set("services", std::move(s));
    payload.set("groups", std::move(g));
    std::string plain = payload.dump();
    payload.wipe();
    Bytes nonce = randomBytes(12);
    std::string aad = aadFor(kVersion, header_.n, header_.r, header_.p, header_.salt, header_.bound);
    Bytes cipher = aesGcmEncrypt(key_, nonce, reinterpret_cast<const uint8_t*>(plain.data()), plain.size(),
                                 reinterpret_cast<const uint8_t*>(aad.data()), aad.size());
    secureZero(plain.data(), plain.size());
    Json kdf = Json::object();
    kdf.set("name", Json("scrypt"));
    kdf.set("n", Json(header_.n));
    kdf.set("r", Json(static_cast<uint64_t>(header_.r)));
    kdf.set("p", Json(static_cast<uint64_t>(header_.p)));
    kdf.set("salt", Json(header_.salt));
    Json doc = Json::object();
    doc.set("format", Json(kFormat));
    doc.set("version", Json(kVersion));
    if (header_.bound) doc.set("bound", Json(true));
    doc.set("kdf", std::move(kdf));
    doc.set("nonce", Json(base64Encode(nonce)));
    doc.set("data", Json(base64Encode(cipher)));
    std::string text = doc.dump();
    if (text.size() > maxFileBytes)   // a vault that is written must be a vault that can be read
        throw VaultError("The vault would be too big (" + std::to_string(text.size() / (1024 * 1024)) +
                         " MB). Nothing was saved. Delete accounts with very large extra data, or import fewer.");
    fs::path tmp = path_;
    tmp += L".tmp";
    try {
        writeFileSynced(tmp, text);
        if (exists()) {
            if (sig_.valid && fileSig(path_) != sig_)
                throw VaultError("The vault was changed by another program. Close and reopen B-2FA before editing it.");
            fs::path bak = path_;
            bak += L".bak";
            if (!copyFileOver(path_, bak)) lastBackupError_ = "Could not keep the previous version of the vault (vault.b2fa.bak).";
        }
        replaceFile(tmp, path_);
    } catch (...) {
        removeFile(tmp);
        throw;
    }
    removeFile(tmp);
    sig_ = fileSig(path_);
    // read it back with the key we hold BEFORE anything that deletes older copies can run
    if (!verifyWritten()) {
        fs::path bak = path_;
        bak += L".bak";
        if (fileExists(bak) && copyFileOver(bak, path_)) sig_ = fileSig(path_);   // put the previous, readable version back
        throw VaultError("The new vault file could not be read back, so the previous version was kept. Nothing was lost.");
    }
    if (backup && !backupDue_) markBackupDue();
}

bool Vault::verifyWritten() {
    try {
        std::string text;
        readFile(path_, text, maxFileBytes + 1024 * 1024);
        Json doc = Json::parse(text);
        const Json* kdf = doc.get("kdf");
        const Json *jnonce = doc.get("nonce"), *jdata = doc.get("data");
        if (!kdf || !jnonce || !jdata || !jnonce->isString() || !jdata->isString()) return false;
        Bytes nonce, data, plain;
        if (!base64Decode(jnonce->asString(), nonce) || !base64Decode(jdata->asString(), data)) return false;
        std::string aad = aadFor(kVersion, header_.n, header_.r, header_.p, header_.salt, header_.bound);
        if (!aesGcmDecrypt(key_, nonce, data.data(), data.size(), reinterpret_cast<const uint8_t*>(aad.data()), aad.size(), plain)) return false;
        bool ok = true;
        try {
            Json payload = Json::parse(std::string_view(reinterpret_cast<const char*>(plain.data()), plain.size()));
            ok = payload.isObject();
            payload.wipe();
        } catch (const std::exception&) {
            ok = false;
        }
        secureZero(plain.data(), plain.size());
        return ok;
    } catch (const std::exception&) {
        return false;
    }
}

void Vault::changePassword(const Secret& oldPassword, const Secret& newPassword) {
    if (!checkPassword(oldPassword)) throw WrongMasterPassword();
    checkMasterPassword(newPassword);
    Header oldHeader = header_;
    Bytes oldKey = key_;
    Secret oldPw = password_.clone();
    header_ = derive(newPassword, key_);
    header_.bound = oldHeader.bound;
    if (header_.bound) {
        Bytes mixed = devicekey::combine(key_, deviceSecret_);
        secureZero(key_.data(), key_.size());
        key_ = std::move(mixed);
    }
    password_ = newPassword.clone();
    try {
        save(false);
    } catch (...) {
        header_ = oldHeader;
        key_ = oldKey;
        password_ = std::move(oldPw);
        throw;
    }
    secureZero(oldKey.data(), oldKey.size());
    purgeCopies();
    markBackupDue();
    flushBackup(0);
}

// ---- backups -------------------------------------------------------------
std::vector<fs::path> Vault::autoBackups() const {
    std::vector<std::pair<fs::file_time_type, fs::path>> list;
    std::error_code ec;
    for (fs::directory_iterator it(backupsDir_, ec), end; !ec && it != end; it.increment(ec)) {
        std::wstring name = it->path().filename().wstring();
        if (matchesAutoName(name)) {
            std::error_code e2;
            list.emplace_back(fs::last_write_time(it->path(), e2), it->path());
        }
    }
    std::sort(list.begin(), list.end(), [](auto& a, auto& b) { return a.first < b.first; });
    std::vector<fs::path> out;
    for (auto& e : list) out.push_back(e.second);
    return out;
}

void Vault::purgeCopies() {
    fs::path bak = path_;
    bak += L".bak";
    removeFile(bak);
    std::error_code ec;
    for (fs::directory_iterator it(backupsDir_, ec), end; !ec && it != end; it.increment(ec)) {
        std::wstring name = it->path().filename().wstring();
        bool tmpCopy = name.rfind(widen(kAutoPrefix), 0) == 0 && name.size() > 4 && name.compare(name.size() - 4, 4, L".tmp") == 0;
        if (matchesAutoName(name) || tmpCopy) removeFile(it->path());
    }
}

void Vault::flushBackup(double delaySeconds) {
    if (!backupDue_ || !unlocked_) return;
    if (static_cast<double>(monotonicMs() - backupDueAt_) / 1000.0 < delaySeconds) return;
    try {
        autoBackup();
        lastBackupError_.clear();
        backupDue_ = false;
    } catch (const std::exception& e) {
        lastBackupError_ = std::string("Automatic backup failed: ") + e.what();
        backupDueAt_ = monotonicMs();   // still due: tried again after the delay
    }
}

std::optional<fs::path> Vault::autoBackup() {
    if (services.empty() || !exists()) return std::nullopt;
    // never copy over good backups a file somebody else changed or damaged
    if (sig_.valid && fileSig(path_) != sig_)
        throw VaultError("the vault file was changed by another program, so no backup was made");
    std::error_code ec;
    fs::create_directories(backupsDir_, ec);
    char stamp[32];
    std::time_t t = std::time(nullptr);
    std::tm local{};
    localtime_s(&local, &t);
    std::strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &local);
    fs::path target = backupsDir_ / (std::string(kAutoPrefix) + stamp + ".b2fa");
    for (int i = 1; fileExists(target); ++i)
        target = backupsDir_ / (std::string(kAutoPrefix) + stamp + "-" + std::to_string(i) + ".b2fa");
    fs::path tmp = target;
    tmp.replace_extension(L".tmp");
    if (!copyFileOver(path_, tmp)) throw IoError("Cannot write the backup");
    try {
        replaceFile(tmp, target);
    } catch (...) {
        removeFile(tmp);
        throw;
    }
    std::vector<fs::path> all = autoBackups();
    if (all.size() > kKeepBackups) {
        for (size_t i = 0; i + kKeepBackups < all.size(); ++i)
            if (all[i] != target) removeFile(all[i]);
    }
    return target;
}

std::vector<Json> Vault::exportableServices() const {
    std::vector<Json*> order;
    auto* self = const_cast<Vault*>(this);
    order = self->sortedServices();
    std::vector<Json> out;
    int64_t i = 0;
    for (const Json* s : order) {
        Json clean = Json::object();
        for (const auto& m : s->members()) if (m.first.empty() || m.first[0] != '_') clean.members().emplace_back(m);   // linear: set() scanned the keys each time
        Json pos = Json::object();
        pos.set("position", Json(i++));
        clean.set("order", std::move(pos));
        out.push_back(std::move(clean));
    }
    return out;
}

void Vault::exportBackup(const fs::path& path, const Secret& password) {
    if (!unlocked_) throw VaultError("The vault is locked. Nothing was exported.");   // a locked vault would export an empty file
    if (password.codepoints() < kMinExportChars)
        throw VaultError("The backup password needs at least " + std::to_string(kMinExportChars) + " characters");
    if (checkPassword(password))
        throw VaultError("Use a password different from the master password: the .2fas format protects it far less than the vault does");
    std::vector<Json> list = exportableServices();
    try {
        twofas::writeBackup(path, list, groups, password);
    } catch (...) {
        wipeJsonList(list);
        throw;
    }
    wipeJsonList(list);
}

// ---- accounts ------------------------------------------------------------
std::vector<Json*> Vault::sortedServices() {
    std::vector<Json*> out;
    for (Json& s : services) out.push_back(&s);
    std::stable_sort(out.begin(), out.end(), [](const Json* a, const Json* b) { return servicePosition(*a) < servicePosition(*b); });
    return out;
}

Json* Vault::find(const std::string& id) {
    for (Json& s : services) if (serviceId(s) == id) return &s;
    return nullptr;
}

static int64_t nextPosition(const std::vector<Json>& services) {
    int64_t best = -1;
    for (const Json& s : services) best = std::max(best, servicePosition(s));
    return best + 1;
}

Json& Vault::add(Json service) {
    Snapshot snap(*this);
    service.set("_id", Json(newId()));
    Json order = Json::object();
    order.set("position", Json(nextPosition(services)));
    service.set("order", std::move(order));
    services.push_back(std::move(service));
    save();
    snap.commit();
    return services.back();
}

void Vault::update(const Json& service) {
    Snapshot snap(*this);
    std::string id = serviceId(service);
    bool found = false;
    for (Json& s : services) {
        if (serviceId(s) == id) {
            Json copy = service;
            copy.set("updatedAt", Json(nowMs()));
            s = std::move(copy);
            found = true;
            break;
        }
    }
    if (!found) throw VaultError("This account no longer exists");
    save();
    snap.commit();
}

void Vault::remove(const std::string& id) {
    {
        Snapshot snap(*this);
        services.erase(std::remove_if(services.begin(), services.end(), [&](const Json& s) { return serviceId(s) == id; }),
                       services.end());
        save(false);
        snap.commit();
    }
    purgeCopies();  // old copies still hold the deleted account
    markBackupDue();
    flushBackup(0);
}

void Vault::bumpCounter(const std::string& id) {
    Json* s = find(id);
    if (!s) throw VaultError("This account no longer exists");
    Json before = *s;
    Json* otp = s->get("otp");
    if (!otp || !otp->isObject()) {
        s->set("otp", Json::object());
        otp = s->get("otp");
    }
    uint64_t counter = 0;
    if (const Json* c = otp->get("counter")) {
        if (!c->toUInt64(counter)) counter = 0;
    }
    if (counter == UINT64_MAX) throw OtpError("Counter out of range");
    otp->set("counter", Json(counter + 1));
    s->set("updatedAt", Json(nowMs()));
    try {
        save();
    } catch (...) {
        *s = std::move(before);
        throw;
    }
}

std::pair<int, int> Vault::merge(const Json& content) {
    const Json* incoming = content.get("services");
    if (!incoming || !incoming->isArray()) throw VaultError("The backup has no list of services");
    if (incoming->items().size() > kMaxServices) throw VaultError("The backup has too many services");
    int added = 0, skipped = 0;
    Snapshot snap(*this);
    std::set<std::string> known;
    for (const Json& s : services) {
        try {
            const Json* sec = s.get("secret");
            known.insert(checkSecret(sec ? *sec : Json()));
        } catch (const OtpError&) {
        }
    }
    std::set<std::string> knownGroups;
    for (const Json& g : groups) knownGroups.insert(g.stringOr("id"));
    if (const Json* rg = content.get("groups"); rg && rg->isArray()) {
        for (const Json& raw : rg->items()) {
            auto g = normalizeGroup(raw);
            if (g && !knownGroups.count(g->stringOr("id"))) {
                knownGroups.insert(g->stringOr("id"));
                groups.push_back(*g);
            }
        }
    }
    std::vector<const Json*> sorted;
    for (const Json& s : incoming->items()) sorted.push_back(&s);
    std::stable_sort(sorted.begin(), sorted.end(), [](const Json* a, const Json* b) {
        return (a->isObject() ? servicePosition(*a) : 0) < (b->isObject() ? servicePosition(*b) : 0);
    });
    for (const Json* raw : sorted) {
        Json s;
        try {
            s = normalizeService(*raw);
        } catch (const OtpError&) {
            ++skipped;
            continue;
        }
        if (s.dump().size() > kMaxServiceBytes) {   // an entry with megabytes of extra fields is not an account
            ++skipped;
            continue;
        }
        std::string secret = s.get("secret")->asString();
        if (known.count(secret)) {
            wipeString(secret);
            ++skipped;
            continue;
        }
        s.set("_id", Json(newId()));
        Json order = Json::object();
        order.set("position", Json(nextPosition(services)));
        s.set("order", std::move(order));
        services.push_back(std::move(s));
        known.insert(secret);
        wipeString(secret);
        ++added;
    }
    // the set of secrets goes away: overwrite its texts first (the nodes are never compared again)
    for (const std::string& k : known) secureZero(const_cast<char*>(k.data()), k.capacity() + 1);
    known.clear();
    if (added) save();
    snap.commit();
    return {added, skipped};
}

}  // namespace b2
