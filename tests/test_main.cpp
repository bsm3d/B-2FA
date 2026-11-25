// B-2FA
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.1
// Fonction du fichier : Core test program checking crypto vectors, OTP codes, the vault, the 2FAS format, the unlock guard and icon pack lookup.

// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include "crypto.h"
#include "devicekey.h"
#include "fileio.h"
#include "icons.h"
#include "paths.h"
#include "json.h"
#include "keypad_layout.h"
#include "pinlock.h"
#include "settings.h"
#include "totp.h"
#include "twofas.h"
#include "unlockguard.h"
#include "util.h"
#include "vault.h"

using namespace b2;
namespace fs = std::filesystem;

static int g_failed = 0, g_checks = 0;
static const char* g_test = "";

#define CHECK(cond)                                                                       \
    do {                                                                                  \
        ++g_checks;                                                                       \
        if (!(cond)) {                                                                    \
            ++g_failed;                                                                   \
            std::printf("  FAIL [%s] %s:%d: %s\n", g_test, __FILE__, __LINE__, #cond);   \
        }                                                                                 \
    } while (0)

#define CHECK_EQ(a, b)                                                                        \
    do {                                                                                      \
        ++g_checks;                                                                           \
        auto va = (a);                                                                        \
        auto vb = (b);                                                                        \
        if (!(va == vb)) {                                                                    \
            ++g_failed;                                                                       \
            std::printf("  FAIL [%s] %s:%d: %s == %s\n", g_test, __FILE__, __LINE__, #a, #b); \
        }                                                                                     \
    } while (0)

template <class E, class F>
static bool throws(F&& f) {
    try {
        f();
    } catch (const E&) {
        return true;
    } catch (...) {
        return false;
    }
    return false;
}

static Bytes B(const std::string& s) { return Bytes(s.begin(), s.end()); }
static std::string H(const Bytes& b) { return hexEncode(b); }
static Secret S(const char* s) { return Secret(std::string_view(s)); }

static fs::path tempDir(const char* name) {
    fs::path p = fs::temp_directory_path() / (std::string("b2fa-test-") + name + "-" + randomHex(4));
    fs::create_directories(p);
    return p;
}

// ---- util -----------------------------------------------------------------
static void test_encodings() {
    CHECK_EQ(base64Encode(B("")), std::string(""));
    CHECK_EQ(base64Encode(B("f")), std::string("Zg=="));
    CHECK_EQ(base64Encode(B("fo")), std::string("Zm8="));
    CHECK_EQ(base64Encode(B("foo")), std::string("Zm9v"));
    CHECK_EQ(base64Encode(B("foobar")), std::string("Zm9vYmFy"));
    Bytes out;
    CHECK(base64Decode("Zm9vYmFy", out) && out == B("foobar"));
    CHECK(base64Decode("Zg==", out) && out == B("f"));
    CHECK(!base64Decode("Zg", out));         // padding required
    CHECK(!base64Decode("Zm9v YmFy", out));  // no whitespace
    CHECK(!base64Decode("Zg=a", out));
    CHECK(base32Decode("MZXW6YTBOI======", out) && out == B("foobar"));
    CHECK(base32Decode("MZXW6YTBOI", out) && out == B("foobar"));
    CHECK(!base32Decode("MZXW6YT1", out));
    CHECK(!base32Decode("M", out));
    CHECK(hexDecode("00ff10", out) && H(out) == "00ff10");
    CHECK(!hexDecode("0g", out));
    CHECK(validUtf8("caf\xC3\xA9"));
    CHECK(!validUtf8("caf\xC3"));
    CHECK(!validUtf8("\xED\xA0\x80"));  // a surrogate
    CHECK_EQ(codepointCount("caf\xC3\xA9"), size_t(4));
    CHECK_EQ(truncateChars("caf\xC3\xA9s", 4), std::string("caf\xC3\xA9"));
    CHECK_EQ(widen("caf\xC3\xA9"), std::wstring(L"caf\u00e9"));
    CHECK_EQ(narrow(L"caf\u00e9"), std::string("caf\xC3\xA9"));
}

static void test_secret() {
    Secret a = S("hunter2 hunter2"), b = S("hunter2 hunter2"), c = S("hunter2 hunter3");
    CHECK(a.equals(b));
    CHECK(!a.equals(c));
    Secret u = S("caf\xC3\xA9 caf\xC3\xA9");
    CHECK_EQ(u.codepoints(), size_t(9));
    Secret d = a.clone();
    CHECK(d.equals(a));
    d.wipe();
    CHECK(d.empty());
}

// ---- json -----------------------------------------------------------------
static void test_json() {
    Json j = Json::parse(R"({"a":1,"b":[true,null,"x\u00e9\ud83d\ude00"],"c":{"d":-2.5e3},"a":3,"big":18446744073709551615})");
    CHECK(j.isObject());
    CHECK_EQ(j.members()[0].first, std::string("a"));   // a repeated key keeps its first place
    uint64_t v = 0;
    CHECK(j.get("a")->toUInt64(v) && v == 3);
    CHECK(j.get("big")->toUInt64(v) && v == 18446744073709551615ull);
    int64_t i = 0;
    CHECK(!j.get("big")->toInt64(i));
    CHECK_EQ(j.get("b")->items()[2].asString(), std::string("x\xC3\xA9\xF0\x9F\x98\x80"));
    CHECK_EQ(j.get("c")->get("d")->numberText(), std::string("-2.5e3"));   // numbers keep their text
    CHECK(!j.get("c")->get("d")->isInteger());
    // round trip keeps order and unknown fields
    Json k = Json::parse(j.dump());
    CHECK_EQ(k.dump(), j.dump());
    CHECK(throws<JsonError>([] { Json::parse("{"); }));
    CHECK(throws<JsonError>([] { Json::parse("[1,]"); }));
    CHECK(throws<JsonError>([] { Json::parse("NaN"); }));
    CHECK(throws<JsonError>([] { Json::parse("{\"a\":01}"); }));
    CHECK(throws<JsonError>([] { Json::parse("\"a\nb\""); }));
    CHECK(throws<JsonError>([] { Json::parse("[1] x"); }));
    CHECK(throws<JsonError>([] { Json::parse(std::string("\"\xFF\"")); }));
    CHECK(throws<JsonError>([] { Json::parse(std::string(500, '[') + std::string(500, ']')); }));
    CHECK(Json::parse("\xEF\xBB\xBF[1]").isArray());  // byte order mark
    Json s = Json("tab\there \"q\" \\ \x01");
    CHECK_EQ(s.dump(), std::string("\"tab\\there \\\"q\\\" \\\\ \\u0001\""));
}

// ---- crypto vectors -------------------------------------------------------
static void test_crypto() {
    // RFC 4231 HMAC test case 2
    Bytes mac = hmac(HashAlg::Sha256, B("Jefe"), B("what do ya want for nothing?"));
    CHECK_EQ(H(mac), std::string("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    mac = hmac(HashAlg::Sha1, B("Jefe"), B("what do ya want for nothing?"));
    CHECK_EQ(H(mac), std::string("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"));
    // RFC 7914 section 11
    Bytes dk = pbkdf2Sha256(reinterpret_cast<const uint8_t*>("passwd"), 6, B("salt"), 1, 64);
    CHECK_EQ(H(dk), std::string("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"));
    dk = scrypt(reinterpret_cast<const uint8_t*>(""), 0, B(""), 16, 1, 1, 64);
    CHECK_EQ(H(dk), std::string("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"));
    dk = scrypt(reinterpret_cast<const uint8_t*>("password"), 8, B("NaCl"), 1024, 8, 16, 64);
    CHECK_EQ(H(dk), std::string("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"));
    // NIST GCM test case 14 (256 bit key, zero IV, 16 zero bytes)
    Bytes key(32, 0), nonce(12, 0), zero(16, 0);
    Bytes ct = aesGcmEncrypt(key, nonce, zero.data(), zero.size(), nullptr, 0);
    CHECK_EQ(H(ct), std::string("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"));
    Bytes plain;
    CHECK(aesGcmDecrypt(key, nonce, ct.data(), ct.size(), nullptr, 0, plain) && plain == zero);
    ct[3] ^= 1;
    CHECK(!aesGcmDecrypt(key, nonce, ct.data(), ct.size(), nullptr, 0, plain));  // tampered
    ct[3] ^= 1;
    Bytes aad = B("header");
    Bytes withAad = aesGcmEncrypt(key, nonce, zero.data(), zero.size(), aad.data(), aad.size());
    CHECK(aesGcmDecrypt(key, nonce, withAad.data(), withAad.size(), aad.data(), aad.size(), plain));
    CHECK(!aesGcmDecrypt(key, nonce, withAad.data(), withAad.size(), nullptr, 0, plain));  // other AAD
}

// ---- one-time passwords ---------------------------------------------------
static const char* S1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
static const char* S256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
static const char* S512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=";

static void test_otp() {
    const char* expected[] = {"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"};
    for (int i = 0; i < 10; ++i) CHECK_EQ(hotp(S1, static_cast<uint64_t>(i), 6, "SHA1"), std::string(expected[i]));
    struct V { double t; const char *a, *b, *c; } vec[] = {
        {59, "94287082", "46119246", "90693936"},          {1111111109, "07081804", "68084774", "25091201"},
        {1111111111, "14050471", "67062674", "99943326"},  {1234567890, "89005924", "91819424", "93441116"},
        {2000000000, "69279037", "90698825", "38618901"},  {20000000000.0, "65353130", "77737706", "47863826"}};
    for (const V& v : vec) {
        CHECK_EQ(totp(S1, v.t, 30, 8, "SHA1"), std::string(v.a));
        CHECK_EQ(totp(S256, v.t, 30, 8, "SHA256"), std::string(v.b));
        CHECK_EQ(totp(S512, v.t, 30, 8, "SHA512"), std::string(v.c));
    }
    CHECK_EQ(checkSecret(std::string("jbsw y3dp-ehpk 3pxp===")), std::string("JBSWY3DPEHPK3PXP"));
    CHECK(throws<OtpError>([] { checkSecret(std::string("")); }));
    CHECK(throws<OtpError>([] { checkSecret(std::string("not base32!")); }));
    CHECK(throws<OtpError>([] { checkSecret(std::string(300, 'A')); }));
    CHECK(throws<OtpError>([] { validateParams("TOTP", 3, 30, "SHA1", 0); }));
    CHECK(throws<OtpError>([] { validateParams("TOTP", 11, 30, "SHA1", 0); }));
    CHECK(throws<OtpError>([] { validateParams("TOTP", 6, 0 + 3601, "SHA1", 0); }));
    CHECK(throws<OtpError>([] { validateParams("TOTP", 6, 30, "MD5", 0); }));
    CHECK(throws<OtpError>([] { validateParams("WAT", 6, 30, "SHA1", 0); }));
    CHECK(throws<OtpError>([] { validateParams(Json("TOTP"), Json("six"), Json(), Json(), Json()); }));
    OtpParams p = validateParams(Json(), Json("8"), Json(60.0 == 60.0 ? 60 : 0), Json("sha256"), Json("5"));
    CHECK_EQ(p.digits, 8);
    CHECK_EQ(p.algorithm, std::string("SHA256"));
    CHECK_EQ(p.counter, uint64_t(5));
    OtpParams big = validateParams(Json("HOTP"), Json(), Json(), Json(), Json::numberFromText("18446744073709551615"));
    CHECK_EQ(big.counter, UINT64_MAX);
    CHECK(throws<OtpError>([] { validateParams(Json("HOTP"), Json(), Json(), Json(), Json::numberFromText("18446744073709551616")); }));

    // a service object with 2FAS defaults, and the countdown rule
    Json s = makeService("Test", S1, "Test", "me");
    OtpCode c = currentCode(s, 59.0);
    CHECK_EQ(c.code, std::string("287082"));
    CHECK_EQ(c.secondsLeft, 1);
    CHECK_EQ(c.period, 30);
    c = currentCode(s, 60.0);
    CHECK_EQ(c.secondsLeft, 30);   // never 0: a new period starts
    Json h = makeService("H", S1, "H", "me", "HOTP", 6, 30, "SHA1", 3);
    c = currentCode(h, 0);
    CHECK_EQ(c.code, std::string("969429"));
    CHECK_EQ(c.secondsLeft, 0);
    Json bad = Json::object();
    bad.set("secret", Json("!!!"));
    CHECK(throws<OtpError>([&] { currentCode(bad, 0); }));

    CHECK_EQ(groupDigits("123456"), std::string("123 456"));
    CHECK_EQ(groupDigits("12345678"), std::string("1234 5678"));
    CHECK_EQ(groupDigits("ABCDE"), std::string("ABCDE"));
    CHECK_EQ(steam(S1, 59.0, 30).size(), size_t(5));

    OtpLink l = parseOtpauth("otpauth://totp/GitHub:octo%20cat?secret=jbsw y3dp&issuer=GitHub&digits=8&period=60&algorithm=SHA256");
    CHECK_EQ(l.account, std::string("octo cat"));
    CHECK_EQ(l.issuer, std::string("GitHub"));
    CHECK_EQ(l.params.digits, 8);
    CHECK_EQ(l.params.period, 60);
    CHECK(throws<OtpError>([] { parseOtpauth("https://example.com"); }));
    CHECK(throws<OtpError>([] { parseOtpauth("otpauth://totp/x"); }));
    CHECK(throws<OtpError>([] { parseOtpauth("otpauth://hotpx/x?secret=JBSWY3DPEHPK3PXP"); }));
    OtpLink st = parseOtpauth("otpauth://totp/Steam:me?secret=JBSWY3DPEHPK3PXP&issuer=Steam");
    CHECK_EQ(st.params.type, std::string("STEAM"));
}

// ---- 2FAS backups ---------------------------------------------------------
static void test_twofas() {
    fs::path dir = tempDir("2fas");
    std::vector<Json> services = {makeService("Example", S1, "Example", "me"), makeService("Caf\xC3\xA9", S256, "Caf\xC3\xA9", "x", "TOTP", 8, 60, "SHA256")};
    fs::path file = dir / "x.2fas";
    twofas::writeBackup(file, services, {}, S("p\xC3\xA4ssword \xC3\xA9 long"));
    Json content = twofas::readBackup(file);
    CHECK(twofas::isEncrypted(content));
    CHECK(content.get("services")->items().empty());
    CHECK(throws<twofas::WrongPassword>([&] { twofas::decryptBackup(content, S("nope nope nope")); }));
    Json plain = twofas::decryptBackup(content, S("p\xC3\xA4ssword \xC3\xA9 long"));
    CHECK_EQ(plain.get("services")->items().size(), size_t(2));
    CHECK_EQ(plain.get("services")->items()[1].stringOr("name"), std::string("Caf\xC3\xA9"));
    CHECK(plain.get("servicesEncrypted")->isNull());
    // damaged files are refused with a clear error, never a crash
    std::string text;
    readFile(file, text);
    for (const char* what : {"[1,2]", "{\"a\":1}", "not json", "{\"servicesEncrypted\":\"x\",\"services\":[]}"}) {
        fs::path f2 = dir / "bad.2fas";
        writeFileSynced(f2, what);
        CHECK(throws<twofas::BackupError>([&] { twofas::readBackup(f2); }));
    }
    Json broken = content;
    broken.set("servicesEncrypted", Json("AAAA:BBBB:CCCC"));
    CHECK(throws<twofas::BackupError>([&] { twofas::decryptBackup(broken, S("p\xC3\xA4ssword \xC3\xA9 long")); }));
    // a plain (unencrypted) backup passes through
    Json plainBackup = Json::parse(R"({"services":[{"name":"x","secret":"JBSWY3DPEHPK3PXP"}],"groups":[]})");
    CHECK(!twofas::isEncrypted(plainBackup));
    CHECK_EQ(twofas::decryptBackup(plainBackup, Secret()).get("services")->items().size(), size_t(1));
    fs::remove_all(dir);
}

// ---- vault ----------------------------------------------------------------
static void test_vault() {
    Vault::scryptN = 1ull << 14;   // fast keys for the tests (the bounds allow it)
    fs::path dir = tempDir("vault");
    fs::path path = dir / "vault.b2fa";
    {
        Vault v(path);
        CHECK(!v.exists());
        CHECK(throws<VaultError>([&] { v.create(S("short")); }));
        v.create(S("correct horse battery"));
        CHECK(v.exists() && v.unlocked());
        CHECK(throws<VaultError>([&] { v.create(S("correct horse battery")); }));   // already exists
        v.add(makeService("GitHub", S1, "GitHub", "me"));
        v.add(makeService("Caf\xC3\xA9 \xE2\x98\x95", S256, "Caf\xC3\xA9", "r\xC3\xA9n\xC3\xA9", "TOTP", 8, 60, "SHA256"));
        CHECK_EQ(v.services.size(), size_t(2));
        v.lock();
        CHECK(!v.unlocked());
        CHECK(v.services.empty());
    }
    {
        Vault v(path);
        CHECK(throws<WrongMasterPassword>([&] { v.unlock(S("wrong password 123")); }));
        CHECK(!v.unlocked());
        v.unlock(S("correct horse battery"));
        CHECK_EQ(v.services.size(), size_t(2));
        auto sorted = v.sortedServices();
        CHECK_EQ(sorted[0]->stringOr("name"), std::string("GitHub"));
        CHECK_EQ(sorted[1]->stringOr("name"), std::string("Caf\xC3\xA9 \xE2\x98\x95"));
        CHECK(!serviceId(*sorted[0]).empty());
        // update, counter, delete
        Json edited = *sorted[0];
        edited.set("name", Json("GitHub 2"));
        v.update(edited);
        CHECK_EQ(v.sortedServices()[0]->stringOr("name"), std::string("GitHub 2"));
        Json h = makeService("HOTP", S1, "HOTP", "me", "HOTP", 6, 30, "SHA1", 0);
        std::string hid = serviceId(v.add(h));
        v.bumpCounter(hid);
        v.bumpCounter(hid);
        uint64_t counter = 0;
        CHECK(v.find(hid)->get("otp")->get("counter")->toUInt64(counter) && counter == 2);
        // a copy of the vault exists after a change: automatic backup, then purged on delete
        v.flushBackup(0);
        CHECK(v.autoBackup().has_value());
        fs::path bak = path;
        bak += L".bak";
        CHECK(fileExists(bak));
        v.remove(hid);
        // after a delete no old copy may survive except the fresh backup written right after
        size_t copies = 0;
        for (auto& e : fs::directory_iterator(dir / "backups")) { (void)e; ++copies; }
        CHECK(copies <= 1);
        CHECK(!fileExists(bak));
        // changing the master password
        CHECK(throws<WrongMasterPassword>([&] { v.changePassword(S("not the one 12345"), S("a brand new passphrase")); }));
        CHECK(throws<VaultError>([&] { v.changePassword(S("correct horse battery"), S("tiny")); }));
        v.changePassword(S("correct horse battery"), S("a brand new passphrase"));
        v.lock();
        CHECK(throws<WrongMasterPassword>([&] { v.unlock(S("correct horse battery")); }));
        v.unlock(S("a brand new passphrase"));
        CHECK_EQ(v.services.size(), size_t(2));
        // export: long, different from the master password
        CHECK(throws<VaultError>([&] { v.exportBackup(dir / "e.2fas", S("short")); }));
        CHECK(throws<VaultError>([&] { v.exportBackup(dir / "e.2fas", S("a brand new passphrase")); }));
        v.exportBackup(dir / "e.2fas", S("an export passphrase!"));
        Json exported = twofas::decryptBackup(twofas::readBackup(dir / "e.2fas"), S("an export passphrase!"));
        CHECK_EQ(exported.get("services")->items().size(), size_t(2));
        CHECK(exported.get("services")->items()[0].get("_id") == nullptr);   // internal keys never leave
        // merge: same secret is skipped, a new one is added
        Json incoming = Json::object();
        Json list = Json::array();
        list.push(makeService("Dup", S1, "Dup", "x"));
        list.push(makeService("Fresh", "MFRGGZDFMZTWQ2LK", "Fresh", "x"));
        Json bad = Json::object();
        bad.set("secret", Json("###"));
        list.push(bad);
        incoming.set("services", std::move(list));
        auto r = v.merge(incoming);
        CHECK_EQ(r.first, 1);
        CHECK_EQ(r.second, 2);
        CHECK_EQ(v.services.size(), size_t(3));
    }
    {
        // someone else changed the file: the next save is refused and the memory is rolled back
        Vault v(path);
        v.unlock(S("a brand new passphrase"));
        size_t before = v.services.size();
        std::string text;
        readFile(path, text);
        writeFileSynced(path, text + " ");
        CHECK(throws<VaultError>([&] { v.add(makeService("Late", S1, "Late", "x")); }));
        CHECK_EQ(v.services.size(), before);
    }
    {
        // damaged and foreign files give errors, not crashes
        for (const char* junk : {"", "not json", "{}", "{\"format\":\"b2fa-vault\"}",
                                 "{\"format\":\"b2fa-vault\",\"version\":9}",
                                 "{\"format\":\"b2fa-vault\",\"version\":2,\"kdf\":{\"name\":\"scrypt\",\"n\":3,\"r\":8,\"p\":1,\"salt\":\"AAAA\"},\"nonce\":\"AAAA\",\"data\":\"AAAA\"}",
                                 "{\"format\":\"b2fa-vault\",\"version\":2,\"kdf\":{\"name\":\"scrypt\",\"n\":4294967296,\"r\":8,\"p\":1,\"salt\":\"AAAA\"},\"nonce\":\"AAAA\",\"data\":\"AAAA\"}"}) {
            fs::path f = dir / "junk.b2fa";
            writeFileSynced(f, junk);
            Vault v(f);
            CHECK(throws<VaultError>([&] { v.unlock(S("whatever password 1")); }));
        }
    }
    fs::remove_all(dir);
    Vault::scryptN = kScryptN;
}

// ---- fixes from the independent review --------------------------------------------------------------------------
static void test_review_fixes() {
    PinStore::kdfN = 1ull << 15;
    // JSON: a hostile object with very many keys parses in linear time, a repeated key keeps its place
    {
        std::string big = "{";
        for (int i = 0; i < 200000; ++i) big += (i ? ",\"k" : "\"k") + std::to_string(i) + "\":" + std::to_string(i);
        big += ",\"k5\":\"last\"}";
        auto t0 = std::chrono::steady_clock::now();
        Json j = Json::parse(big);
        double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        CHECK(seconds < 3.0);   // it was 1.5 s for 50 000 keys and grew with the square
        CHECK_EQ(j.members().size(), size_t(200000));
        CHECK_EQ(j.members()[5].first, std::string("k5"));
        CHECK_EQ(j.members()[5].second.asString(), std::string("last"));
    }
    {
        Json j = Json::parse(R"({"secret":"JBSWY3DPEHPK3PXP","list":["a","b",{"x":"y"}]})");
        j.wipe();
        CHECK(j.isNull());
        CHECK(j.members().empty() && j.items().empty());
    }

    Vault::scryptN = 1ull << 14;
    fs::path dir = tempDir("review");
    fs::path path = dir / "vault.b2fa";

    // exporting from a locked vault must not write an empty "successful" file
    {
        Vault v(path);
        v.create(S("a long master pass"));
        v.add(makeService("GitHub", S1, "GitHub", "me"));
        v.lock();
        CHECK(throws<VaultError>([&] { v.exportBackup(dir / "locked.2fas", S("an export passphrase!")); }));
        CHECK(!fileExists(dir / "locked.2fas"));
    }

    // a backup is refused when the vault file was changed behind our back (it could copy over good backups)
    {
        Vault v(path);
        v.unlock(S("a long master pass"));
        std::string text;
        readFile(path, text);
        writeFileSynced(path, text + " ");
        CHECK(throws<VaultError>([&] { v.autoBackup(); }));
        writeFileSynced(path, text);   // restore the bytes (the signature still differs: the file time moved)
        v.lock();
    }

    // creating a vault next to the copies of an earlier one keeps them, in a folder of their own
    {
        Vault v(path);
        v.unlock(S("a long master pass"));
        v.add(makeService("Second", "MFRGGZDFMZTWQ2LK", "Second", "me"));   // leaves a .bak
        v.flushBackup(0);
        CHECK(v.autoBackup().has_value());
        v.lock();
        size_t before = 0;
        for (auto& e : fs::directory_iterator(dir / "backups")) { (void)e; ++before; }
        CHECK(before >= 1);
        fs::path bak = path;
        bak += L".bak";
        CHECK(fileExists(bak));
        fs::remove(path);   // the vault file got lost
        Vault fresh(path);
        fresh.create(S("a different master pass"));
        CHECK(!fresh.keptCopiesDir().empty());
        CHECK(fs::exists(fresh.keptCopiesDir() / path.filename().concat(L".bak")));
        for (int i = 0; i < 14; ++i) fresh.add(makeService("N" + std::to_string(i), S1, "N", "x"));   // rotation must not touch them
        CHECK(fs::exists(fresh.keptCopiesDir() / path.filename().concat(L".bak")));
        size_t kept = 0;
        for (auto& e : fs::directory_iterator(fresh.keptCopiesDir())) { (void)e; ++kept; }
        CHECK(kept >= 2);   // the .bak and at least one automatic backup
        // and they still open with the OLD password
        Vault old(fresh.keptCopiesDir() / path.filename().concat(L".bak"));
        old.unlock(S("a long master pass"));
        CHECK(old.services.size() >= 1);
        old.lock();
        fresh.lock();
    }

    // a vault that could not be read back is never written: the size limit and the per-account limit
    {
        fs::path p2 = dir / "big.b2fa";
        Vault v(p2);
        v.create(S("a long master pass"));
        Vault::maxFileBytes = 60000;
        Json fat = makeService("Fat", S1, "Fat", "x");
        fat.set("extra", Json(std::string(80000, 'x')));
        CHECK(throws<VaultError>([&] { v.add(fat); }));
        CHECK(v.services.empty());   // rolled back
        Vault::maxFileBytes = 192ull * 1024 * 1024;
        // an imported entry with a huge unknown field is skipped, not kept
        Json incoming = Json::object(), list = Json::array();
        Json heavy = makeService("Heavy", S1, "Heavy", "x");
        heavy.set("extra", Json(std::string(70000, 'y')));
        list.push(heavy);
        list.push(makeService("Light", S256, "Light", "x"));
        incoming.set("services", std::move(list));
        auto r = v.merge(incoming);
        CHECK_EQ(r.first, 1);
        CHECK_EQ(r.second, 1);
        v.lock();
    }
    fs::remove_all(dir);
    Vault::scryptN = kScryptN;

    // PIN: a text that cannot be a PIN costs no attempt, a busy file is not a damaged file
    {
        fs::path pdir = tempDir("pinreview");
        PinStore pins(pdir / "pin.b2fa");
        pins.enable(S("427103"), S("master password 123"));
        for (int i = 0; i < 12; ++i) {
            CHECK(throws<PinError>([&] { pins.unlock(S("")); }));
            CHECK(throws<PinError>([&] { pins.unlock(S("12")); }));
        }
        CHECK(pins.enabled());
        CHECK(pins.unlock(S("427103")).equals(S("master password 123")));
        // the file held open without sharing, like a scanner would: unlock fails but keeps the file
        HANDLE hold = CreateFileW((pdir / "pin.b2fa").c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        CHECK(hold != INVALID_HANDLE_VALUE);
        CHECK(throws<PinError>([&] { pins.unlock(S("427103")); }));
        if (hold != INVALID_HANDLE_VALUE) CloseHandle(hold);
        CHECK(pins.enabled());
        CHECK(pins.unlock(S("427103")).equals(S("master password 123")));
        fs::remove_all(pdir);
    }
}

// ---- fixes from the independent security audit -------------------------------------------------------------------------
static std::string readAll(const fs::path& p) {
    std::string t;
    readFile(p, t);
    return t;
}

static void test_audit_fixes() {
    PinStore::kdfN = 1ull << 15;
    fs::path dir = tempDir("audit");

    // a PIN is 6 to 10 digits, to set and to unlock
    {
        PinStore pins(dir / "pin.b2fa");
        CHECK(throws<PinError>([&] { pins.enable(S("4271"), S("master password 123")); }));          // too short
        CHECK(throws<PinError>([&] { pins.enable(S("12345678901"), S("master password 123")); }));   // too long
        pins.enable(S("1234567890"), S("master password 123"));
        CHECK(pins.unlock(S("1234567890")).equals(S("master password 123")));
        for (int i = 0; i < 12; ++i) CHECK(throws<PinError>([&] { pins.unlock(S("4271")); }));       // too short to be a PIN: no attempt used
        CHECK(pins.enabled());
        Json doc = Json::parse(readAll(dir / "pin.b2fa"));
        uint64_t v = 0, n = 0, left = 0;
        CHECK(doc.get("version")->toUInt64(v) && v == 1);
        CHECK(doc.get("n")->toUInt64(n) && n == (1ull << 15));   // the cost is stored in the file
        CHECK(doc.get("attempts_left")->toUInt64(left) && left == 5);
        // files of earlier development builds (no cost in the file, or another version) are damaged files: removed
        Json old = doc;
        old.set("version", Json(2));
        writeFileSynced(dir / "pin.b2fa", old.dump());
        CHECK(throws<PinDisabled>([&] { pins.unlock(S("1234567890")); }));
        CHECK(!pins.enabled());
    }
    // a file cannot choose the cost of the key derivation (it is untrusted input): absurd settings are a damaged file
    {
        PinStore pins(dir / "pin.b2fa");
        pins.enable(S("427103"), S("master password 123"));
        Json doc = Json::parse(readAll(dir / "pin.b2fa"));
        for (uint64_t badN : {uint64_t(1) << 30, uint64_t(3), uint64_t(1) << 12}) {
            Json bad = doc;
            bad.set("n", Json(badN));
            writeFileSynced(dir / "pin.b2fa", bad.dump());
            CHECK(throws<PinDisabled>([&] { pins.unlock(S("427103")); }));
            CHECK(!pins.enabled());
            pins.enable(S("427103"), S("master password 123"));
        }
        Json odd = doc;
        odd.set("r", Json(16));
        writeFileSynced(dir / "pin.b2fa", odd.dump());
        CHECK(throws<PinDisabled>([&] { pins.unlock(S("427103")); }));
        pins.disable();
    }

    // JSON: a document with an absurd number of values is refused, not parsed into gigabytes
    {
        std::string many = "[";
        for (int i = 0; i < 1600000; ++i) many += i ? ",0" : "0";
        many += "]";
        CHECK(throws<JsonError>([&] { Json::parse(many); }));
        std::string fine = "[";
        for (int i = 0; i < 1000; ++i) fine += i ? ",0" : "0";
        fine += "]";
        CHECK_EQ(Json::parse(fine).items().size(), size_t(1000));
    }
    // a backup file over the size cap is refused before it is read
    {
        fs::path big = dir / "big.2fas";
        std::string junk(17u * 1024 * 1024, ' ');
        writeFileSynced(big, junk);
        CHECK(throws<twofas::BackupError>([&] { twofas::readBackup(big); }));
    }
    // json strings and keys keep their content through copies and moves (the destructor wipes buffers, not values)
    {
        Json a = Json::parse(R"({"secret":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP","list":["abc","a much longer string than the small buffer"]})");
        Json b = a;
        Json c = std::move(a);
        a = Json();
        CHECK_EQ(b.get("secret")->asString(), std::string("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"));
        CHECK_EQ(c.dump(), b.dump());
        c = b;
        b.wipe();
        CHECK_EQ(c.get("list")->items()[1].asString(), std::string("a much longer string than the small buffer"));
    }
    // the export of an account with thousands of fields is linear, and the internal keys do not leave
    {
        Vault::scryptN = 1ull << 14;
        Vault v(dir / "many.b2fa");
        v.create(S("a long master pass"));
        Json fat = makeService("Fat", S1, "Fat", "x");
        for (int i = 0; i < 6000; ++i) fat.set("k" + std::to_string(i), Json(i));
        v.add(fat);
        auto t0 = std::chrono::steady_clock::now();
        auto list = v.exportableServices();
        double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        CHECK(seconds < 1.0);
        CHECK_EQ(list.size(), size_t(1));
        CHECK(list[0].get("_id") == nullptr);
        CHECK(list[0].get("k5999") != nullptr);
        v.lock();
        Vault::scryptN = kScryptN;
    }
    // a vault file that changed between our read and our signature is noticed (the signature is taken first)
    {
        Vault::scryptN = 1ull << 14;
        Vault v(dir / "sig.b2fa");
        v.create(S("a long master pass"));
        v.add(makeService("A", S1, "A", "x"));
        v.lock();
        Vault w(dir / "sig.b2fa");
        w.unlock(S("a long master pass"));
        std::string text = readAll(dir / "sig.b2fa");
        writeFileSynced(dir / "sig.b2fa", text + " ");
        CHECK(throws<VaultError>([&] { w.add(makeService("B", S256, "B", "x")); }));
        w.lock();
        Vault::scryptN = kScryptN;
    }
    // leftovers of an interrupted backup copy go with the other old copies
    {
        Vault::scryptN = 1ull << 14;
        fs::path p = dir / "purge.b2fa";
        Vault v(p);
        v.create(S("a long master pass"));
        v.add(makeService("A", S1, "A", "x"));
        fs::create_directories(dir / "backups");
        writeFileSynced(dir / "backups" / "B-2FA-auto-20260101-000000.tmp", "leftover");
        v.add(makeService("B", S256, "B", "x"));
        v.remove(serviceId(v.services[0]));   // a delete purges every copy
        CHECK(!fileExists(dir / "backups" / "B-2FA-auto-20260101-000000.tmp"));
        v.lock();
        Vault::scryptN = kScryptN;
    }
    fs::remove_all(dir);
}

// ---- binding the vault to this PC, longer passwords, a stronger key derivation ----------------------------------------------
static void test_binding() {
    Vault::scryptN = 1ull << 14;
    fs::path dir = tempDir("bind");
    fs::path path = dir / "vault.b2fa";
    const char* pw = "a long master pass";
    std::string id;

    // limits: 16 characters to create, 16 to export, the full key derivation by default
    {
        CHECK_EQ(kMinMasterChars, size_t(16));
        CHECK_EQ(kMinExportChars, size_t(16));
        CHECK_EQ(kScryptN, uint64_t(1) << 18);
        Vault v(dir / "short.b2fa");
        CHECK(throws<VaultError>([&] { v.create(S("fifteen chars!!")); }));      // 15 characters
        CHECK(!fileExists(devicekey::pathFor(dir / "short.b2fa")));              // and no key was left behind
        v.create(S("sixteen chars!!!!"));                                          // 16 characters
        v.add(makeService("A", S1, "A", "x"));
        CHECK(throws<VaultError>([&] { v.exportBackup(dir / "e.2fas", S("fifteen chars!!")); }));
        v.exportBackup(dir / "e.2fas", S("sixteen chars!!!!x"));
        v.lock();
    }
    // a new vault is bound by default: a device key next to it, a flag in the (authenticated) header
    {
        Vault v(path);
        v.create(S(pw));
        CHECK(v.bound());
        CHECK(fileExists(devicekey::pathFor(path)));
        CHECK(!v.deviceId().empty());
        id = v.deviceId();
        v.add(makeService("A", S1, "A", "x"));
        v.lock();
        Json doc = Json::parse(readAll(path));
        CHECK(doc.get("bound") && doc.get("bound")->asBool());
        Vault w(path);
        w.unlock(S(pw));
        CHECK(w.bound());
        CHECK_EQ(w.deviceId(), id);
        CHECK_EQ(w.services.size(), size_t(1));
        // changing the master password keeps the binding and the device key
        w.changePassword(S(pw), S("another long passphrase"));
        w.lock();
        Vault x(path);
        CHECK(throws<WrongMasterPassword>([&] { x.unlock(S(pw)); }));
        x.unlock(S("another long passphrase"));
        CHECK(x.bound() && x.deviceId() == id);
        x.lock();
    }
    // the vault file alone does not open: copied elsewhere, with the right password, it says why
    {
        fs::path other = dir / "elsewhere";
        fs::create_directories(other);
        fs::copy_file(path, other / "vault.b2fa");
        Vault v(other / "vault.b2fa");
        bool clear = false, wrongPassword = false;
        try {
            v.unlock(S("another long passphrase"));
        } catch (const WrongMasterPassword&) {
            wrongPassword = true;
        } catch (const VaultError& e) {
            clear = std::string(e.what()).find("bound to the PC") != std::string::npos;
        }
        CHECK(clear && !wrongPassword);
        CHECK(!v.unlocked());
        // a damaged device key says the same, and the vault stays untouched
        writeFileSynced(other / "device.b2fa", "{not json");
        clear = false;
        try { v.unlock(S("another long passphrase")); } catch (const VaultError& e) { clear = std::string(e.what()).find("bound to the PC") != std::string::npos; }
        CHECK(clear);
        // another device key (even a good one) does not decrypt it
        devicekey::create(other / "device.b2fa");
        CHECK(throws<WrongMasterPassword>([&] { v.unlock(S("another long passphrase")); }));
    }
    // the flag cannot be dropped to dodge the device key: the header is authenticated, the key would differ anyway
    {
        Json doc = Json::parse(readAll(path));
        doc.erase("bound");
        fs::path forged = dir / "forged" / "vault.b2fa";
        fs::create_directories(forged.parent_path());
        writeFileSynced(forged, doc.dump());
        fs::copy_file(devicekey::pathFor(path), devicekey::pathFor(forged), fs::copy_options::overwrite_existing);
        Vault v(forged);
        CHECK(throws<WrongMasterPassword>([&] { v.unlock(S("another long passphrase")); }));
        doc.set("bound", Json("yes"));
        writeFileSynced(forged, doc.dump());
        CHECK(throws<VaultError>([&] { v.unlock(S("another long passphrase")); }));
    }
    // a vault that is not bound opens from any folder
    {
        fs::path a = dir / "free" / "vault.b2fa";
        fs::create_directories(a.parent_path());
        Vault v(a);
        v.create(S(pw), false);
        CHECK(!v.bound());
        CHECK(v.deviceId().empty());
        CHECK(!fileExists(devicekey::pathFor(a)));
        v.add(makeService("Free", S256, "Free", "x"));
        v.lock();
        fs::path b = dir / "moved";
        fs::create_directories(b);
        fs::copy_file(a, b / "vault.b2fa");
        Vault w(b / "vault.b2fa");
        w.unlock(S(pw));
        CHECK(!w.bound());
        CHECK_EQ(w.services.size(), size_t(1));
        w.lock();
    }
    // a new vault where an old one had its device key: that key goes with the old copies, the new one is new
    {
        Vault old(path);
        old.unlock(S("another long passphrase"));
        old.add(makeService("B", S256, "B", "x"));
        old.lock();
        fs::remove(path);
        Vault fresh(path);
        fresh.create(S("yet another long pass"));
        CHECK(!fresh.keptCopiesDir().empty());
        CHECK(fileExists(fresh.keptCopiesDir() / "device.b2fa"));
        CHECK(fresh.bound() && fresh.deviceId() != id);
        fresh.lock();
        // the earlier vault copy still opens with ITS key, which was kept beside it
        fs::path bak = fresh.keptCopiesDir() / "vault.b2fa.bak";
        CHECK(fileExists(bak));
        Vault again(bak);
        again.unlock(S("another long passphrase"));
        CHECK(again.bound() && again.deviceId() == id);
        again.lock();
    }
    // settings: which vault has had its recovery export
    {
        Settings s(dir / "settings.json");
        CHECK(s.recoveryExportedFor().empty());
        s.setRecoveryExportedFor("0123456789abcdef");
        CHECK_EQ(Settings(dir / "settings.json").recoveryExportedFor(), std::string("0123456789abcdef"));
        Json doc = Json::parse(readAll(dir / "settings.json"));
        doc.set("recovery_exported_for", Json(std::string(200, 'x')));   // absurd: ignored
        writeFileSynced(dir / "settings.json", doc.dump());
        CHECK(Settings(dir / "settings.json").recoveryExportedFor().empty());
    }
    fs::remove_all(dir);
    Vault::scryptN = kScryptN;
}

// ---- the brake on guessing at the unlock screen ------------------------------------------------------------------------------------
static int64_t g_fakeNow = 1000000;
static int64_t fakeClock() { return g_fakeNow; }

static void test_unlock_guard() {
    fs::path dir = tempDir("guard");
    fs::path file = dir / "unlock-guard.json";
    UnlockGuard::clock = &fakeClock;
    g_fakeNow = 1700000000000LL;
    {
        UnlockGuard g(file, 3, 30);
        CHECK_EQ(g.waitSeconds(), 0);
        CHECK_EQ(g.triesBeforeWait(), 3);
        g.failure();
        g.failure();
        CHECK_EQ(g.waitSeconds(), 0);          // two wrong tries: still free
        CHECK_EQ(g.triesBeforeWait(), 1);
        g.failure();                           // the third: the waiting starts
        CHECK_EQ(g.waitSeconds(), 30);
        CHECK_EQ(g.triesBeforeWait(), 0);
        g_fakeNow += 10000;
        CHECK_EQ(g.waitSeconds(), 20);
        g_fakeNow += 500;
        CHECK_EQ(g.waitSeconds(), 20);         // 19.5 s left rounds up: never says 0 too early
        g_fakeNow += 19500;
        CHECK_EQ(g.waitSeconds(), 0);          // 30 s after the wrong try: allowed
        g.failure();                           // wrong again: another 30 s, not a fresh set of free tries
        CHECK_EQ(g.waitSeconds(), 30);
    }
    {
        // closing and reopening the program gives nothing back
        UnlockGuard again(file, 3, 30);
        CHECK_EQ(again.failures(), 4);
        CHECK_EQ(again.waitSeconds(), 30);
        g_fakeNow += 31000;
        CHECK_EQ(again.waitSeconds(), 0);
        again.success();                       // a right password forgives everything
        CHECK_EQ(again.failures(), 0);
        CHECK(!fileExists(file));
        CHECK_EQ(UnlockGuard(file, 3, 30).failures(), 0);
    }
    {
        // a clock set back must not freeze the wait for hours
        UnlockGuard g(file, 1, 30);
        g.failure();
        g_fakeNow -= 3600000;
        CHECK(g.waitSeconds() <= 30);
        g.success();
    }
    {
        // a damaged or hostile file is a clean start, and the settings are kept in range
        writeFileSynced(file, "{broken");
        CHECK_EQ(UnlockGuard(file, 3, 30).failures(), 0);
        writeFileSynced(file, "{\"failures\": -5, \"last_failure_ms\": 1}");
        CHECK_EQ(UnlockGuard(file, 3, 30).failures(), 0);
        writeFileSynced(file, "{\"failures\": \"many\", \"last_failure_ms\": 1}");
        CHECK_EQ(UnlockGuard(file, 3, 30).failures(), 0);
        UnlockGuard odd(file, 99, 1);
        CHECK_EQ(odd.freeAttempts(), 10);
        CHECK_EQ(odd.delaySeconds(), 5);
        UnlockGuard odd2(file, 0, 999999);
        CHECK_EQ(odd2.freeAttempts(), 1);
        CHECK_EQ(odd2.delaySeconds(), 3600);
        removeFile(file);
    }
    {
        // settings: defaults, a user's edit of settings.json, and nonsense that is ignored
        Settings s(dir / "settings.json");
        CHECK_EQ(s.unlockFreeAttempts(), 3);
        CHECK_EQ(s.unlockDelaySeconds(), 30);
        s.setSecureKeypad(true);   // saving writes the two numbers so the user can see and change them
        Json doc = Json::parse(readAll(dir / "settings.json"));
        CHECK(doc.get("unlock_free_attempts") != nullptr && doc.get("unlock_delay_seconds") != nullptr);
        doc.set("unlock_free_attempts", Json(5));
        doc.set("unlock_delay_seconds", Json(60));
        writeFileSynced(dir / "settings.json", doc.dump());
        CHECK_EQ(Settings(dir / "settings.json").unlockFreeAttempts(), 5);
        CHECK_EQ(Settings(dir / "settings.json").unlockDelaySeconds(), 60);
        doc.set("unlock_free_attempts", Json(0));
        doc.set("unlock_delay_seconds", Json(1));
        writeFileSynced(dir / "settings.json", doc.dump());
        CHECK_EQ(Settings(dir / "settings.json").unlockFreeAttempts(), 3);
        CHECK_EQ(Settings(dir / "settings.json").unlockDelaySeconds(), 30);
    }
    UnlockGuard::clock = &nowMs;
    fs::remove_all(dir);
}

// ---- the logo pack: the user's folder first, then the one next to the program --------------------------------------------------
static void test_icon_pack_location() {
    fs::path home = tempDir("iconhome");
    fs::path shipped = b2::paths::installedIconsDir();
    CHECK(!shipped.empty());
    bool madeShipped = !fs::exists(shipped);
    fs::create_directories(shipped);
    SetEnvironmentVariableW(L"B2FA_HOME", home.wstring().c_str());
    {
        IconStore none;   // no pack anywhere
        CHECK(!none.available() || fs::exists(shipped / L"services.json"));
    }
    bool hadShipped = fs::exists(shipped / L"services.json");
    if (!hadShipped) writeFileSynced(shipped / L"services.json", "[]");
    {
        IconStore fromProgram;
        CHECK(fromProgram.available());   // the pack that comes with the program
    }
    fs::create_directories(home / L"icons");
    writeFileSynced(home / L"icons" / L"services.json", "[]");
    {
        IconStore fromUser;
        CHECK(fromUser.available());      // the user's own pack is found too (and wins; both exist now)
    }
    fs::remove(home / L"icons" / L"services.json");
    {
        IconStore backToProgram;
        CHECK(backToProgram.available());
    }
    if (!hadShipped) fs::remove(shipped / L"services.json");
    if (madeShipped) fs::remove(shipped);
    SetEnvironmentVariableW(L"B2FA_HOME", nullptr);
    fs::remove_all(home);
}

// ---- PIN, settings, keypad ---------------------------------------------------
static void test_pin_settings_keypad() {
    PinStore::kdfN = 1ull << 15;   // fast keys for the tests (the bounds allow it)
    fs::path dir = tempDir("pin");
    PinStore pins(dir / "pin.b2fa");
    CHECK(!pins.enabled());
    CHECK(throws<PinDisabled>([&] { pins.unlock(S("1234")); }));
    CHECK(throws<PinError>([&] { pins.enable(S("12"), S("master password 123")); }));       // too short
    CHECK(throws<PinError>([&] { pins.enable(S("12ab"), S("master password 123")); }));     // not digits
    pins.enable(S("427103"), S("master pÃ¤ssword 123"));
    CHECK(pins.enabled());
    Secret back = pins.unlock(S("427103"));
    CHECK(back.equals(S("master pÃ¤ssword 123")));
    // a wrong PIN is counted before the try, the right one resets the count, five wrong ones wipe the file
    for (int expected : {4, 3}) {
        bool ok = false;
        try { pins.unlock(S("000000")); } catch (const WrongPin& e) { ok = e.attemptsLeft == expected; }
        CHECK(ok);
    }
    CHECK(pins.unlock(S("427103")).equals(S("master pÃ¤ssword 123")));   // reset to 5
    for (int i = 0; i < 4; ++i) CHECK(throws<WrongPin>([&] { pins.unlock(S("000000")); }));
    CHECK(throws<PinDisabled>([&] { pins.unlock(S("000000")); }));   // the fifth wrong one
    CHECK(!pins.enabled());
    // a damaged file is removed, not trusted
    writeFileSynced(dir / "pin.b2fa", "{broken");
    CHECK(throws<PinDisabled>([&] { pins.unlock(S("427103")); }));
    CHECK(!pins.enabled());

    Settings s(dir / "settings.json");
    CHECK(!s.secureKeypad());   // off by default: the PIN is typed on the keyboard, the keypad is on demand
    s.setSecureKeypad(true);
    CHECK(Settings(dir / "settings.json").secureKeypad());
    writeFileSynced(dir / "settings.json", "{\"secure_keypad\": \"yes\"}");
    CHECK(!Settings(dir / "settings.json").secureKeypad());   // a wrong type is ignored
    writeFileSynced(dir / "settings.json", "garbage");
    CHECK(!Settings(dir / "settings.json").secureKeypad());

    // the shuffle: every key present once, and the order changes
    std::wstring digits = L"0123456789";
    std::vector<std::wstring> seen;
    for (int i = 0; i < 30; ++i) {
        auto v = keypad::shuffled(digits);
        std::wstring s2(v.begin(), v.end());
        std::wstring sorted = s2;
        std::sort(sorted.begin(), sorted.end());
        CHECK(sorted == digits);
        seen.push_back(s2);
    }
    std::sort(seen.begin(), seen.end());
    CHECK(std::unique(seen.begin(), seen.end()) - seen.begin() > 25);   // 30 draws, nearly all different
    size_t counts[5] = {};
    for (int i = 0; i < 5000; ++i) ++counts[keypad::randomBelow(5)];
    for (size_t c : counts) CHECK(c > 800 && c < 1200);                  // no visible bias
    CHECK_EQ(keypad::kSymbols.size(), size_t(42));
    fs::remove_all(dir);
}

// ---- files made by the earlier Python prototype -------------------------------------
static void test_python_interop() {
    fs::path vectors = VECTORS_DIR;
    fs::path dir = tempDir("interop");
    fs::path path = dir / "vault.b2fa";
    fs::copy_file(vectors / "py_vault.b2fa", path);
    Vault v(path);
    CHECK(throws<WrongMasterPassword>([&] { v.unlock(S("not the python password")); }));
    v.unlock(S("python-made-pass-123"));
    CHECK_EQ(v.services.size(), size_t(4));
    // the 2FAS file made by the Python prototype
    Json exported = twofas::decryptBackup(twofas::readBackup(vectors / "py_export.2fas"), S("python-export-pass"));
    CHECK_EQ(exported.get("services")->items().size(), size_t(4));
    // the same codes as Python computed at fixed times
    std::string text;
    readFile(vectors / "py_expected.json", text);
    Json expected = Json::parse(text);
    int compared = 0;
    for (Json* s : v.sortedServices()) {
        for (double now : {1700000000.0, 1700000029.5, 1234567890.0}) {
            char key[256];
            std::snprintf(key, sizeof(key), "%s@%.1f", s->stringOr("name").c_str(), now);
            const Json* e = expected.get(key);
            CHECK(e != nullptr);
            if (!e) continue;
            OtpCode c = currentCode(*s, now);
            CHECK_EQ(c.code, e->items()[0].asString());
            int64_t left = 0, period = 0;
            e->items()[1].toInt64(left);
            e->items()[2].toInt64(period);
            CHECK_EQ(static_cast<int64_t>(c.secondsLeft), left);
            CHECK_EQ(static_cast<int64_t>(c.period), period);
            ++compared;
        }
    }
    CHECK_EQ(compared, 12);
    // a vault written by this program opens again after the upgrade path (N lowered to raised)
    v.save();
    v.lock();
    v.unlock(S("python-made-pass-123"));
    CHECK_EQ(v.services.size(), size_t(4));
    fs::remove_all(dir);
}

// `b2tests --emit DIR` writes a vault and a .2fas made by this program, so the Python prototype (or
// any other reader) can check it opens them. Passwords: cpp-made-pass-1234 and cpp-export-pass-12.
static int emitInteropFiles(const fs::path& dir) {
    fs::create_directories(dir);
    fs::path path = dir / "cpp_vault.b2fa";
    fs::remove(path);
    Vault v(path);
    v.create(S("cpp-made-pass-1234"), false);
    v.add(makeService("GitHub", "JBSWY3DPEHPK3PXP", "GitHub", "octocat"));
    v.add(makeService("Caf\xC3\xA9 \xE2\x98\x95", "GEZDGNBVGY3TQOJQ", "Caf\xC3\xA9", "r\xC3\xA9n\xC3\xA9", "TOTP", 8, 60, "SHA256"));
    v.add(makeService("Counter", "MFRGGZDFMZTWQ2LK", "Counter", "me", "HOTP", 6, 30, "SHA1", 7));
    v.exportBackup(dir / "cpp_export.2fas", S("cpp-export-pass-12"));
    std::printf("written to %s\n", dir.string().c_str());
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 3 && std::string(argv[1]) == "--emit") return emitInteropFiles(argv[2]);
    struct T { const char* name; std::function<void()> fn; } tests[] = {
        {"encodings", test_encodings}, {"secret", test_secret}, {"json", test_json}, {"crypto", test_crypto},
        {"otp", test_otp},           {"twofas", test_twofas},   {"vault", test_vault}, {"pin, settings, keypad", test_pin_settings_keypad}, {"review fixes", test_review_fixes}, {"audit fixes", test_audit_fixes}, {"binding", test_binding}, {"unlock guard", test_unlock_guard}, {"icon pack location", test_icon_pack_location},
        {"python interop", test_python_interop}};
    for (auto& t : tests) {
        g_test = t.name;
        int before = g_failed;
        try {
            t.fn();
        } catch (const std::exception& e) {
            ++g_failed;
            std::printf("  EXCEPTION [%s]: %s\n", t.name, e.what());
        }
        std::printf("%-16s %s\n", t.name, g_failed == before ? "ok" : "FAILED");
    }
    std::printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
