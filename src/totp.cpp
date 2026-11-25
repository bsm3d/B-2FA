// B-2FA
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.1
// Fonction du fichier : Implements HOTP, TOTP and Steam Guard one-time codes and parsing of otpauth links with Python-like integer handling.

// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "totp.h"

#include <cmath>
#include <map>

#include "crypto.h"

namespace b2 {

namespace {

const char kSteamAlphabet[] = "23456789BCDFGHJKMNPQRTVWXY";
constexpr size_t kMaxSecretChars = 256;

// A whole number as Python's int() reads it: sign and magnitude, with an overflow flag.
struct Whole {
    bool neg = false;
    uint64_t mag = 0;
    bool overflow = false;
};

bool addDigit(Whole& w, char c) {
    uint64_t d = static_cast<uint64_t>(c - '0');
    if (w.mag > (UINT64_MAX - d) / 10) { w.overflow = true; return true; }
    w.mag = w.mag * 10 + d;
    return true;
}

// Falsy values (null, 0, "", false) give `def`, like Python's `x or def`.
Whole toWhole(const Json& v, uint64_t def) {
    Whole w;
    w.mag = def;
    switch (v.type()) {
        case Json::Type::Null: return w;
        case Json::Type::Bool:
            if (!v.asBool()) return w;
            w.mag = 1;
            return w;
        case Json::Type::Number: {
            const std::string& t = v.numberText();
            if (v.isInteger()) {
                Whole r;
                size_t i = 0;
                if (t[0] == '-') { r.neg = true; i = 1; }
                for (; i < t.size(); ++i) addDigit(r, t[i]);
                if (r.mag == 0 && !r.overflow) return w;  // zero is falsy
                return r;
            }
            double d;
            if (!v.toDouble(d)) throw OtpError("Digits, period and counter must be whole numbers");
            d = std::trunc(d);
            if (d == 0) return w;
            Whole r;
            r.neg = d < 0;
            if (std::fabs(d) >= 1.8446744073709552e19) r.overflow = true;
            else r.mag = static_cast<uint64_t>(std::fabs(d));
            return r;
        }
        case Json::Type::String: {
            std::string t = trim(v.asString());
            if (t.empty()) return w;  // "" is falsy
            Whole r;
            size_t i = 0;
            if (t[0] == '+' || t[0] == '-') { r.neg = t[0] == '-'; i = 1; }
            if (i >= t.size()) throw OtpError("Digits, period and counter must be whole numbers");
            for (; i < t.size(); ++i) {
                if (t[i] < '0' || t[i] > '9') throw OtpError("Digits, period and counter must be whole numbers");
                addDigit(r, t[i]);
            }
            if (r.mag == 0 && !r.overflow) {
                // "0" is a non-empty string: int("0") is 0, and 0 is then used as is
                r.mag = 0;
                return r;
            }
            return r;
        }
        default:
            throw OtpError("Digits, period and counter must be whole numbers");
    }
}

int smallInt(const Whole& w, int lo, int hi, const char* msg) {
    if (w.overflow || (w.neg && w.mag != 0) || w.mag < static_cast<uint64_t>(lo) || w.mag > static_cast<uint64_t>(hi))
        throw OtpError(msg);
    return static_cast<int>(w.mag);
}

HashAlg algOf(const std::string& a) {
    if (a == "SHA1") return HashAlg::Sha1;
    if (a == "SHA256") return HashAlg::Sha256;
    return HashAlg::Sha512;
}

std::string cleanSecretText(const std::string& s) {
    std::string out;
    out.reserve(s.size());   // no regrowth: it would leave smaller copies of the secret in freed memory
    for (char c : s) {
        if (c == ' ' || c == '-' || c == '\t' || c == '\r' || c == '\n') continue;
        out += (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
    }
    while (!out.empty() && out.back() == '=') out.pop_back();
    return out;
}

struct WipeAtExit {
    std::string& s;
    ~WipeAtExit() { wipeString(s); }
};

Bytes secretKey(const std::string& secret) {
    std::string cleaned = cleanSecretText(secret);
    WipeAtExit wipe{cleaned};
    if (cleaned.empty()) throw OtpError("The secret is empty");
    size_t padded = cleaned.size() + ((8 - cleaned.size() % 8) % 8);
    if (padded > kMaxSecretChars) throw OtpError("The secret is too long");
    Bytes key;
    if (!base32Decode(cleaned, key)) throw OtpError("Invalid secret (not base32)");
    return key;
}

Bytes counterBytes(uint64_t c) {
    Bytes b(8);
    for (int i = 7; i >= 0; --i) { b[static_cast<size_t>(i)] = static_cast<uint8_t>(c & 0xFF); c >>= 8; }
    return b;
}

uint32_t truncate(const Bytes& mac) {
    size_t offset = mac.back() & 0x0F;
    return ((static_cast<uint32_t>(mac[offset]) << 24) | (static_cast<uint32_t>(mac[offset + 1]) << 16) |
            (static_cast<uint32_t>(mac[offset + 2]) << 8) | static_cast<uint32_t>(mac[offset + 3])) & 0x7FFFFFFFu;
}

std::string percentDecode(std::string_view s, bool plusIsSpace) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '%' && i + 2 < s.size()) {
            auto hv = [](char h) -> int {
                if (h >= '0' && h <= '9') return h - '0';
                if (h >= 'a' && h <= 'f') return h - 'a' + 10;
                if (h >= 'A' && h <= 'F') return h - 'A' + 10;
                return -1;
            };
            int a = hv(s[i + 1]), b = hv(s[i + 2]);
            if (a >= 0 && b >= 0) { out += static_cast<char>(a * 16 + b); i += 2; continue; }
        }
        out += (plusIsSpace && c == '+') ? ' ' : c;
    }
    return sanitizeUtf8(out);
}

}  // namespace

std::string checkSecret(const std::string& secret) {
    secretKey(secret);
    return cleanSecretText(secret);
}

std::string checkSecret(const Json& secret) {
    if (!secret.isString()) throw OtpError("The secret is missing");
    return checkSecret(secret.asString());
}

OtpParams validateParams(const Json& type, const Json& digits, const Json& period, const Json& algorithm,
                         const Json& counter) {
    OtpParams p;
    if ((!type.isNull() && !type.isString()) || (!algorithm.isNull() && !algorithm.isString()))
        throw OtpError("Unknown token type or algorithm");
    std::string kind = type.isString() && !type.asString().empty() ? upperAscii(type.asString()) : "TOTP";
    if (kind != "TOTP" && kind != "HOTP" && kind != "STEAM")
        throw OtpError("Unknown token type: " + truncateChars(kind, 20));
    std::string algo = algorithm.isString() && !algorithm.asString().empty() ? upperAscii(algorithm.asString()) : "SHA1";
    if (algo != "SHA1" && algo != "SHA256" && algo != "SHA512")
        throw OtpError("Unsupported algorithm: " + truncateChars(algo, 20));
    Whole d = toWhole(digits, 6), per = toWhole(period, 30), cnt = toWhole(counter, 0);
    p.type = kind;
    p.algorithm = algo;
    p.digits = smallInt(d, kMinDigits, kMaxDigits, "Digits must be between 4 and 10");
    p.period = smallInt(per, kMinPeriod, kMaxPeriod, "Period must be between 1 and 3600 seconds");
    if (cnt.overflow || (cnt.neg && cnt.mag != 0)) throw OtpError("Counter out of range");
    p.counter = cnt.mag;
    return p;
}

OtpParams validateParams(const std::string& type, int digits, int period, const std::string& algorithm,
                         uint64_t counter) {
    return validateParams(Json(type), Json(digits), Json(period), Json(algorithm), Json(counter));
}

OtpParams otpParams(const Json& service) {
    static const Json kNull;
    const Json* otp = service.isObject() ? service.get("otp") : nullptr;
    if (!otp || !otp->isObject()) otp = nullptr;
    auto field = [&](const char* k) -> const Json& {
        const Json* v = otp ? otp->get(k) : nullptr;
        return v ? *v : kNull;
    };
    return validateParams(field("tokenType"), field("digits"), field("period"), field("algorithm"), field("counter"));
}

std::string hotp(const std::string& secret, uint64_t counter, int digits, const std::string& algorithm) {
    OtpParams p = validateParams("HOTP", digits, 30, algorithm, counter);
    Bytes key = secretKey(secret);
    Bytes cb = counterBytes(p.counter);
    Bytes mac = hmac(algOf(p.algorithm), key.data(), key.size(), cb.data(), cb.size());
    secureZero(key.data(), key.size());
    uint32_t number = truncate(mac);
    uint64_t mod = 1;
    for (int i = 0; i < p.digits; ++i) mod *= 10;
    std::string s = std::to_string(number % mod);
    return std::string(static_cast<size_t>(p.digits) - s.size(), '0') + s;
}

std::string totp(const std::string& secret, double now, int period, int digits, const std::string& algorithm) {
    OtpParams p = validateParams("TOTP", digits, period, algorithm, 0);
    return hotp(secret, static_cast<uint64_t>(std::floor(now / p.period)), p.digits, p.algorithm);
}

std::string steam(const std::string& secret, double now, int period) {
    OtpParams p = validateParams("STEAM", 5, period, "SHA1", 0);
    Bytes key = secretKey(secret);
    Bytes cb = counterBytes(static_cast<uint64_t>(std::floor(now / p.period)));
    Bytes mac = hmac(HashAlg::Sha1, key.data(), key.size(), cb.data(), cb.size());
    secureZero(key.data(), key.size());
    uint32_t number = truncate(mac);
    std::string out;
    for (int i = 0; i < 5; ++i) {
        out += kSteamAlphabet[number % 26];
        number /= 26;
    }
    return out;
}

OtpCode currentCode(const Json& service, double now) {
    try {
        OtpParams p = otpParams(service);
        const Json* secretValue = service.get("secret");
        if (!secretValue || !secretValue->isString()) throw OtpError("The secret is missing");
        const std::string& secret = secretValue->asString();
        OtpCode out;
        if (p.type == "HOTP") {
            out.code = hotp(secret, p.counter, p.digits, p.algorithm);
            return out;
        }
        out.period = p.period;
        int left = static_cast<int>(p.period - std::fmod(now, static_cast<double>(p.period)));
        out.secondsLeft = left ? left : p.period;
        out.code = p.type == "STEAM" ? steam(secret, now, p.period)
                                     : totp(secret, now, p.period, p.digits, p.algorithm);
        return out;
    } catch (const OtpError&) {
        throw;
    } catch (const std::exception&) {
        throw OtpError("Cannot compute a code for this account");
    }
}

OtpLink parseOtpauth(const std::string& uriIn) {
    std::string uri = trim(uriIn);
    auto sep = uri.find("://");
    if (sep == std::string::npos || lowerAscii(uri.substr(0, sep)) != "otpauth") throw OtpError("Not an otpauth:// link");
    std::string rest = uri.substr(sep + 3);
    auto hash = rest.find('#');
    if (hash != std::string::npos) rest.resize(hash);
    std::string query;
    auto q = rest.find('?');
    if (q != std::string::npos) { query = rest.substr(q + 1); rest.resize(q); }
    std::string netloc = rest, path;
    auto slash = rest.find('/');
    if (slash != std::string::npos) { netloc = rest.substr(0, slash); path = rest.substr(slash); }
    std::string kind = upperAscii(netloc);
    if (kind != "TOTP" && kind != "HOTP") throw OtpError("Unsupported otpauth type: " + truncateChars(netloc, 20));
    size_t s0 = 0;
    while (s0 < path.size() && path[s0] == '/') ++s0;
    std::string label = percentDecode(std::string_view(path).substr(s0), false);

    std::map<std::string, std::string> params;     // first value of each key, keys in lower case
    size_t pos = 0;
    while (pos <= query.size() && !query.empty()) {
        size_t amp = query.find('&', pos);
        std::string part = query.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        size_t eq = part.find('=');
        if (eq != std::string::npos && eq > 0) {
            std::string k = lowerAscii(percentDecode(std::string_view(part).substr(0, eq), true));
            std::string v = percentDecode(std::string_view(part).substr(eq + 1), true);
            if (!v.empty() && !params.count(k)) params[k] = v;
        }
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }

    std::string issuer, account = label;
    auto colon = label.find(':');
    if (colon != std::string::npos) { issuer = trim(label.substr(0, colon)); account = trim(label.substr(colon + 1)); }
    if (params.count("issuer")) issuer = params["issuer"];
    if (!params.count("secret")) throw OtpError("The link has no secret");
    std::string secret = checkSecret(params["secret"]);
    if (lowerAscii(issuer) == "steam" || lowerAscii(params.count("encoder") ? params["encoder"] : "") == "steam") kind = "STEAM";
    auto arg = [&](const char* k) -> Json { return params.count(k) ? Json(params[k]) : Json(); };
    OtpLink link;
    link.params = validateParams(Json(kind), arg("digits"), arg("period"), arg("algorithm"), arg("counter"));
    for (auto& kv : params) wipeString(kv.second);   // the link and its pieces carried the secret
    link.name = truncateChars(issuer.empty() ? account : issuer, 256);
    link.issuer = truncateChars(issuer, 256);
    link.account = truncateChars(account, 256);
    link.secret = secret;
    return link;
}

std::string groupDigits(const std::string& code) {
    bool digits = !code.empty();
    for (char c : code) if (c < '0' || c > '9') digits = false;
    if (digits && (code.size() == 6 || code.size() == 8)) {
        size_t half = code.size() / 2;
        return code.substr(0, half) + " " + code.substr(half);
    }
    return code;
}

}  // namespace b2
