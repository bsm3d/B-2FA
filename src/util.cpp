// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "util.h"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <chrono>
#include <cstring>

namespace b2 {

void secureZero(void* p, size_t n) {
    if (p && n) SecureZeroMemory(p, n);
}

bool Secret::equals(const Secret& o) const {
    if (size() != o.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < size(); ++i) diff |= static_cast<unsigned char>(data_[i] ^ o.data_[i]);
    return diff == 0;
}

size_t Secret::codepoints() const { return codepointCount(view()); }

// ---- text ----------------------------------------------------------------
std::wstring widen(std::string_view s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::string narrow(std::wstring_view w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

bool validUtf8(std::string_view s) {
    size_t i = 0, n = s.size();
    while (i < n) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        size_t len;
        uint32_t cp;
        if (c < 0x80) { ++i; continue; }
        if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; }
        else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; }
        else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; }
        else return false;
        if (i + len > n) return false;
        for (size_t k = 1; k < len; ++k) {
            unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3F);
        }
        if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000)) return false;
        if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        i += len;
    }
    return true;
}

std::string sanitizeUtf8(std::string_view s) {
    if (validUtf8(s)) return std::string(s);
    std::wstring w;
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    w.resize(static_cast<size_t>(n));
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);  // replaces bad bytes
    return narrow(w);
}

size_t codepointCount(std::string_view s) {
    size_t n = 0;
    for (unsigned char c : s) n += ((c & 0xC0) != 0x80);
    return n;
}

std::string truncateChars(std::string_view s, size_t maxChars) {
    size_t count = 0, i = 0;
    while (i < s.size()) {
        if ((static_cast<unsigned char>(s[i]) & 0xC0) != 0x80) {
            if (count == maxChars) break;
            ++count;
        }
        ++i;
    }
    return std::string(s.substr(0, i));
}

std::string lowerAscii(std::string_view s) {
    std::string out(s);
    for (char& c : out) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return out;
}

std::string upperAscii(std::string_view s) {
    std::string out(s);
    for (char& c : out) if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    return out;
}

std::string trim(std::string_view s) {
    auto isSpace = [](unsigned char c) { return c == ' ' || (c >= 9 && c <= 13); };
    size_t a = 0, b = s.size();
    while (a < b && isSpace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && isSpace(static_cast<unsigned char>(s[b - 1]))) --b;
    return std::string(s.substr(a, b - a));
}

std::string lowerUnicode(std::string_view utf8) {
    std::wstring w = widen(utf8);
    if (w.empty()) return {};
    CharLowerBuffW(w.data(), static_cast<DWORD>(w.size()));
    return narrow(w);
}

// ---- encodings -----------------------------------------------------------
static const char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64Encode(const uint8_t* d, size_t n) {
    std::string out;
    out.reserve((n + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 2 < n; i += 3) {
        uint32_t v = (d[i] << 16) | (d[i + 1] << 8) | d[i + 2];
        out += kB64[v >> 18]; out += kB64[(v >> 12) & 63]; out += kB64[(v >> 6) & 63]; out += kB64[v & 63];
    }
    if (i + 1 == n) {
        uint32_t v = d[i] << 16;
        out += kB64[v >> 18]; out += kB64[(v >> 12) & 63]; out += "==";
    } else if (i + 2 == n) {
        uint32_t v = (d[i] << 16) | (d[i + 1] << 8);
        out += kB64[v >> 18]; out += kB64[(v >> 12) & 63]; out += kB64[(v >> 6) & 63]; out += '=';
    }
    return out;
}

bool base64Decode(std::string_view t, Bytes& out) {
    out.clear();
    if (t.size() % 4 != 0) return false;
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    out.reserve(t.size() / 4 * 3);
    for (size_t i = 0; i < t.size(); i += 4) {
        int a = val(t[i]), b = val(t[i + 1]);
        if (a < 0 || b < 0) return false;
        bool last = (i + 4 == t.size());
        char c2 = t[i + 2], c3 = t[i + 3];
        if (c2 == '=') {
            if (!last || c3 != '=' || (b & 0x0F) != 0) return false;
            out.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
        } else {
            int c = val(c2);
            if (c < 0) return false;
            if (c3 == '=') {
                if (!last || (c & 0x03) != 0) return false;
                out.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
                out.push_back(static_cast<uint8_t>(((b & 15) << 4) | (c >> 2)));
            } else {
                int d = val(c3);
                if (d < 0) return false;
                out.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
                out.push_back(static_cast<uint8_t>(((b & 15) << 4) | (c >> 2)));
                out.push_back(static_cast<uint8_t>(((c & 3) << 6) | d));
            }
        }
    }
    return true;
}

bool base32Decode(std::string_view t, Bytes& out) {
    out.clear();
    while (!t.empty() && t.back() == '=') t.remove_suffix(1);
    uint32_t buffer = 0;
    int bits = 0;
    for (char ch : t) {
        int v;
        if (ch >= 'A' && ch <= 'Z') v = ch - 'A';
        else if (ch >= '2' && ch <= '7') v = ch - '2' + 26;
        else return false;
        buffer = (buffer << 5) | static_cast<uint32_t>(v);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
        }
    }
    // like Python's b32decode: lengths of 1, 3 and 6 characters (mod 8) cannot be a base32 text;
    // spare bits at the end are ignored
    size_t r = t.size() % 8;
    if (r == 1 || r == 3 || r == 6) return false;
    return true;
}

std::string hexEncode(const uint8_t* d, size_t n) {
    static const char* h = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += h[d[i] >> 4]; s += h[d[i] & 15]; }
    return s;
}

bool hexDecode(std::string_view t, Bytes& out) {
    out.clear();
    if (t.size() % 2) return false;
    auto v = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < t.size(); i += 2) {
        int a = v(t[i]), b = v(t[i + 1]);
        if (a < 0 || b < 0) return false;
        out.push_back(static_cast<uint8_t>(a * 16 + b));
    }
    return true;
}

// ---- system --------------------------------------------------------------
Bytes randomBytes(size_t n) {
    Bytes b(n);
    if (n && BCryptGenRandom(nullptr, b.data(), static_cast<ULONG>(n), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        throw std::runtime_error("The system random generator failed");
    return b;
}

std::string randomHex(size_t nBytes) { return hexEncode(randomBytes(nBytes)); }

int64_t nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

double nowSeconds() {
    using namespace std::chrono;
    return duration_cast<duration<double>>(system_clock::now().time_since_epoch()).count();
}

uint64_t monotonicMs() { return GetTickCount64(); }

}  // namespace b2
