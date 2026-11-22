// B-2FA, small helpers shared by every module: text conversion, base64/base32, random bytes,
// and a string type that wipes itself (secrets must not stay in memory after use).
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace b2 {

using Bytes = std::vector<uint8_t>;

// Overwrite memory in a way the optimiser cannot remove.
void secureZero(void* p, size_t n);

// An allocator that wipes what it frees: used for everything that holds a password or a key.
template <class T>
struct ZeroAllocator {
    using value_type = T;
    ZeroAllocator() = default;
    template <class U>
    ZeroAllocator(const ZeroAllocator<U>&) {}
    T* allocate(size_t n) { return static_cast<T*>(::operator new(n * sizeof(T))); }
    void deallocate(T* p, size_t n) {
        secureZero(p, n * sizeof(T));
        ::operator delete(p);
    }
    template <class U>
    bool operator==(const ZeroAllocator<U>&) const { return true; }
};

// A secret text (password, PIN) in UTF-8. Always on the heap (never a small-string buffer),
// wiped when destroyed, and never copied by accident: copy explicitly with clone().
class Secret {
public:
    Secret() = default;
    explicit Secret(std::string_view utf8) : data_(utf8.begin(), utf8.end()) {}
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    Secret(Secret&&) noexcept = default;
    Secret& operator=(Secret&&) noexcept = default;
    ~Secret() { wipe(); }

    Secret clone() const { return Secret(view()); }
    std::string_view view() const { return std::string_view(data_.data(), data_.size()); }
    const char* data() const { return data_.data(); }
    size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }
    void append(std::string_view s) { data_.insert(data_.end(), s.begin(), s.end()); }
    void wipe() {
        secureZero(data_.data(), data_.size());
        data_.clear();
    }
    bool equals(const Secret& o) const;  // constant time
    size_t codepoints() const;           // length in characters, like Python's len(str)

private:
    std::vector<char, ZeroAllocator<char>> data_;
};

// Overwrite the whole buffer of a string (also the small-string buffer and the unused capacity), then empty it.
inline void wipeString(std::string& s) {
    secureZero(s.data(), s.capacity() + 1);
    s.clear();
}

// ---- text ----------------------------------------------------------------
std::wstring widen(std::string_view utf8);
std::string narrow(std::wstring_view wide);
bool validUtf8(std::string_view s);
std::string sanitizeUtf8(std::string_view s);   // invalid bytes become U+FFFD
size_t codepointCount(std::string_view utf8);
std::string truncateChars(std::string_view utf8, size_t maxChars);  // cut on a character boundary
std::string lowerAscii(std::string_view s);
std::string upperAscii(std::string_view s);
std::string trim(std::string_view s);
std::string lowerUnicode(std::string_view utf8);                     // for searching

// ---- encodings -----------------------------------------------------------
std::string base64Encode(const uint8_t* data, size_t n);
inline std::string base64Encode(const Bytes& b) { return base64Encode(b.data(), b.size()); }
// Strict: standard alphabet, padding required, no whitespace (Python's validate=True).
bool base64Decode(std::string_view text, Bytes& out);
// RFC 4648 base32 (upper case, '=' padding optional). False on an invalid character.
bool base32Decode(std::string_view text, Bytes& out);
std::string hexEncode(const uint8_t* data, size_t n);
inline std::string hexEncode(const Bytes& b) { return hexEncode(b.data(), b.size()); }
bool hexDecode(std::string_view text, Bytes& out);

// ---- system --------------------------------------------------------------
Bytes randomBytes(size_t n);   // BCryptGenRandom; throws on failure
std::string randomHex(size_t nBytes);
int64_t nowMs();               // Unix time in milliseconds
double nowSeconds();           // Unix time in seconds
uint64_t monotonicMs();        // for timeouts: never jumps with the clock

}  // namespace b2
