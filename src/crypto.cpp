// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "crypto.h"

#include <windows.h>
#include <bcrypt.h>

#include <cstring>
#include <memory>

namespace b2 {

namespace {

bool ok(NTSTATUS s) { return s >= 0; }

// Providers are opened once and kept for the life of the program.
struct Providers {
    BCRYPT_ALG_HANDLE hmac[3] = {};
    BCRYPT_ALG_HANDLE aes = nullptr;
    Providers() {
        LPCWSTR names[3] = {BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA512_ALGORITHM};
        for (int i = 0; i < 3; ++i) {
            if (!ok(BCryptOpenAlgorithmProvider(&hmac[i], names[i], nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
                throw CryptoError("Cannot open the hash provider");
        }
        if (!ok(BCryptOpenAlgorithmProvider(&aes, BCRYPT_AES_ALGORITHM, nullptr, 0)))
            throw CryptoError("Cannot open the AES provider");
        if (!ok(BCryptSetProperty(aes, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                                  sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
            throw CryptoError("Cannot select the GCM mode");
    }
};

Providers& providers() {
    static Providers p;
    return p;
}

BCRYPT_ALG_HANDLE hmacProvider(HashAlg a) { return providers().hmac[static_cast<int>(a)]; }

}  // namespace

Bytes hmac(HashAlg alg, const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen) {
    static const uint8_t kEmpty = 0;
    BCRYPT_HASH_HANDLE h = nullptr;
    // an empty key is legal in HMAC but CNG refuses a null pointer
    if (!ok(BCryptCreateHash(hmacProvider(alg), &h, nullptr, 0, const_cast<PUCHAR>(keyLen ? key : &kEmpty),
                             static_cast<ULONG>(keyLen), 0)))
        throw CryptoError("HMAC failed");
    std::unique_ptr<void, void (*)(void*)> guard(h, [](void* p) { BCryptDestroyHash(p); });
    if (dataLen && !ok(BCryptHashData(h, const_cast<PUCHAR>(data), static_cast<ULONG>(dataLen), 0)))
        throw CryptoError("HMAC failed");
    ULONG len = 0, got = 0;
    BCryptGetProperty(h, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&len), sizeof(len), &got, 0);
    Bytes out(len);
    if (!ok(BCryptFinishHash(h, out.data(), len, 0))) throw CryptoError("HMAC failed");
    return out;
}

Bytes pbkdf2Sha256(const uint8_t* password, size_t passwordLen, const Bytes& salt, uint32_t iterations,
                   size_t outLen) {
    static const uint8_t kEmpty = 0;
    Bytes out(outLen);
    NTSTATUS s = BCryptDeriveKeyPBKDF2(hmacProvider(HashAlg::Sha256),
                                       const_cast<PUCHAR>(passwordLen ? password : &kEmpty),
                                       static_cast<ULONG>(passwordLen), const_cast<PUCHAR>(salt.data()),
                                       static_cast<ULONG>(salt.size()), iterations, out.data(),
                                       static_cast<ULONG>(outLen), 0);
    if (!ok(s)) throw CryptoError("PBKDF2 failed");
    return out;
}

// ---- scrypt --------------------------------------------------------------
namespace {

inline uint32_t rotl(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

void salsa20_8(uint32_t B[16]) {
    uint32_t x[16];
    std::memcpy(x, B, 64);
    for (int i = 0; i < 8; i += 2) {
        x[4] ^= rotl(x[0] + x[12], 7);   x[8] ^= rotl(x[4] + x[0], 9);
        x[12] ^= rotl(x[8] + x[4], 13);  x[0] ^= rotl(x[12] + x[8], 18);
        x[9] ^= rotl(x[5] + x[1], 7);    x[13] ^= rotl(x[9] + x[5], 9);
        x[1] ^= rotl(x[13] + x[9], 13);  x[5] ^= rotl(x[1] + x[13], 18);
        x[14] ^= rotl(x[10] + x[6], 7);  x[2] ^= rotl(x[14] + x[10], 9);
        x[6] ^= rotl(x[2] + x[14], 13);  x[10] ^= rotl(x[6] + x[2], 18);
        x[3] ^= rotl(x[15] + x[11], 7);  x[7] ^= rotl(x[3] + x[15], 9);
        x[11] ^= rotl(x[7] + x[3], 13);  x[15] ^= rotl(x[11] + x[7], 18);
        x[1] ^= rotl(x[0] + x[3], 7);    x[2] ^= rotl(x[1] + x[0], 9);
        x[3] ^= rotl(x[2] + x[1], 13);   x[0] ^= rotl(x[3] + x[2], 18);
        x[6] ^= rotl(x[5] + x[4], 7);    x[7] ^= rotl(x[6] + x[5], 9);
        x[4] ^= rotl(x[7] + x[6], 13);   x[5] ^= rotl(x[4] + x[7], 18);
        x[11] ^= rotl(x[10] + x[9], 7);  x[8] ^= rotl(x[11] + x[10], 9);
        x[9] ^= rotl(x[8] + x[11], 13);  x[10] ^= rotl(x[9] + x[8], 18);
        x[12] ^= rotl(x[15] + x[14], 7); x[13] ^= rotl(x[12] + x[15], 9);
        x[14] ^= rotl(x[13] + x[12], 13); x[15] ^= rotl(x[14] + x[13], 18);
    }
    for (int i = 0; i < 16; ++i) B[i] += x[i];
}

// B and Y hold 2*r blocks of 16 words
void blockMix(uint32_t* B, uint32_t* Y, uint32_t r) {
    uint32_t X[16];
    std::memcpy(X, &B[(2 * r - 1) * 16], 64);
    for (uint32_t i = 0; i < 2 * r; ++i) {
        for (int k = 0; k < 16; ++k) X[k] ^= B[i * 16 + k];
        salsa20_8(X);
        std::memcpy(&Y[i * 16], X, 64);
    }
    for (uint32_t i = 0; i < r; ++i) std::memcpy(&B[i * 16], &Y[(2 * i) * 16], 64);
    for (uint32_t i = 0; i < r; ++i) std::memcpy(&B[(r + i) * 16], &Y[(2 * i + 1) * 16], 64);
}

// A large buffer that is wiped and returned to the system when it goes out of scope.
class BigBuffer {
public:
    explicit BigBuffer(size_t bytes) : size_(bytes) {
        p_ = VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!p_) throw CryptoError("Not enough memory for the key derivation");
    }
    ~BigBuffer() {
        if (p_) {
            secureZero(p_, size_);
            VirtualFree(p_, 0, MEM_RELEASE);
        }
    }
    BigBuffer(const BigBuffer&) = delete;
    BigBuffer& operator=(const BigBuffer&) = delete;
    uint32_t* words() { return static_cast<uint32_t*>(p_); }

private:
    void* p_ = nullptr;
    size_t size_;
};

void roMix(uint32_t* B, uint32_t r, uint64_t N) {
    size_t words = static_cast<size_t>(32) * r;
    BigBuffer V(static_cast<size_t>(N) * words * sizeof(uint32_t));
    BigBuffer Y(words * sizeof(uint32_t));
    uint32_t* v = V.words();
    for (uint64_t i = 0; i < N; ++i) {
        std::memcpy(&v[i * words], B, words * sizeof(uint32_t));
        blockMix(B, Y.words(), r);
    }
    for (uint64_t i = 0; i < N; ++i) {
        uint64_t j = B[(2 * r - 1) * 16] & (N - 1);   // Integerify: low word of the last block
        for (size_t k = 0; k < words; ++k) B[k] ^= v[j * words + k];
        blockMix(B, Y.words(), r);
    }
}

}  // namespace

Bytes scrypt(const uint8_t* password, size_t passwordLen, const Bytes& salt, uint64_t N, uint32_t r,
             uint32_t p, size_t outLen) {
    if (N < 2 || (N & (N - 1)) != 0 || r == 0 || p == 0) throw CryptoError("Bad scrypt parameters");
    size_t blockBytes = static_cast<size_t>(128) * r;
    Bytes B = pbkdf2Sha256(password, passwordLen, salt, 1, blockBytes * p);
    {
        // work on 32-bit little-endian words (this PC is little-endian)
        std::vector<uint32_t, ZeroAllocator<uint32_t>> words(blockBytes / 4);
        for (uint32_t i = 0; i < p; ++i) {
            std::memcpy(words.data(), &B[i * blockBytes], blockBytes);
            roMix(words.data(), r, N);
            std::memcpy(&B[i * blockBytes], words.data(), blockBytes);
        }
    }
    Bytes out = pbkdf2Sha256(password, passwordLen, B, 1, outLen);
    secureZero(B.data(), B.size());
    return out;
}

// ---- AES-GCM -------------------------------------------------------------
namespace {

struct KeyHandle {
    BCRYPT_KEY_HANDLE h = nullptr;
    ~KeyHandle() { if (h) BCryptDestroyKey(h); }
};

void makeKey(KeyHandle& k, const Bytes& key) {
    if (key.size() != 32) throw CryptoError("The AES key must be 32 bytes");
    if (!ok(BCryptGenerateSymmetricKey(providers().aes, &k.h, nullptr, 0, const_cast<PUCHAR>(key.data()),
                                       static_cast<ULONG>(key.size()), 0)))
        throw CryptoError("Cannot create the AES key");
}

}  // namespace

Bytes aesGcmEncrypt(const Bytes& key, const Bytes& nonce, const uint8_t* plain, size_t plainLen,
                    const uint8_t* aad, size_t aadLen) {
    if (nonce.size() != 12) throw CryptoError("The nonce must be 12 bytes");
    KeyHandle k;
    makeKey(k, key);
    uint8_t tag[16] = {};
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce.data());
    info.cbNonce = static_cast<ULONG>(nonce.size());
    info.pbAuthData = aadLen ? const_cast<PUCHAR>(aad) : nullptr;
    info.cbAuthData = static_cast<ULONG>(aadLen);
    info.pbTag = tag;
    info.cbTag = sizeof(tag);
    Bytes out(plainLen + 16);
    ULONG written = 0;
    static const uint8_t kEmpty = 0;
    if (!ok(BCryptEncrypt(k.h, const_cast<PUCHAR>(plainLen ? plain : &kEmpty), static_cast<ULONG>(plainLen),
                          &info, nullptr, 0, out.data(), static_cast<ULONG>(plainLen), &written, 0)))
        throw CryptoError("AES-GCM encryption failed");
    std::memcpy(out.data() + plainLen, tag, 16);
    return out;
}

bool aesGcmDecrypt(const Bytes& key, const Bytes& nonce, const uint8_t* data, size_t dataLen,
                   const uint8_t* aad, size_t aadLen, Bytes& plain) {
    plain.clear();
    if (nonce.size() != 12 || dataLen < 16) return false;
    KeyHandle k;
    makeKey(k, key);
    size_t n = dataLen - 16;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce.data());
    info.cbNonce = static_cast<ULONG>(nonce.size());
    info.pbAuthData = aadLen ? const_cast<PUCHAR>(aad) : nullptr;
    info.cbAuthData = static_cast<ULONG>(aadLen);
    uint8_t tag[16];
    std::memcpy(tag, data + n, 16);
    info.pbTag = tag;
    info.cbTag = sizeof(tag);
    Bytes out(n ? n : 1);
    ULONG written = 0;
    static const uint8_t kEmpty = 0;
    NTSTATUS s = BCryptDecrypt(k.h, const_cast<PUCHAR>(n ? data : &kEmpty), static_cast<ULONG>(n), &info, nullptr, 0,
                               out.data(), static_cast<ULONG>(n), &written, 0);
    if (!ok(s)) {
        secureZero(out.data(), out.size());
        return false;  // STATUS_AUTH_TAG_MISMATCH or any other failure: not decryptable
    }
    out.resize(n);
    plain = std::move(out);
    return true;
}

}  // namespace b2
