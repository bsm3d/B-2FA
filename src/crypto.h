// B-2FA, cryptography on top of the Windows CNG API (nothing to ship, nothing to install).
// SHA-1/256/512, HMAC, PBKDF2-HMAC-SHA256, AES-256-GCM, and scrypt (written here: CNG has none).
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <stdexcept>
#include <string_view>

#include "util.h"

namespace b2 {

enum class HashAlg { Sha1, Sha256, Sha512 };

struct CryptoError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

Bytes hmac(HashAlg alg, const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen);
inline Bytes hmac(HashAlg alg, const Bytes& key, const Bytes& data) {
    return hmac(alg, key.data(), key.size(), data.data(), data.size());
}

// PBKDF2-HMAC-SHA256. The password is raw bytes (UTF-8 text).
Bytes pbkdf2Sha256(const uint8_t* password, size_t passwordLen, const Bytes& salt, uint32_t iterations,
                   size_t outLen);

// scrypt (RFC 7914). Needs 128 * N * r bytes of memory; throws CryptoError if it cannot get them.
Bytes scrypt(const uint8_t* password, size_t passwordLen, const Bytes& salt, uint64_t N, uint32_t r,
             uint32_t p, size_t outLen);

// AES-256-GCM, 12 byte nonce, 16 byte tag. encrypt returns ciphertext || tag.
Bytes aesGcmEncrypt(const Bytes& key, const Bytes& nonce, const uint8_t* plain, size_t plainLen,
                    const uint8_t* aad, size_t aadLen);
// False when the tag does not match (wrong key, wrong data or wrong associated data).
bool aesGcmDecrypt(const Bytes& key, const Bytes& nonce, const uint8_t* data, size_t dataLen,
                   const uint8_t* aad, size_t aadLen, Bytes& plain);

}  // namespace b2
