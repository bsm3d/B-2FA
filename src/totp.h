// B-2FA, one-time password maths (RFC 4226 HOTP, RFC 6238 TOTP, Steam Guard) and otpauth links.
//
// Every number that comes from a file or a link goes through validateParams(), so a hostile
// backup cannot make the maths crash, freeze or silently use another algorithm.
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <stdexcept>
#include <string>

#include "json.h"
#include "util.h"

namespace b2 {

struct OtpError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct OtpParams {
    std::string type = "TOTP";        // TOTP, HOTP or STEAM
    int digits = 6;
    int period = 30;
    std::string algorithm = "SHA1";   // SHA1, SHA256 or SHA512
    uint64_t counter = 0;
};

struct OtpCode {
    std::string code;
    int secondsLeft = 0;              // 0 for HOTP
    int period = 0;                   // 0 for HOTP
};

struct OtpLink {                      // what an otpauth:// link holds
    OtpParams params;
    std::string name, issuer, account, secret;
};

constexpr int kMinDigits = 4, kMaxDigits = 10, kMinPeriod = 1, kMaxPeriod = 3600;

// The secret as stored: upper case, no spaces or dashes, no padding. Throws OtpError.
std::string checkSecret(const Json& secret);
std::string checkSecret(const std::string& secret);

// Check and normalise settings. Each argument may be null (default), a number or a text.
OtpParams validateParams(const Json& type, const Json& digits, const Json& period, const Json& algorithm,
                         const Json& counter);
OtpParams validateParams(const std::string& type, int digits, int period, const std::string& algorithm,
                         uint64_t counter);

// Read the settings of a 2FAS service object (2FAS defaults apply). Throws OtpError.
OtpParams otpParams(const Json& service);

std::string hotp(const std::string& secret, uint64_t counter, int digits, const std::string& algorithm);
std::string totp(const std::string& secret, double now, int period, int digits, const std::string& algorithm);
std::string steam(const std::string& secret, double now, int period);

// code, seconds left and period for a service object. Only ever throws OtpError.
OtpCode currentCode(const Json& service, double now);

OtpLink parseOtpauth(const std::string& uri);

// '123456' -> '123 456', '12345678' -> '1234 5678'. Steam codes stay whole.
std::string groupDigits(const std::string& code);

}  // namespace b2
