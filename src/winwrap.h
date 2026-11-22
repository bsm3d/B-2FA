// B-2FA, Windows DPAPI: data that only this Windows account on this PC can unwrap again.
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "util.h"

namespace b2 {

// Wrap `data` for the current Windows account. `entropy` is mixed in (an extra secret or a fixed label).
// False on failure, with the Windows error code in `error`.
bool dpapiProtect(const Bytes& data, const Bytes& entropy, const wchar_t* description, Bytes& wrapped, unsigned long& error);
// False when the data was not wrapped by this account on this PC with this entropy.
bool dpapiUnprotect(const Bytes& wrapped, const Bytes& entropy, Bytes& data);

}  // namespace b2
