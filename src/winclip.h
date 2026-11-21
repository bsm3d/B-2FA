// B-2FA, the Windows clipboard, with the three documented opt-out formats so a copied code stays
// out of the clipboard history (Win+V) and the cloud clipboard.
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace b2::clip {

bool setText(const std::string& utf8);   // false if the clipboard could not be opened
bool getText(std::string& utf8);         // false if it holds no text
bool clear();

}  // namespace b2::clip
