// B-2FA
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.1
// Fonction du fichier : Declares the clipboard API: set, read and clear text, with the opt-out formats that keep copied codes out of history.

// B-2FA, the Windows clipboard, with the three documented opt-out formats so a copied code stays
// out of the clipboard history (Win+V) and the cloud clipboard.
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace b2::clip {

bool setText(const std::string& utf8);   // false if the clipboard could not be opened
// 1 = text read, 0 = the clipboard holds no text, -1 = it could not be opened (busy): try again later
int getText(std::string& utf8);
bool clear();

}  // namespace b2::clip
