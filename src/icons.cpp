// B-2FA
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.1
// Fonction du fichier : Loads service logos from a local copy of the 2FAS icon pack and resolves each account to its PNG, with no network access.

// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "icons.h"

#include <wincodec.h>
#include <wrl/client.h>

#include "fileio.h"
#include "paths.h"
#include "util.h"
#include "vault.h"

namespace b2 {

using Microsoft::WRL::ComPtr;

namespace {

bool looksLikeUuid(const std::string& s) {
    if (s.size() != 36) return false;
    for (char c : s) {
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '-';
        if (!hex) return false;
    }
    return true;
}

}  // namespace

IconStore::IconStore(std::filesystem::path folder) {
    if (!folder.empty()) {
        folder_ = std::move(folder);
        return;
    }
    folder_ = paths::iconsDir();   // a pack the user put in the data folder wins
    if (!fileExists(folder_ / L"services.json")) {
        std::filesystem::path installed = paths::installedIconsDir();
        if (!installed.empty() && fileExists(installed / L"services.json")) folder_ = std::move(installed);
    }
}

IconStore::~IconStore() { clearImages(); }

void IconStore::clearImages() {
    for (auto& e : images_) if (e.second) DeleteObject(e.second);
    images_.clear();
}

bool IconStore::available() const { return fileExists(folder_ / L"services.json"); }

void IconStore::load() {
    if (loaded_) return;
    loaded_ = true;
    Json services;
    try {
        std::string text;
        readFile(folder_ / L"services.json", text, 64ull * 1024 * 1024);
        services = Json::parse(text);
    } catch (const std::exception&) {
        return;
    }
    if (!services.isArray()) return;
    for (const Json& s : services.items()) {
        if (!s.isObject()) continue;
        const Json* colls = s.get("icons_collections");
        if (!colls || !colls->isArray()) continue;
        for (const Json& coll : colls->items()) {
            const Json* icons = coll.isObject() ? coll.get("icons") : nullptr;
            const Json* cid = coll.isObject() ? coll.get("id") : nullptr;
            if (!icons || !icons->isArray() || icons->items().empty() || !cid || !cid->isString()) continue;
            Collection entry;
            for (const Json& ic : icons->items()) {
                if (!ic.isObject() || !ic.get("id") || !ic.get("id")->isString()) continue;
                bool dark = ic.stringOr("type") == "dark";
                std::string& slot = dark ? entry.dark : entry.light;
                if (slot.empty()) slot = ic.get("id")->asString();
            }
            if (entry.light.empty()) entry.light = entry.dark;
            if (entry.light.empty()) continue;
            std::string key = lowerAscii(cid->asString());
            collections_.emplace(key, entry);
            if (const Json* sid = s.get("id"); sid && sid->isString()) byService_.emplace(lowerAscii(sid->asString()), key);
            std::vector<std::string> names;
            if (const Json* n = s.get("name"); n && n->isString()) names.push_back(n->asString());
            if (const Json* is = s.get("issuers"); is && is->isArray())
                for (const Json& i : is->items()) if (i.isString()) names.push_back(i.asString());
            for (const std::string& n : names) {
                std::string t = lowerUnicode(trim(n));
                if (!t.empty()) byName_.emplace(t, key);
            }
            break;   // first collection only, like the apps
        }
    }
}

std::optional<std::string> IconStore::iconId(const Json& service) {
    if (!available() || !service.isObject()) return std::nullopt;
    load();
    std::vector<std::string> candidates;
    const Json* icon = service.get("icon");
    const Json* collRef = (icon && icon->isObject()) ? icon->get("iconCollection") : nullptr;
    const Json* brand = (icon && icon->isObject()) ? icon->get("brand") : nullptr;
    // the apps' "no brand" collection is a grey placeholder: a letter tile looks better
    if (collRef && collRef->isObject()) {
        if (const Json* id = collRef->get("id"); id && id->isString() && lowerAscii(id->asString()) != kDefaultIconCollection)
            candidates.push_back(lowerAscii(id->asString()));
    }
    for (const Json* key : {service.get("serviceTypeID"), brand && brand->isObject() ? brand->get("id") : nullptr}) {
        if (key && key->isString()) {
            auto it = byService_.find(lowerAscii(key->asString()));
            if (it != byService_.end()) candidates.push_back(it->second);
        }
    }
    const Json* otp = service.get("otp");
    for (const Json* key : {service.get("name"), otp && otp->isObject() ? otp->get("issuer") : nullptr}) {
        if (key && key->isString()) {
            auto it = byName_.find(lowerUnicode(trim(key->asString())));
            if (it != byName_.end()) candidates.push_back(it->second);
        }
    }
    for (const std::string& c : candidates) {
        auto it = collections_.find(c);
        if (it != collections_.end()) return it->second.light;   // the window is light: use the light variant
    }
    return std::nullopt;
}

HBITMAP IconStore::loadPng(const std::string& iconId, int px) {
    ComPtr<IWICImagingFactory> factory;
    if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&factory)))) return nullptr;
    ComPtr<IWICBitmapDecoder> decoder;
    std::filesystem::path file = folder_ / (widen(iconId) + L".png");
    if (FAILED(factory->CreateDecoderFromFilename(file.c_str(), nullptr, GENERIC_READ, WICDecodeMetadataCacheOnDemand, &decoder)))
        return nullptr;
    ComPtr<IWICBitmapFrameDecode> frame;
    if (FAILED(decoder->GetFrame(0, &frame))) return nullptr;
    ComPtr<IWICBitmapScaler> scaler;
    if (FAILED(factory->CreateBitmapScaler(&scaler)) ||
        FAILED(scaler->Initialize(frame.Get(), static_cast<UINT>(px), static_cast<UINT>(px), WICBitmapInterpolationModeFant)))
        return nullptr;
    ComPtr<IWICFormatConverter> conv;
    if (FAILED(factory->CreateFormatConverter(&conv)) ||
        FAILED(conv->Initialize(scaler.Get(), GUID_WICPixelFormat32bppPBGRA, WICBitmapDitherTypeNone, nullptr, 0.0,
                                WICBitmapPaletteTypeCustom)))
        return nullptr;
    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(bi.bmiHeader);
    bi.bmiHeader.biWidth = px;
    bi.bmiHeader.biHeight = -px;   // top-down
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    HBITMAP bmp = CreateDIBSection(nullptr, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (!bmp) return nullptr;
    if (FAILED(conv->CopyPixels(nullptr, static_cast<UINT>(px * 4), static_cast<UINT>(px * px * 4), static_cast<BYTE*>(bits)))) {
        DeleteObject(bmp);
        return nullptr;
    }
    return bmp;
}

HBITMAP IconStore::image(const Json& service, int px) {
    auto id = iconId(service);
    if (!id || !looksLikeUuid(*id)) return nullptr;
    auto key = std::make_pair(*id, px);
    auto it = images_.find(key);
    if (it != images_.end()) return it->second;
    HBITMAP bmp = loadPng(*id, px);
    images_[key] = bmp;   // a missing or broken file is remembered as nullptr
    return bmp;
}

std::string initials(const std::string& name) {
    std::vector<std::string> words;
    std::string cur;
    auto flush = [&] { if (!cur.empty()) { words.push_back(cur); cur.clear(); } };
    size_t i = 0;
    while (i < name.size()) {
        unsigned char c = static_cast<unsigned char>(name[i]);
        if (c == ' ' || c == '.' || c == '_' || c == '@' || c == '-' || (c >= 9 && c <= 13)) { flush(); ++i; continue; }
        size_t len = 1;
        if (c >= 0xF0) len = 4; else if (c >= 0xE0) len = 3; else if (c >= 0xC0) len = 2;
        cur += name.substr(i, len);
        i += len;
    }
    flush();
    auto upper = [](const std::string& s) {
        std::wstring w = widen(s);
        if (!w.empty()) CharUpperBuffW(w.data(), static_cast<DWORD>(w.size()));
        return narrow(w);
    };
    if (words.empty()) return "?";
    if (words.size() == 1) return upper(truncateChars(words[0], 2));
    return upper(truncateChars(words[0], 1) + truncateChars(words[1], 1));
}

}  // namespace b2
