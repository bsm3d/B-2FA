// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "fileio.h"

#include <windows.h>

#include <algorithm>

namespace b2 {

namespace {
struct Handle {
    HANDLE h = INVALID_HANDLE_VALUE;
    ~Handle() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
};
}  // namespace

void readFile(const std::filesystem::path& path, std::string& out, uint64_t maxBytes) {
    out.clear();
    Handle f;
    f.h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f.h == INVALID_HANDLE_VALUE) throw IoError("Cannot open the file");
    LARGE_INTEGER size;
    if (!GetFileSizeEx(f.h, &size)) throw IoError("Cannot read the file size");
    if (static_cast<uint64_t>(size.QuadPart) > maxBytes) throw IoError("The file is too big");
    out.resize(static_cast<size_t>(size.QuadPart));
    size_t done = 0;
    while (done < out.size()) {
        DWORD got = 0;
        DWORD want = static_cast<DWORD>(std::min<size_t>(out.size() - done, 1u << 24));
        if (!ReadFile(f.h, out.data() + done, want, &got, nullptr) || got == 0) throw IoError("Cannot read the file");
        done += got;
    }
}

void writeFileSynced(const std::filesystem::path& path, std::string_view data) {
    Handle f;
    f.h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f.h == INVALID_HANDLE_VALUE) throw IoError("Cannot create the file");
    size_t done = 0;
    while (done < data.size()) {
        DWORD put = 0;
        DWORD want = static_cast<DWORD>(std::min<size_t>(data.size() - done, 1u << 24));
        if (!WriteFile(f.h, data.data() + done, want, &put, nullptr)) throw IoError("Cannot write the file");
        done += put;
    }
    if (!FlushFileBuffers(f.h)) throw IoError("Cannot flush the file to disk");
}

void replaceFile(const std::filesystem::path& src, const std::filesystem::path& dst) {
    if (!MoveFileExW(src.c_str(), dst.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        throw IoError("Cannot replace the file");
}

bool copyFileOver(const std::filesystem::path& src, const std::filesystem::path& dst) {
    return CopyFileW(src.c_str(), dst.c_str(), FALSE) != 0;
}

bool removeFile(const std::filesystem::path& path) { return DeleteFileW(path.c_str()) != 0; }

bool fileExists(const std::filesystem::path& path) {
    DWORD a = GetFileAttributesW(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

FileSig fileSig(const std::filesystem::path& path) {
    WIN32_FILE_ATTRIBUTE_DATA d;
    FileSig s;
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &d)) return s;
    s.valid = true;
    s.mtime = (static_cast<uint64_t>(d.ftLastWriteTime.dwHighDateTime) << 32) | d.ftLastWriteTime.dwLowDateTime;
    s.size = (static_cast<uint64_t>(d.nFileSizeHigh) << 32) | d.nFileSizeLow;
    return s;
}

}  // namespace b2
