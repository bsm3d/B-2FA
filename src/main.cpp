// B-2FA, entry point. Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include <windows.h>

#include <commctrl.h>
#include <objbase.h>

#include <string>

#include "app.h"
#include "paths.h"

namespace {

// One window per vault: two writers would silently overwrite each other.
bool acquireSingleInstance() {
    std::wstring path = b2::paths::vaultPath().wstring();
    CharLowerBuffW(path.data(), static_cast<DWORD>(path.size()));
    unsigned long long h = 1469598103934665603ull;   // FNV-1a
    for (wchar_t c : path) {
        h ^= static_cast<unsigned long long>(c);
        h *= 1099511628211ull;
    }
    wchar_t name[64];
    swprintf_s(name, L"Local\\B2FA-%016llx", h);
    HANDLE mutex = CreateMutexW(nullptr, FALSE, name);   // kept for the life of the process
    if (mutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        if (HWND other = FindWindowW(L"B2FAMain", nullptr)) {
            if (IsIconic(other)) ShowWindow(other, SW_RESTORE);
            SetForegroundWindow(other);
        } else {
            MessageBoxW(nullptr, L"B-2FA seems to be running already, or another program holds its lock. Close it and try again.", L"B-2FA",
                        MB_OK | MB_ICONWARNING);
        }
        return false;
    }
    return true;
}

}  // namespace

// A program next to which somebody planted a DLL (a portable copy in Downloads) must not load it, and neither
// may the system components it uses: DLLs only come from System32 and images only from local disks.
void hardenProcess() {
    SetDllDirectoryW(L"");   // no current directory in the search
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY load{};
    load.NoRemoteImages = 1;
    load.NoLowMandatoryLabelImages = 1;
    load.PreferSystem32Images = 1;
    SetProcessMitigationPolicy(ProcessImageLoadPolicy, &load, sizeof(load));
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ext{};
    ext.DisableExtensionPoints = 1;   // no legacy extension DLLs (AppInit and the like)
    SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &ext, sizeof(ext));
}

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand) {
    hardenProcess();
    HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);
    int code = 0;
    if (acquireSingleInstance()) code = b2::runApp(instance, showCommand);
    if (SUCCEEDED(com)) CoUninitialize();
    return code;
}
