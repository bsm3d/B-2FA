cmake_minimum_required(VERSION 3.20)
project(B2FA LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# static runtime: the program needs no Visual C++ redistributable on the target PC
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

add_compile_options(/W4 /WX /utf-8 /permissive- /EHsc /GS /guard:cf /sdl /Zc:__cplusplus)
add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
add_link_options(/DYNAMICBASE /NXCOMPAT /guard:cf /CETCOMPAT /HIGHENTROPYVA /DEPENDENTLOADFLAG:0x800)

# ---- the core: everything but the window ------------------------------------------------
add_library(b2core STATIC
    src/util.cpp src/json.cpp src/crypto.cpp src/totp.cpp src/twofas.cpp
    src/fileio.cpp src/paths.cpp src/vault.cpp
    src/pinlock.cpp src/settings.cpp src/winclip.cpp src/winwrap.cpp src/devicekey.cpp src/unlockguard.cpp)
target_include_directories(b2core PUBLIC src)
target_link_libraries(b2core PUBLIC bcrypt crypt32 shell32 ole32 user32)

# ---- the program ---------------------------------------------------------------------------
add_executable(B-2FA WIN32
    src/main.cpp src/app.cpp src/ui.cpp src/dialogs.cpp src/captureguard.cpp src/icons.cpp
    res/b2fa.rc)
target_link_libraries(B-2FA PRIVATE b2core gdi32 comctl32 comdlg32 msimg32 dwmapi windowscodecs uuid wtsapi32)
# scripted GUI tests only: lets the menu commands arrive as WM_COMMAND. Never switch it on for a release build.
option(B2FA_TEST_HOOKS "Compile the test-only message hooks" OFF)
if(B2FA_TEST_HOOKS)
    target_compile_definitions(B-2FA PRIVATE B2FA_TEST_HOOKS)
endif()
# our own manifest (DPI awareness, UTF-8, common controls 6) is in the resource file
target_link_options(B-2FA PRIVATE /MANIFEST:NO)
set_target_properties(B-2FA PROPERTIES OUTPUT_NAME "B-2FA")

# ---- tests ----------------------------------------------------------------------------
enable_testing()
add_executable(b2tests tests/test_main.cpp src/icons.cpp)
target_link_libraries(b2tests PRIVATE b2core gdi32 windowscodecs uuid)
target_compile_definitions(b2tests PRIVATE VECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors")
add_test(NAME core COMMAND b2tests)
