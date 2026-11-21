// B-2FA, the small toolkit under the windows: colours, fonts, flat buttons, text fields with a thin
// frame, modal windows, and the shuffled on-screen keypad (against keyloggers).
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <windows.h>

#include <functional>
#include <string>
#include <vector>

#include "util.h"

namespace b2::ui {

// ---- look: white, thin, one red ----------------------------------------------------------
constexpr COLORREF kBg = RGB(255, 255, 255);
constexpr COLORREF kFg = RGB(0x11, 0x11, 0x11);
constexpr COLORREF kDim = RGB(0x7a, 0x7a, 0x7a);
constexpr COLORREF kRed = RGB(0xe1, 0x06, 0x00);
constexpr COLORREF kRedHover = RGB(0xff, 0x3a, 0x33);
constexpr COLORREF kLine = RGB(0xd6, 0xd6, 0xd6);       // field frames
constexpr COLORREF kHairline = RGB(0xeb, 0xeb, 0xeb);   // separators between accounts
constexpr COLORREF kHover = RGB(0xf7, 0xf7, 0xf7);      // row under the pointer
constexpr COLORREF kBtn = RGB(0xf0, 0xf0, 0xf0);
constexpr COLORREF kBtnHover = RGB(0xe4, 0xe4, 0xe4);
constexpr COLORREF kTile = RGB(0xef, 0xef, 0xef);

enum class Role { Body, Bold, Small, Mono, Title, Heading, Key };

void setDpi(UINT dpi);           // (re)creates the fonts
UINT dpi();
int dp(int px);                  // 96-dpi pixels to this screen
HFONT font(Role r);
void applyFont(HWND w, Role r);  // also remembered, so a DPI change can reapply it
void refreshFonts(HWND root);    // after setDpi: every child gets its font again

// Called for every dialog right after it is created (the main window uses it to keep dialogs out of
// screen captures too).
void setModalHook(std::function<void(HWND)> hook);

// Activity is anything the user does in any window: it feeds the auto-lock.
uint64_t lastActivity();
void touchActivity();
// One message loop step for every window of the program (records activity, handles dialog keys).
bool pump(HWND dialog);          // false when WM_QUIT was received

// ---- controls ------------------------------------------------------------------------------
enum class BtnStyle { Normal, Primary, Link, LinkLeft, Key };   // LinkLeft: a link aligned on the left edge
HWND makeButton(HWND parent, int id, const std::wstring& text, BtnStyle style, bool tabStop = true);
void drawButton(const DRAWITEMSTRUCT* d);   // call from the parent's WM_DRAWITEM
void setButtonText(HWND button, const std::wstring& text);

HWND makeEdit(HWND parent, int id, bool password);
void lockPhysicalKeyboard(HWND edit, bool locked);   // typed characters ignored; paste and Enter still work
Secret readSecret(HWND edit);                        // the text as a wiped-on-exit secret
std::string readText(HWND edit);                     // UTF-8
void setText(HWND edit, const std::string& utf8);
void wipeEdit(HWND edit);

// ---- a surface with labels and framed fields, painted flicker free -----------------------------
struct Label {
    RECT box{};
    std::wstring text;
    Role role = Role::Body;
    COLORREF color = kFg;
    UINT format = DT_LEFT | DT_WORDBREAK | DT_NOPREFIX;
};
struct Field {
    HWND edit = nullptr;
    RECT frame{};
};

class Surface {
public:
    std::vector<Label> labels;
    std::vector<Field> fields;
    COLORREF background = kBg;

    int addLabel(const std::wstring& text, Role role, COLORREF color, int x, int y, int w, UINT format = DT_LEFT | DT_WORDBREAK | DT_NOPREFIX);   // returns the bottom y
    int measure(const std::wstring& text, Role role, int w);                                                                                  // height of wrapped text
    void placeField(HWND edit, int x, int y, int w);                                                                                           // returns nothing: frame is dp(30) tall
    static int fieldHeight() { return dp(30); }
    void paint(HWND window, const std::function<void(HDC, const RECT&)>& extra = nullptr);
    void invalidateField(HWND window, HWND edit);
    void clear() { labels.clear(); fields.clear(); }
};

// WM_CTLCOLOREDIT and friends: white background, dark text.
LRESULT ctlColor(UINT msg, HDC dc, HWND ctl);

// ---- modal windows ----------------------------------------------------------------------------
class Modal {
public:
    Modal(HWND owner, const wchar_t* title) : owner_(owner), title_(title) {}
    virtual ~Modal() = default;
    int run();                       // shows the window, loops until close() and returns the result

    static void closeAll();          // locking the vault closes every open dialog
    static HWND current();           // the top dialog or nullptr

protected:
    HWND hwnd_ = nullptr;
    HWND owner_;
    std::wstring title_;
    Surface surface_;
    int clientWidth_ = 0;
    int result_ = 0;
    bool done_ = false;

    virtual int widthDp() const { return 420; }
    virtual void build() = 0;                                                   // create controls, fill surface_, return nothing; call setClientHeight
    virtual void onCommand(int id, int code, HWND control) { (void)id; (void)code; (void)control; }
    virtual void onClose() { close(0); }
    void close(int result);
    void setClientHeight(int h);
    void setMessage(const std::wstring& text);                                  // the red line (label index msgLabel_)
    int addMessageLabel(int x, int y, int w);                                   // reserves one line for setMessage
    HWND button(int id, const std::wstring& text, BtnStyle style, int x, int y, int w, int h);

private:
    int msgLabel_ = -1;
    static LRESULT CALLBACK proc(HWND, UINT, WPARAM, LPARAM);
    LRESULT handle(UINT, WPARAM, LPARAM);
};

// ---- the shuffled keypad -----------------------------------------------------------------------
// digits: a 3 x 4 digit pad, reshuffled after every key. Otherwise three pages of a full keyboard.
// always: the pad is always shown and the physical keyboard is locked on the fields (the PIN).
// Otherwise a link shows or hides the pad and the keyboard is locked while it is shown.
class SecureInput {
public:
    SecureInput(HWND parent, std::vector<HWND> edits, bool digits, bool always, int idBase);
    ~SecureInput();
    SecureInput(const SecureInput&) = delete;
    SecureInput& operator=(const SecureInput&) = delete;

    // Place the link (if any) and the pad at x,y (the pad is centred in `width`). Returns the height used.
    int layout(int x, int y, int width);
    bool onCommand(int id);                 // a key or the link was pressed
    void onEditFocus(HWND edit) { focus_ = edit; }
    bool visible() const { return !pad_.empty(); }
    static constexpr int kIdCount = 128;
    std::function<void()> onLayoutChanged;   // the pad appeared or disappeared: the owner lays out again

private:
    HWND parent_;
    std::vector<HWND> edits_;
    HWND focus_;
    bool digits_, always_;
    int idBase_;
    HWND link_ = nullptr;
    std::vector<HWND> pad_;                 // key buttons, then the bar
    std::vector<std::wstring> keys_;        // what each key types
    std::wstring page_ = L"abc";
    int originX_ = 0, originY_ = 0, width_ = 0;

    void show();
    void hide();
    void build();
    void shuffleKeys();
    void press(size_t index);
    void backspace();
    void clearField();
    void type(const std::wstring& s);
};

}  // namespace b2::ui
