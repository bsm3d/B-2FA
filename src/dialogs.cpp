// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "dialogs.h"

#include <memory>

#include "totp.h"
#include "ui.h"
#include "vault.h"
#include "version.h"

namespace b2 {

using namespace ui;

namespace {

constexpr int kIdE1 = 100, kIdE2 = 101, kIdPad = 300;

// ---- password ----------------------------------------------------------------------------------------------
class PasswordDialog : public Modal {
public:
    PasswordDialog(HWND owner, std::wstring title, std::wstring prompt, bool confirm, size_t minLen, bool digitsOnly, bool secureKeypad)
        : Modal(owner, title.c_str()), prompt_(std::move(prompt)), confirm_(confirm), minLen_(minLen), digitsOnly_(digitsOnly),
          secureKeypad_(secureKeypad) {}
    Secret secret;

protected:
    void build() override {
        x_ = dp(22);
        w_ = clientWidth_ - 2 * x_;
        int y = dp(18);
        y = surface_.addLabel(prompt_, Role::Body, kFg, x_, y, w_) + dp(10);
        e1_ = makeEdit(hwnd_, kIdE1, true);
        surface_.placeField(e1_, x_, y, w_);
        y += Surface::fieldHeight() + dp(8);
        std::vector<HWND> edits{e1_};
        if (confirm_) {
            y = surface_.addLabel(L"Repeat it", Role::Body, kDim, x_, y, w_) + dp(3);
            e2_ = makeEdit(hwnd_, kIdE2, true);
            surface_.placeField(e2_, x_, y, w_);
            y += Surface::fieldHeight() + dp(8);
            edits.push_back(e2_);
        }
        padY_ = y;
        pad_ = std::make_unique<SecureInput>(hwnd_, edits, digitsOnly_, digitsOnly_ && secureKeypad_, kIdPad);
        pad_->onLayoutChanged = [this] { layoutBelow(); };
        msgIndex_ = static_cast<int>(surface_.labels.size());
        addMessageLabel(x_, 0, w_);
        ok_ = button(IDOK, L"OK", BtnStyle::Primary, 0, 0, dp(80), dp(30));
        cancel_ = button(IDCANCEL, L"Cancel", BtnStyle::Normal, 0, 0, dp(80), dp(30));
        layoutBelow();
    }

    void onCommand(int id, int code, HWND ctl) override {
        if (code == EN_SETFOCUS && pad_) pad_->onEditFocus(ctl);
        if (id == IDOK && code == BN_CLICKED) return accept();
        if (id == IDCANCEL) return onClose();
        if (pad_ && code == BN_CLICKED) pad_->onCommand(id);
    }

    void onClose() override {
        wipeEdit(e1_);
        if (e2_) wipeEdit(e2_);
        close(0);
    }

private:
    std::wstring prompt_;
    bool confirm_;
    size_t minLen_;
    bool digitsOnly_, secureKeypad_;
    HWND e1_ = nullptr, e2_ = nullptr, ok_ = nullptr, cancel_ = nullptr;
    std::unique_ptr<SecureInput> pad_;
    int x_ = 0, w_ = 0, padY_ = 0, msgIndex_ = -1;

    void layoutBelow() {
        int y = padY_ + pad_->layout(x_, padY_, w_) + dp(2);
        Label& msg = surface_.labels[static_cast<size_t>(msgIndex_)];
        int mh = msg.box.bottom - msg.box.top;
        msg.box = RECT{x_, y, x_ + w_, y + mh};
        y += mh + dp(8);
        SetWindowPos(ok_, nullptr, x_ + w_ - dp(80), y, dp(80), dp(30), SWP_NOZORDER | SWP_NOACTIVATE);
        SetWindowPos(cancel_, nullptr, x_ + w_ - dp(168), y, dp(80), dp(30), SWP_NOZORDER | SWP_NOACTIVATE);
        setClientHeight(y + dp(30) + dp(18));
        InvalidateRect(hwnd_, nullptr, FALSE);
    }

    void accept() {
        Secret pw = readSecret(e1_);
        if (pw.empty()) return;
        if (digitsOnly_) {
            for (char c : pw.view()) if (c < '0' || c > '9') return setMessage(L"Digits only");
        }
        if (pw.codepoints() < minLen_) {
            setMessage(L"At least " + std::to_wstring(minLen_) + (digitsOnly_ ? L" digits" : L" characters"));
            return;
        }
        if (confirm_ && !pw.equals(readSecret(e2_))) return setMessage(L"The two passwords differ");
        secret = std::move(pw);
        wipeEdit(e1_);
        if (e2_) wipeEdit(e2_);
        close(1);
    }
};

// ---- account -----------------------------------------------------------------------------------------------------
constexpr int kIdUri = 110, kIdName = 111, kIdAccount = 112, kIdSecret = 113, kIdShow = 114, kIdAdv = 115;
constexpr int kIdType = 120, kIdAlgo = 121, kIdDigits = 122, kIdPeriod = 123;

class AccountDialog : public Modal {
public:
    AccountDialog(HWND owner, const Json* existing)
        : Modal(owner, existing ? L"Edit account" : L"Add account"), existing_(existing ? std::optional<Json>(*existing) : std::nullopt) {}
    ~AccountDialog() override {
        if (existing_) existing_->wipe();
    }
    Json result;

protected:
    void build() override {
        x_ = dp(22);
        w_ = clientWidth_ - 2 * x_;
        int y = dp(18);
        OtpParams p;
        if (existing_) {
            try { p = otpParams(*existing_); } catch (const OtpError&) {}
        }
        std::string name, account, secret;
        if (existing_) {
            name = existing_->stringOr("name");
            secret = existing_->stringOr("secret");
            if (const Json* otp = existing_->get("otp"); otp && otp->isObject()) account = otp->stringOr("account");
        }
        auto field = [&](const wchar_t* label, int id, const std::string& value, bool password) {
            y = surface_.addLabel(label, Role::Body, kDim, x_, y, w_) + dp(3);
            HWND e = makeEdit(hwnd_, id, password);
            setText(e, value);
            surface_.placeField(e, x_, y, w_);
            y += Surface::fieldHeight() + dp(8);
            return e;
        };
        if (!existing_) uri_ = field(L"Paste an otpauth:// link (optional)", kIdUri, "", false);
        name_ = field(L"Service name", kIdName, name, false);
        account_ = field(L"Account (login, email)", kIdAccount, account, false);
        secret_ = field(L"Secret key (base32)", kIdSecret, secret, true);
        showBtn_ = button(kIdShow, L"Show the secret", BtnStyle::LinkLeft, x_, y - dp(6), dp(140), dp(24));
        y += dp(26);
        advY_ = y;
        static const wchar_t* heads[4] = {L"Type", L"Algorithm", L"Digits", L"Period"};
        static const wchar_t* values[4][3] = {{L"TOTP", L"HOTP", L"STEAM"}, {L"SHA1", L"SHA256", L"SHA512"}, {L"6", L"7", L"8"}, {L"30", L"60", L"15"}};
        std::wstring current[4] = {widen(p.type), widen(p.algorithm), std::to_wstring(p.digits), std::to_wstring(p.period)};
        int ids[4] = {kIdType, kIdAlgo, kIdDigits, kIdPeriod};
        for (int i = 0; i < 4; ++i) {
            headLabel_[i] = static_cast<int>(surface_.labels.size());
            surface_.addLabel(heads[i], Role::Body, kDim, 0, 0, dp(80));
            combo_[i] = CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWN | CBS_AUTOHSCROLL, 0, 0, dp(90), dp(160),
                                        hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ids[i])), GetModuleHandleW(nullptr), nullptr);
            applyFont(combo_[i], Role::Body);
            for (const wchar_t* v : values[i]) SendMessageW(combo_[i], CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(v));
            SetWindowTextW(combo_[i], current[i].c_str());
            SendMessageW(combo_[i], CB_SETEDITSEL, 0, MAKELPARAM(0, 0));   // no highlighted text
        }
        advBtn_ = button(kIdAdv, L"Advanced options", BtnStyle::LinkLeft, x_, 0, dp(170), dp(24));
        msgIndex_ = static_cast<int>(surface_.labels.size());
        addMessageLabel(x_, 0, w_);
        save_ = button(IDOK, L"Save", BtnStyle::Primary, 0, 0, dp(80), dp(30));
        cancel_ = button(IDCANCEL, L"Cancel", BtnStyle::Normal, 0, 0, dp(80), dp(30));
        // the technical settings are hidden: nearly every service uses the defaults (TOTP, SHA1, 6 digits, 30 s),
        // shown only on request or when the account differs
        advShown_ = p.type != "TOTP" || p.algorithm != "SHA1" || p.digits != 6 || p.period != 30;
        layoutBelow();
    }

    void onCommand(int id, int code, HWND ctl) override {
        if (id == kIdUri && code == EN_CHANGE) return fillFromUri();
        if (code == EN_SETFOCUS || code == EN_KILLFOCUS) return;
        if (id == kIdShow && code == BN_CLICKED) {
            showSecret_ = !showSecret_;
            SendMessageW(secret_, EM_SETPASSWORDCHAR, showSecret_ ? 0 : 0x25CF, 0);
            InvalidateRect(secret_, nullptr, TRUE);
            setButtonText(showBtn_, showSecret_ ? L"Hide the secret" : L"Show the secret");
            return;
        }
        if (id == kIdAdv && code == BN_CLICKED) {
            advShown_ = !advShown_;
            return layoutBelow();
        }
        if (id == IDOK && code == BN_CLICKED) return save();
        if (id == IDCANCEL) return onClose();
        (void)ctl;
    }

    void onClose() override {
        // the link and the secret may hold the secret key in clear: overwrite them
        for (HWND e : {uri_, secret_, name_, account_}) if (e) wipeEdit(e);
        close(0);
    }

private:
    std::optional<Json> existing_;
    HWND uri_ = nullptr, name_ = nullptr, account_ = nullptr, secret_ = nullptr, showBtn_ = nullptr, advBtn_ = nullptr, save_ = nullptr,
         cancel_ = nullptr;
    HWND combo_[4] = {};
    int headLabel_[4] = {};
    int x_ = 0, w_ = 0, advY_ = 0, msgIndex_ = -1;
    bool advShown_ = false, showSecret_ = false;
    std::string issuer_;
    uint64_t counter_ = 0;

    void layoutBelow() {
        int y = advY_;
        int cw = (w_ - 3 * dp(10)) / 4;
        for (int i = 0; i < 4; ++i) {
            Label& l = surface_.labels[static_cast<size_t>(headLabel_[i])];
            int lh = l.box.bottom - l.box.top;
            if (advShown_) {
                int cx = x_ + i * (cw + dp(10));
                l.box = RECT{cx, y, cx + cw, y + lh};
                SetWindowPos(combo_[i], nullptr, cx, y + lh + dp(3), cw, dp(160), SWP_NOZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW);
            } else {
                l.box = RECT{0, 0, 0, 0};
                ShowWindow(combo_[i], SW_HIDE);
            }
        }
        if (advShown_) {
            HDC dc = GetDC(nullptr);
            HGDIOBJ old = SelectObject(dc, font(Role::Body));
            TEXTMETRICW tm{};
            GetTextMetricsW(dc, &tm);
            SelectObject(dc, old);
            ReleaseDC(nullptr, dc);
            y += (surface_.labels[static_cast<size_t>(headLabel_[0])].box.bottom - surface_.labels[static_cast<size_t>(headLabel_[0])].box.top) + dp(3) +
                 tm.tmHeight + dp(10) + dp(8);
        }
        SetWindowPos(advBtn_, nullptr, x_, y, dp(170), dp(24), SWP_NOZORDER | SWP_NOACTIVATE);
        setButtonText(advBtn_, advShown_ ? L"Hide advanced options" : L"Advanced options");
        y += dp(28);
        Label& msg = surface_.labels[static_cast<size_t>(msgIndex_)];
        int mh = msg.box.bottom - msg.box.top;
        msg.box = RECT{x_, y, x_ + w_, y + mh};
        y += mh + dp(8);
        SetWindowPos(save_, nullptr, x_ + w_ - dp(80), y, dp(80), dp(30), SWP_NOZORDER | SWP_NOACTIVATE);
        SetWindowPos(cancel_, nullptr, x_ + w_ - dp(168), y, dp(80), dp(30), SWP_NOZORDER | SWP_NOACTIVATE);
        setClientHeight(y + dp(30) + dp(18));
        InvalidateRect(hwnd_, nullptr, FALSE);
    }

    std::string comboText(int i) {
        int n = GetWindowTextLengthW(combo_[i]);
        std::wstring w(static_cast<size_t>(n) + 1, L'\0');
        GetWindowTextW(combo_[i], w.data(), n + 1);
        w.resize(static_cast<size_t>(n));
        return narrow(w);
    }

    void fillFromUri() {
        std::string text = trim(readText(uri_));
        if (text.rfind("otpauth://", 0) != 0) return;
        OtpLink l;
        try {
            l = parseOtpauth(text);
        } catch (const std::exception& e) {
            return setMessage(widen(e.what()));
        }
        secureZero(text.data(), text.size());   // the link carries the secret
        setMessage(L"");
        setText(name_, l.name);
        setText(account_, l.account);
        setText(secret_, l.secret);
        SetWindowTextW(combo_[0], widen(l.params.type).c_str());
        SetWindowTextW(combo_[1], widen(l.params.algorithm).c_str());
        SetWindowTextW(combo_[2], std::to_wstring(l.params.digits).c_str());
        SetWindowTextW(combo_[3], std::to_wstring(l.params.period).c_str());
        for (HWND c : combo_) SendMessageW(c, CB_SETEDITSEL, 0, MAKELPARAM(0, 0));
        issuer_ = l.issuer;
        counter_ = l.params.counter;
        wipeString(l.secret);
        bool nonDefault = l.params.type != "TOTP" || l.params.algorithm != "SHA1" || l.params.digits != 6 || l.params.period != 30;
        if (nonDefault && !advShown_) { advShown_ = true; layoutBelow(); }
    }

    static bool wholeNumber(const std::string& t, int& out) {
        std::string s = trim(t);
        if (s.empty() || s.size() > 9) return false;
        for (char c : s) if (c < '0' || c > '9') return false;
        out = std::stoi(s);
        return true;
    }

    void save() {
        std::string name = trim(readText(name_)), account = trim(readText(account_));
        Secret secret = readSecret(secret_);
        int digits = 0, period = 0;
        if (!wholeNumber(comboText(2), digits) || !wholeNumber(comboText(3), period))
            return setMessage(L"Digits, period and counter must be whole numbers");
        std::string secretText(secret.view());
        try {
            Json made = makeService(name, secretText, issuer_.empty() ? name : issuer_, account, comboText(0), digits, period,
                                    comboText(1), counter_);
            secureZero(secretText.data(), secretText.size());
            currentCode(made, nowSeconds());   // proves the secret computes a code
            if (!existing_) {
                result = std::move(made);
            } else {
                // edit: keep icon, group, order, issuer, counter and every field we do not touch
                Json s = *existing_;
                s.set("name", *made.get("name"));
                s.set("secret", *made.get("secret"));
                Json* otp = s.get("otp");
                if (!otp || !otp->isObject()) { s.set("otp", Json::object()); otp = s.get("otp"); }
                for (const char* k : {"label", "account", "digits", "period", "algorithm", "tokenType"}) otp->set(k, *made.get("otp")->get(k));
                const Json* c = otp->get("counter");
                if (made.get("otp")->stringOr("tokenType") == "HOTP" && (!c || c->isNull())) otp->set("counter", Json(0));
                result = std::move(s);
            }
        } catch (const std::exception& e) {
            secureZero(secretText.data(), secretText.size());
            return setMessage(widen(e.what()));
        }
        for (HWND e : {uri_, secret_}) if (e) wipeEdit(e);
        close(1);
    }
};

// ---- about ---------------------------------------------------------------------------------------------------------------
class AboutDialog : public Modal {
public:
    explicit AboutDialog(HWND owner) : Modal(owner, (std::wstring(L"About ") + kAppName).c_str()) {}

protected:
    void build() override {
        int x = dp(22), w = clientWidth_ - 2 * x, y = dp(18);
        y = surface_.addLabel(kAppName, Role::Heading, kFg, x, y, w);
        y = surface_.addLabel(std::wstring(L"Version ") + kVersion, Role::Body, kDim, x, y, w) + dp(16);
        y = surface_.addLabel(L"Your 2FAS codes on your PC, without your phone.", Role::Body, kFg, x, y, w) + dp(8);
        y = surface_.addLabel(std::wstring(L"By ") + kAuthor + L" (" + kWebsite + L")\n" + kRepository, Role::Body, kDim, x, y, w) + dp(8);
        y = surface_.addLabel(L"Free software under the GNU General Public License v3 or later, without warranty.", Role::Body, kDim, x, y, w) + dp(14);
        button(IDOK, L"Close", BtnStyle::Primary, x + w - dp(80), y, dp(80), dp(30));
        setClientHeight(y + dp(30) + dp(18));
    }

    void onCommand(int id, int code, HWND) override {
        if ((id == IDOK && code == BN_CLICKED) || id == IDCANCEL) close(0);
    }
};

}  // namespace

bool askPassword(HWND owner, const std::wstring& title, const std::wstring& prompt, Secret& out, bool confirm, size_t minLen, bool digitsOnly,
                 bool secureKeypad) {
    PasswordDialog d(owner, title, prompt, confirm, minLen, digitsOnly, secureKeypad);
    if (d.run() != 1) return false;
    out = std::move(d.secret);
    return true;
}

bool editAccount(HWND owner, const Json* existing, Json& result) {
    AccountDialog d(owner, existing);
    if (d.run() != 1) return false;
    result = std::move(d.result);
    return true;
}

void showAbout(HWND owner) { AboutDialog(owner).run(); }

}  // namespace b2
