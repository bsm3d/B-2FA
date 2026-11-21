// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#include "json.h"

#include <cerrno>
#include <cmath>
#include <cstdlib>

#include "util.h"

namespace b2 {

namespace {

constexpr int kMaxDepth = 200;

class Parser {
public:
    explicit Parser(std::string_view t) : s_(t) {}

    Json run() {
        if (!validUtf8(s_)) throw JsonError("The text is not valid UTF-8");
        skipWs();
        Json v = value(0);
        skipWs();
        if (i_ != s_.size()) fail("Extra data after the document");
        return v;
    }

private:
    std::string_view s_;
    size_t i_ = 0;

    [[noreturn]] void fail(const char* what) const { throw JsonError(what); }
    void skipWs() {
        while (i_ < s_.size() && (s_[i_] == ' ' || s_[i_] == '\t' || s_[i_] == '\n' || s_[i_] == '\r')) ++i_;
    }
    char peek() const { return i_ < s_.size() ? s_[i_] : '\0'; }
    bool eof() const { return i_ >= s_.size(); }

    Json value(int depth) {
        if (depth > kMaxDepth) fail("The document is nested too deeply");
        if (eof()) fail("Unexpected end of the document");
        char c = s_[i_];
        if (c == '{') return object(depth);
        if (c == '[') return array(depth);
        if (c == '"') return Json(string());
        if (c == '-' || (c >= '0' && c <= '9')) return number();
        if (s_.compare(i_, 4, "true") == 0) { i_ += 4; return Json(true); }
        if (s_.compare(i_, 5, "false") == 0) { i_ += 5; return Json(false); }
        if (s_.compare(i_, 4, "null") == 0) { i_ += 4; return Json(); }
        fail("Unexpected character in the document");
    }

    Json object(int depth) {
        Json obj = Json::object();
        ++i_;
        skipWs();
        if (peek() == '}') { ++i_; return obj; }
        while (true) {
            skipWs();
            if (peek() != '"') fail("Expected a key");
            std::string key = string();
            skipWs();
            if (peek() != ':') fail("Expected ':'");
            ++i_;
            skipWs();
            Json v = value(depth + 1);
            obj.set(key, std::move(v));  // a repeated key keeps its first place, last value wins (Python)
            skipWs();
            if (peek() == ',') { ++i_; continue; }
            if (peek() == '}') { ++i_; return obj; }
            fail("Expected ',' or '}'");
        }
    }

    Json array(int depth) {
        Json arr = Json::array();
        ++i_;
        skipWs();
        if (peek() == ']') { ++i_; return arr; }
        while (true) {
            skipWs();
            arr.push(value(depth + 1));
            skipWs();
            if (peek() == ',') { ++i_; continue; }
            if (peek() == ']') { ++i_; return arr; }
            fail("Expected ',' or ']'");
        }
    }

    static void putUtf8(std::string& out, uint32_t cp) {
        if (cp < 0x80) out += static_cast<char>(cp);
        else if (cp < 0x800) { out += static_cast<char>(0xC0 | (cp >> 6)); out += static_cast<char>(0x80 | (cp & 0x3F)); }
        else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }

    uint32_t hex4() {
        if (i_ + 4 > s_.size()) fail("Bad \\u escape");
        uint32_t v = 0;
        for (int k = 0; k < 4; ++k) {
            char c = s_[i_++];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') v |= static_cast<uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= static_cast<uint32_t>(c - 'A' + 10);
            else fail("Bad \\u escape");
        }
        return v;
    }

    std::string string() {
        ++i_;  // opening quote
        std::string out;
        while (true) {
            if (eof()) fail("Unterminated string");
            unsigned char c = static_cast<unsigned char>(s_[i_++]);
            if (c == '"') return out;
            if (c < 0x20) fail("Control character in a string");
            if (c != '\\') { out += static_cast<char>(c); continue; }
            if (eof()) fail("Unterminated string");
            char e = s_[i_++];
            switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    uint32_t cp = hex4();
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        if (s_.compare(i_, 2, "\\u") == 0) {
                            size_t save = i_;
                            i_ += 2;
                            uint32_t lo = hex4();
                            if (lo >= 0xDC00 && lo <= 0xDFFF) cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            else { i_ = save; cp = 0xFFFD; }
                        } else cp = 0xFFFD;
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) cp = 0xFFFD;  // lone surrogate
                    putUtf8(out, cp);
                    break;
                }
                default: fail("Bad escape in a string");
            }
        }
    }

    Json number() {
        size_t start = i_;
        if (peek() == '-') ++i_;
        if (peek() == '0') ++i_;
        else if (peek() >= '1' && peek() <= '9') { while (peek() >= '0' && peek() <= '9') ++i_; }
        else fail("Bad number");
        if (peek() == '.') {
            ++i_;
            if (!(peek() >= '0' && peek() <= '9')) fail("Bad number");
            while (peek() >= '0' && peek() <= '9') ++i_;
        }
        if (peek() == 'e' || peek() == 'E') {
            ++i_;
            if (peek() == '+' || peek() == '-') ++i_;
            if (!(peek() >= '0' && peek() <= '9')) fail("Bad number");
            while (peek() >= '0' && peek() <= '9') ++i_;
        }
        return Json::numberFromText(std::string(s_.substr(start, i_ - start)));
    }
};

void escapeInto(std::string& out, const std::string& s) {
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if (c < 0x20) {
                    static const char* h = "0123456789abcdef";
                    out += "\\u00";
                    out += h[c >> 4];
                    out += h[c & 15];
                } else out += static_cast<char>(c);
        }
    }
    out += '"';
}

void dumpInto(std::string& out, const Json& j) {
    switch (j.type()) {
        case Json::Type::Null: out += "null"; break;
        case Json::Type::Bool: out += j.asBool() ? "true" : "false"; break;
        case Json::Type::Number: out += j.numberText(); break;
        case Json::Type::String: escapeInto(out, j.asString()); break;
        case Json::Type::Array: {
            out += '[';
            bool first = true;
            for (const Json& v : j.items()) {
                if (!first) out += ',';
                first = false;
                dumpInto(out, v);
            }
            out += ']';
            break;
        }
        case Json::Type::Object: {
            out += '{';
            bool first = true;
            for (const auto& m : j.members()) {
                if (!first) out += ',';
                first = false;
                escapeInto(out, m.first);
                out += ':';
                dumpInto(out, m.second);
            }
            out += '}';
            break;
        }
    }
}

}  // namespace

Json Json::parse(std::string_view text) {
    // a UTF-8 byte order mark is accepted (backups exported on Windows may have one)
    if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xEF &&
        static_cast<unsigned char>(text[1]) == 0xBB && static_cast<unsigned char>(text[2]) == 0xBF)
        text.remove_prefix(3);
    return Parser(text).run();
}

std::string Json::dump() const {
    std::string out;
    dumpInto(out, *this);
    return out;
}

bool Json::isInteger() const {
    if (type_ != Type::Number) return false;
    return text_.find_first_of(".eE") == std::string::npos;
}

bool Json::toInt64(int64_t& out) const {
    if (!isInteger()) return false;
    errno = 0;
    char* end = nullptr;
    long long v = std::strtoll(text_.c_str(), &end, 10);
    if (errno == ERANGE || !end || *end != '\0') return false;
    out = v;
    return true;
}

bool Json::toUInt64(uint64_t& out) const {
    if (!isInteger()) return false;
    if (text_[0] == '-') {
        if (text_ == "-0") { out = 0; return true; }
        return false;
    }
    errno = 0;
    char* end = nullptr;
    unsigned long long v = std::strtoull(text_.c_str(), &end, 10);
    if (errno == ERANGE || !end || *end != '\0') return false;
    out = v;
    return true;
}

bool Json::toDouble(double& out) const {
    if (type_ != Type::Number) return false;
    errno = 0;
    char* end = nullptr;
    double v = std::strtod(text_.c_str(), &end);
    if (!end || *end != '\0' || !std::isfinite(v)) return false;
    out = v;
    return true;
}

const Json* Json::get(std::string_view key) const {
    if (type_ != Type::Object) return nullptr;
    for (const auto& m : members_) if (m.first == key) return &m.second;
    return nullptr;
}

Json* Json::get(std::string_view key) {
    if (type_ != Type::Object) return nullptr;
    for (auto& m : members_) if (m.first == key) return &m.second;
    return nullptr;
}

void Json::set(std::string_view key, Json v) {
    if (type_ != Type::Object) { *this = Json::object(); }
    if (Json* existing = get(key)) { *existing = std::move(v); return; }
    members_.emplace_back(std::string(key), std::move(v));
}

bool Json::erase(std::string_view key) {
    for (auto it = members_.begin(); it != members_.end(); ++it) {
        if (it->first == key) { members_.erase(it); return true; }
    }
    return false;
}

std::string Json::stringOr(std::string_view key, std::string def) const {
    const Json* v = get(key);
    return (v && v->isString()) ? v->asString() : def;
}

}  // namespace b2
