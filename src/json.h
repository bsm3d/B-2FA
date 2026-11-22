// B-2FA, a small JSON document model that keeps what it does not understand.
//
// The 2FAS backups and the vault carry fields this program never reads. They must survive a
// load and save unchanged, so objects keep their keys in insertion order and numbers keep their
// original text. Parsing is strict (no NaN, no trailing commas, UTF-8 only) and limited in depth.
// Copyright (C) 2026 Benoit Saint-Moulin. SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "util.h"

namespace b2 {

struct JsonError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

class Json {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };
    using Member = std::pair<std::string, Json>;

    Json() = default;
    // Every text of a document is overwritten when the document goes away (account secrets live in here),
    // also the texts of copies and of moved-from objects.
    ~Json() { wipeBuffers(); }
    Json(const Json&) = default;
    Json(Json&&) noexcept = default;
    Json& operator=(const Json&) = default;
    Json& operator=(Json&&) noexcept = default;
    Json(std::nullptr_t) {}
    Json(bool b) : type_(Type::Bool), bool_(b) {}
    Json(int v) : Json(static_cast<int64_t>(v)) {}
    Json(int64_t v) : type_(Type::Number), text_(std::to_string(v)) {}
    Json(uint64_t v) : type_(Type::Number), text_(std::to_string(v)) {}
    Json(const char* s) : type_(Type::String), text_(s) {}
    Json(std::string s) : type_(Type::String), text_(std::move(s)) {}
    Json(std::string_view s) : type_(Type::String), text_(s) {}

    static Json array() { Json j; j.type_ = Type::Array; return j; }
    static Json object() { Json j; j.type_ = Type::Object; return j; }
    static Json numberFromText(std::string text) { Json j; j.type_ = Type::Number; j.text_ = std::move(text); return j; }

    // Parse a whole document. Throws JsonError.
    static Json parse(std::string_view text);
    // Serialise. UTF-8 is written as is (not \u escaped), compact.
    std::string dump() const;

    Type type() const { return type_; }
    bool isNull() const { return type_ == Type::Null; }
    bool isBool() const { return type_ == Type::Bool; }
    bool isNumber() const { return type_ == Type::Number; }
    bool isString() const { return type_ == Type::String; }
    bool isArray() const { return type_ == Type::Array; }
    bool isObject() const { return type_ == Type::Object; }
    // "an integer" in the Python sense: a number written without fraction or exponent
    bool isInteger() const;

    bool asBool() const { return bool_; }
    const std::string& asString() const { return text_; }
    const std::string& numberText() const { return text_; }
    bool toInt64(int64_t& out) const;      // integer text only, in range
    bool toUInt64(uint64_t& out) const;    // integer text only, in range (no minus sign except -0)
    bool toDouble(double& out) const;

    // arrays
    std::vector<Json>& items() { return items_; }
    const std::vector<Json>& items() const { return items_; }
    void push(Json v) { items_.push_back(std::move(v)); }

    // objects (ordered). get() returns nullptr when the key is absent or this is not an object.
    const Json* get(std::string_view key) const;
    Json* get(std::string_view key);
    void set(std::string_view key, Json v);     // replaces the value in place, or appends
    bool erase(std::string_view key);
    std::vector<Member>& members() { return members_; }
    const std::vector<Member>& members() const { return members_; }

    // handy readers that never throw: the default when absent or of another type
    std::string stringOr(std::string_view key, std::string def = "") const;

    // Overwrite every text of this document with zeros, then empty it (account secrets live in here).
    void wipe();

private:
    void wipeBuffers() {
        secureZero(text_.data(), text_.capacity() + 1);
        for (auto& m : members_) secureZero(m.first.data(), m.first.capacity() + 1);
    }
    Type type_ = Type::Null;
    bool bool_ = false;
    std::string text_;                // string value, or the original text of a number
    std::vector<Json> items_;
    std::vector<Member> members_;
};

// wipe() on each element, then empty the list
void wipeJsonList(std::vector<Json>& list);

}  // namespace b2
