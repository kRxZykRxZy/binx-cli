#pragma once
#include <string>
#include <variant>
#include <utility>

namespace binx {
enum class ErrorCode {
    Ok = 0,
    General = 1,
    InvalidArguments = 2,
    FileNotFound = 3,
    FileAccess = 4,
    InvalidBinary = 5,
    UnsupportedFormat = 6,
    Analysis = 7
};

struct Error {
    ErrorCode code;
    std::string message;
};

template <typename T>
class Result {
public:
    Result(T value) : value_(std::move(value)) {}
    Result(Error error) : value_(std::move(error)) {}
    bool has_value() const noexcept { return std::holds_alternative<T>(value_); }
    explicit operator bool() const noexcept { return has_value(); }
    T& value() { return std::get<T>(value_); }
    const T& value() const { return std::get<T>(value_); }
    Error& error() { return std::get<Error>(value_); }
    const Error& error() const { return std::get<Error>(value_); }
private:
    std::variant<T, Error> value_;
};
}
