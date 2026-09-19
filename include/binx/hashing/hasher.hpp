#pragma once
#include <span>
#include <string>
#include "binx/error.hpp"

namespace binx {
struct Hashes {
    std::string md5;
    std::string sha1;
    std::string sha256;
};
Result<Hashes> hash_all(std::span<const std::byte> data);
}
