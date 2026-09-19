#pragma once
#include <string>
#include "binx/core/binary.hpp"
#include "binx/hashing/hasher.hpp"
namespace binx {
std::string format_help();
std::string format_version();
std::string format_info(const BinaryFile& file, bool json, bool detailed);
std::string format_hashes(const Hashes& hashes, bool json);
}
