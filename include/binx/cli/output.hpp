#pragma once
#include <string>
#include "binx/core/binary.hpp"
#include "binx/hashing/hasher.hpp"

namespace binx {
void print_help();
void print_version();
void print_info(const BinaryFile&, bool json);
void print_hashes(const Hashes&, bool json);
}
