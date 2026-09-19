#pragma once
#include <span>
#include "binx/core/binary.hpp"
namespace binx {
Metadata detect_metadata(std::span<const std::byte> data);
const char* format_name(BinaryFormat);
const char* architecture_name(Architecture);
const char* endianness_name(Endianness);
}
