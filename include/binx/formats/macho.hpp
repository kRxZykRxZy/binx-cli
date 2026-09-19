#pragma once
#include <cstddef>
#include <span>
#include "binx/core/binary.hpp"
namespace binx { bool parse_macho(std::span<const std::byte> data, Metadata& metadata); }
