#pragma once
#include <cstdint>
#include <string>
#include <string_view>

namespace binx {

std::string json_escape(std::string_view value);
std::string hex_u64(std::uint64_t value, bool uppercase = true);

} // namespace binx
