#pragma once
#include <string>
#include "binx/analysis/byte_analysis.hpp"
namespace binx {
std::string format_strings(const std::vector<ExtractedString>&,bool);
std::string format_hexdump(const std::vector<HexdumpLine>&,bool);
std::string format_search(const std::vector<SearchMatch>&,bool);
std::string format_regions(const std::vector<BinaryRegion>&,bool);
}
