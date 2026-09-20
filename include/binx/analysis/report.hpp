#pragma once
#include "binx/core/binary.hpp"
#include <cstddef>
#include <string>
#include <vector>
namespace binx {
struct BinaryReport {
 std::string file_name;
 std::uint64_t file_size=0;
 BinaryFormat format=BinaryFormat::Unknown;
 Architecture architecture=Architecture::Unknown;
 std::string endianness;
 std::string platform;
 std::vector<std::string> dependencies;
 std::size_t symbol_count=0;
 std::size_t debug_compilation_units=0;
 bool has_dwarf=false, has_pdb=false;
 std::uint64_t code_size=0, initialized_data=0, uninitialized_data=0;
 std::vector<std::string> sample_strings;
};
Result<BinaryReport> build_binary_report(const BinaryFile&);
std::string format_binary_report(const BinaryReport&, bool json);
}