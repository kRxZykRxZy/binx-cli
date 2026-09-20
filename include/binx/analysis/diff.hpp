#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "binx/core/binary.hpp"
#include "binx/error.hpp"
namespace binx {
struct DiffHunk { std::uint64_t offset=0, length=0, old_offset=0, new_offset=0; };
struct SectionDiff { std::string name; std::uint64_t old_size=0, new_size=0; std::int64_t delta=0; std::uint64_t changed_bytes=0; bool added=false, removed=false; };
struct BinaryDiff {
 std::uint64_t old_size=0,new_size=0,common_size=0,changed_bytes=0,added_bytes=0,removed_bytes=0;
 double similarity=0.0;
 std::vector<DiffHunk> hunks;
 std::vector<SectionDiff> sections;
};
struct SizeEntry { std::string name; std::uint64_t raw_size=0, virtual_size=0; std::string kind; };
struct SizeReport {
 std::uint64_t file_size=0, image_size=0, headers_size=0, code_size=0, initialized_data=0, uninitialized_data=0;
 std::vector<SizeEntry> sections;
};
Result<BinaryDiff> compare_binaries(const BinaryFile&, const BinaryFile&, std::size_t max_hunks=256);
Result<SizeReport> analyze_size(const BinaryFile&);
std::string format_binary_diff(const BinaryDiff&, const BinaryFile&, const BinaryFile&, bool json);
std::string format_size_report(const SizeReport&, const BinaryFile&, bool json);
}