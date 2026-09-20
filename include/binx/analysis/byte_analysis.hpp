#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <span>
namespace binx {
enum class StringEncoding { ASCII, UTF8, UTF16LE, UTF16BE };
struct ExtractedString { std::uint64_t offset{}; StringEncoding encoding{}; std::string text; };
struct HexdumpLine { std::uint64_t offset{}; std::vector<std::uint8_t> bytes; };
enum class SearchKind { Bytes, Text };
struct SearchMatch { std::uint64_t offset{}; std::size_t length{}; };
enum class RegionKind { Zero, Printable, Binary };
struct BinaryRegion { std::uint64_t offset{}; std::uint64_t size{}; RegionKind kind{}; };
std::vector<ExtractedString> extract_strings(std::span<const std::byte>, StringEncoding, std::size_t min_length, std::size_t max_results=0);
std::vector<HexdumpLine> make_hexdump(std::span<const std::byte>, std::uint64_t offset, std::uint64_t length, std::size_t width);
std::vector<SearchMatch> search_bytes(std::span<const std::byte>, std::span<const std::byte> pattern, std::size_t max_results=0);
std::vector<SearchMatch> search_text(std::span<const std::byte>, const std::string&, StringEncoding, std::size_t max_results=0);
std::vector<BinaryRegion> classify_regions(std::span<const std::byte>, std::size_t minimum_region=16);
const char* string_encoding_name(StringEncoding);
const char* region_kind_name(RegionKind);
bool parse_hex_pattern(const std::string&, std::vector<int>&);
}
