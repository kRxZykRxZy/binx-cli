#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>
#include "binx/analysis/disassembly.hpp"
#include "binx/error.hpp"

namespace binx {

struct Options {
    std::string command;
    std::filesystem::path input;
    std::filesystem::path output;
    bool has_output = false;
    bool json = false;
    bool quiet = false;
    bool verbose = false;
    std::string encoding = "ascii";
    std::string pattern;
    std::string text;
    std::filesystem::path second_input;
    bool has_second_input = false;
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
    std::size_t width = 16;
    std::size_t min_length = 4;
    std::size_t max_results = 0;
    std::size_t region_min = 16;
    std::vector<std::filesystem::path> search_paths;
    std::size_t depth = 8;
    std::size_t max_nodes = 256;
    bool dot = false;
    bool recursive = false;
    std::size_t count = 100;
    std::size_t max_bytes = 0;
    bool from_entry = false;
    DisassemblySyntax syntax = DisassemblySyntax::Intel;
};

Result<Options> parse_options(int argc, char** argv);

} // namespace binx
