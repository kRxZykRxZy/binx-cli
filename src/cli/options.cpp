#include "binx/cli/options.hpp"
#include "binx/cli/commands.hpp"
#include <charconv>
#include <limits>
#include <string>
#include <vector>

namespace binx {
namespace {

bool parse_number(const std::string& input, std::uint64_t& value) {
    if (input.empty()) return false;
    const char* first = input.data();
    const char* last = input.data() + input.size();
    int base = 10;
    if (input.size() > 2 && input[0] == '0' &&
        (input[1] == 'x' || input[1] == 'X')) {
        base = 16;
        first += 2;
    }
    const auto [ptr, ec] = std::from_chars(first, last, value, base);
    return ec == std::errc{} && ptr == last;
}

bool parse_size(const std::string& input, std::size_t& value) {
    std::uint64_t parsed = 0;
    if (!parse_number(input, parsed) ||
        parsed > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return false;
    }
    value = static_cast<std::size_t>(parsed);
    return true;
}

Result<bool> consume_value(int& index, int argc, char** argv,
                           const char* option, std::string& value) {
    if (index + 1 >= argc) {
        return Error{ErrorCode::InvalidArguments,
                     std::string(option) + " requires a value"};
    }
    value = argv[++index];
    return true;
}

} // namespace

Result<Options> parse_options(int argc, char** argv) {
    if (argc < 2) {
        return Error{ErrorCode::InvalidArguments, "missing command"};
    }

    Options options;
    options.command = argv[1];

    if (options.command == "--help" || options.command == "-h") {
        options.command = "help";
        return options;
    }
    if (options.command == "--version") {
        options.command = "version";
        return options;
    }

    std::vector<std::string> positional;
    positional.reserve(static_cast<std::size_t>(argc));

    for (int i = 2; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "--json") {
            options.json = true;
        } else if (arg == "--quiet") {
            options.quiet = true;
        } else if (arg == "--verbose") {
            options.verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            options.command = "help";
            return options;
        } else if (arg == "--output" || arg == "-o") {
            std::string value;
            auto result = consume_value(i, argc, argv, "--output", value);
            if (!result) return result.error();
            options.output = value;
            options.has_output = true;
        } else if (arg == "--encoding") {
            std::string value;
            auto result = consume_value(i, argc, argv, "--encoding", value);
            if (!result) return result.error();
            options.encoding = std::move(value);
        } else if (arg == "--min-length") {
            if (i + 1 >= argc || !parse_size(argv[i + 1], options.min_length)) {
                return Error{ErrorCode::InvalidArguments,
                             "--min-length requires a non-negative integer"};
            }
            ++i;
        } else if (arg == "--max-results") {
            if (i + 1 >= argc || !parse_size(argv[i + 1], options.max_results)) {
                return Error{ErrorCode::InvalidArguments,
                             "--max-results requires a non-negative integer"};
            }
            ++i;
        } else if (arg == "--offset") {
            if (i + 1 >= argc || !parse_number(argv[i + 1], options.offset)) {
                return Error{ErrorCode::InvalidArguments,
                             "--offset requires a non-negative integer"};
            }
            ++i;
        } else if (arg == "--length") {
            if (i + 1 >= argc || !parse_number(argv[i + 1], options.length)) {
                return Error{ErrorCode::InvalidArguments,
                             "--length requires a non-negative integer"};
            }
            ++i;
        } else if (arg == "--width") {
            if (i + 1 >= argc || !parse_size(argv[i + 1], options.width) ||
                options.width == 0 || options.width > 256) {
                return Error{ErrorCode::InvalidArguments, "--width must be 1..256"};
            }
            ++i;
        } else if (arg == "--pattern" || arg == "--hex") {
            std::string value;
            auto result = consume_value(i, argc, argv, arg.c_str(), value);
            if (!result) return result.error();
            options.pattern = std::move(value);
        } else if (arg == "--text") {
            std::string value;
            auto result = consume_value(i, argc, argv, "--text", value);
            if (!result) return result.error();
            options.text = std::move(value);
        } else if (arg == "--region-min") {
            if (i + 1 >= argc || !parse_size(argv[i + 1], options.region_min) ||
                options.region_min == 0) {
                return Error{ErrorCode::InvalidArguments,
                             "--region-min must be greater than zero"};
            }
            ++i;
        } else if (arg == "--search-path") {
            std::string value;
            auto result = consume_value(i, argc, argv, "--search-path", value);
            if (!result) return result.error();
            options.search_paths.emplace_back(value);
        } else if (arg == "--depth") {
            if (i + 1 >= argc || !parse_size(argv[i + 1], options.depth) ||
                options.depth > 64) {
                return Error{ErrorCode::InvalidArguments, "--depth must be 0..64"};
            }
            ++i;
        } else if (arg == "--max-nodes") {
            if (i + 1 >= argc || !parse_size(argv[i + 1], options.max_nodes) ||
                options.max_nodes == 0 || options.max_nodes > 100000) {
                return Error{ErrorCode::InvalidArguments,
                             "--max-nodes must be 1..100000"};
            }
            ++i;
        } else if (arg == "--dot") {
            options.dot = true;
        } else if (arg == "--recursive") {
            options.recursive = true;
        } else if (arg == "--from-entry") {
            options.from_entry = true;
        } else if (arg == "--syntax") {
            std::string value;
            auto result = consume_value(i, argc, argv, "--syntax", value);
            if (!result) return result.error();
            if (value == "intel") {
                options.syntax = DisassemblySyntax::Intel;
            } else if (value == "att") {
                options.syntax = DisassemblySyntax::Att;
            } else {
                return Error{ErrorCode::InvalidArguments,
                             "--syntax must be intel or att"};
            }
        } else if (arg == "--count") {
            if (i + 1 >= argc || !parse_size(argv[i + 1], options.count) ||
                options.count == 0) {
                return Error{ErrorCode::InvalidArguments,
                             "--count must be greater than zero"};
            }
            ++i;
        } else if (arg == "--max-bytes") {
            if (i + 1 >= argc || !parse_size(argv[i + 1], options.max_bytes)) {
                return Error{ErrorCode::InvalidArguments,
                             "--max-bytes requires a non-negative integer"};
            }
            ++i;
        } else if (!arg.empty() && arg[0] == '-') {
            return Error{ErrorCode::InvalidArguments,
                         "unknown option '" + arg + "'"};
        } else {
            positional.push_back(arg);
        }
    }

    if (options.command == "help" || options.command == "version") return options;

    if (is_diff_command(options.command)) {
        if (positional.size() != 2) {
            return Error{ErrorCode::InvalidArguments,
                         "diff requires two input files"};
        }
        options.input = positional[0];
        options.second_input = positional[1];
        options.has_second_input = true;
    } else {
        if (positional.size() != 1) {
            return Error{ErrorCode::InvalidArguments,
                         positional.empty() ? "missing input file"
                                            : "too many input files"};
        }
        options.input = positional[0];
    }

    if (options.command == "strings" &&
        options.encoding != "ascii" && options.encoding != "utf8" &&
        options.encoding != "utf16le" && options.encoding != "utf16be" &&
        options.encoding != "all") {
        return Error{ErrorCode::InvalidArguments,
                     "unsupported string encoding '" + options.encoding + "'"};
    }

    if (options.command == "search" &&
        options.pattern.empty() && options.text.empty()) {
        return Error{ErrorCode::InvalidArguments,
                     "search requires --pattern/--hex or --text"};
    }

    if (options.command == "graph" && options.dot) {
        options.json = false;
    }

    return options;
}

} // namespace binx
