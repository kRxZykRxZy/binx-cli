#include "binx/cli/runner.hpp"
#include "binx/analysis/byte_analysis.hpp"
#include "binx/analysis/crash.hpp"
#include "binx/analysis/dependencies.hpp"
#include "binx/analysis/diff.hpp"
#include "binx/analysis/disassembly.hpp"
#include "binx/analysis/report.hpp"
#include "binx/analysis/symbols.hpp"
#include "binx/cli/commands.hpp"
#include "binx/cli/dependency_output.hpp"
#include "binx/cli/io.hpp"
#include "binx/cli/analysis_output.hpp"
#include "binx/cli/output.hpp"
#include "binx/formats/elf.hpp"
#include "binx/formats/pe.hpp"
#include "binx/formats/detect.hpp"
#include "binx/hashing/hasher.hpp"
#include "binx/core/binary.hpp"
#include <charconv>
#include <iostream>
#include <vector>

namespace binx {
namespace {

Result<int> emit_result(const std::string& text, const Options& o) {
    auto written = write_command_output(text, o.quiet, o.has_output, o.output);
    if (!written) return written.error();
    return 0;
}

Result<int> run_diff(const Options& o) {
    auto a = BinaryFile::open(o.input);
    if (!a) return a.error();
    auto b = BinaryFile::open(o.second_input);
    if (!b) return b.error();

    auto diff = compare_binaries(a.value(), b.value());
    if (!diff) return diff.error();
    return emit_result(format_binary_diff(diff.value(), a.value(), b.value(), o.json), o);
}

Result<int> run_dependency(const Options& o, const BinaryFile& file) {
    if ((o.command == "deps" || o.command == "dependencies") && !o.recursive) {
        return emit_result(format_dependencies(extract_dependencies(file), o.json), o);
    }

    auto graph = build_dependency_graph(o.input, o.search_paths, o.depth, o.max_nodes);
    if (!graph) return graph.error();

    if (o.dot) {
        return emit_result(dependency_graph_dot(graph.value()), o);
    }
    return emit_result(format_dependency_graph(graph.value(), o.json), o);
}

Result<int> run_strings(const Options& o, const BinaryFile& file) {
    std::vector<ExtractedString> strings;
    const auto add = [&](StringEncoding encoding) {
        auto found = extract_strings(file.bytes(), encoding, o.min_length, o.max_results);
        strings.insert(strings.end(), found.begin(), found.end());
    };

    if (o.encoding == "ascii" || o.encoding == "all") add(StringEncoding::ASCII);
    if (o.encoding == "utf8") add(StringEncoding::UTF8);
    if (o.encoding == "utf16le" || o.encoding == "all") add(StringEncoding::UTF16LE);
    if (o.encoding == "utf16be" || o.encoding == "all") add(StringEncoding::UTF16BE);

    if (o.max_results && strings.size() > o.max_results) {
        strings.resize(o.max_results);
    }
    return emit_result(format_strings(strings, o.json), o);
}

Result<int> run_search(const Options& o, const BinaryFile& file) {
    std::vector<SearchMatch> matches;
    if (!o.pattern.empty()) {
        std::vector<int> pattern;
        if (!parse_hex_pattern(o.pattern, pattern)) {
            return Error{ErrorCode::InvalidArguments,
                         "invalid hex pattern; use bytes such as '48 8B ?? FF'"};
        }

        const auto data = file.bytes();
        for (std::size_t pos = 0;
             pos + pattern.size() <= data.size() &&
             (o.max_results == 0 || matches.size() < o.max_results);
             ++pos) {
            bool matched = true;
            for (std::size_t j = 0; j < pattern.size(); ++j) {
                if (pattern[j] >= 0 &&
                    std::to_integer<unsigned char>(data[pos + j]) !=
                        static_cast<unsigned char>(pattern[j])) {
                    matched = false;
                    break;
                }
            }
            if (matched) matches.push_back({pos, pattern.size()});
        }
    } else {
        matches = search_text(file.bytes(), o.text, StringEncoding::UTF8, o.max_results);
    }

    return emit_result(format_search(matches, o.json), o);
}

Result<int> run_format_specific(const Options& o, const BinaryFile& file) {
    const auto format = file.metadata().format;

    if (!is_pe_command(o.command) && !is_elf_command(o.command)) {
        if (o.verbose) {
            std::cerr << "[binx] detected " << format_name(format) << "\n";
        }
        return emit_result(format_info(file, o.json, o.command == "inspect"), o);
    }

    if (is_elf(format)) {
        auto elf = parse_elf_image(file.bytes());
        if (!elf) return elf.error();
        return emit_result(
            format_elf_command(elf.value(), o.command, o.json, o.command == "inspect"), o);
    }

    if (is_elf_command(o.command)) {
        return Error{ErrorCode::UnsupportedFormat, "command requires an ELF image"};
    }

    if (o.command == "inspect" && !is_pe(format)) {
        return emit_result(format_info(file, o.json, true), o);
    }

    auto pe = parse_pe(file.bytes());
    if (!pe) return pe.error();
    const auto& image = pe.value();
    const auto text = format_pe_command(image, o.command, o.json, o.command == "inspect");
    auto emitted = emit_result(text, o);
    if (!emitted) return emitted;
    if (image.header_status == ParseStatus::Malformed ||
        image.header_status == ParseStatus::Unsupported) {
        return Error{ErrorCode::InvalidBinary, "PE header validation failed"};
    }
    return 0;
}

} // namespace

Result<int> run_command(const Options& o) {
    if (!is_supported_command(o.command)) {
        return Error{ErrorCode::InvalidArguments,
                     "unknown command '" + o.command + "'"};
    }

    if (o.command == "help") {
        return emit_result(format_help(), o);
    }
    if (o.command == "version") {
        return emit_result(format_version(), o);
    }
    if (is_diff_command(o.command)) return run_diff(o);

    auto file = BinaryFile::open(o.input);
    if (!file) return file.error();

    if (is_report_command(o.command)) {
        auto report = build_binary_report(file.value());
        if (!report) return report.error();
        return emit_result(format_binary_report(report.value(), o.json), o);
    }

    if (is_dependency_command(o.command)) {
        return run_dependency(o, file.value());
    }

    if (o.command == "strings") return run_strings(o, file.value());

    if (o.command == "hexdump") {
        if (o.offset > file.value().size()) {
            return Error{ErrorCode::InvalidArguments, "offset is beyond end of file"};
        }
        const auto length = o.length
                                ? o.length
                                : file.value().size() - o.offset;
        return emit_result(
            format_hexdump(
                make_hexdump(file.value().bytes(), o.offset, length, o.width), o.json),
            o);
    }

    if (o.command == "regions") {
        return emit_result(
            format_regions(classify_regions(file.value().bytes(), o.region_min), o.json), o);
    }

    if (o.command == "size") {
        auto size = analyze_size(file.value());
        if (!size) return size.error();
        return emit_result(format_size_report(size.value(), file.value(), o.json), o);
    }

    if (o.command == "search") return run_search(o, file.value());

    if (is_crash_command(o.command)) {
        auto report = analyze_crash_dump(file.value());
        if (!report) return report.error();
        return emit_result(format_crash_report(report.value(), file.value(), o.json), o);
    }

    if (is_symbols_command(o.command)) {
        auto symbols = collect_symbols(file.value());
        if (!symbols) return symbols.error();
        return emit_result(format_symbols(symbols.value(), o.json), o);
    }

    if (is_debug_command(o.command)) {
        auto debug = collect_debug_info(file.value());
        if (!debug) return debug.error();
        return emit_result(format_debug_info(debug.value(), o.json), o);
    }

    if (is_disassembly_command(o.command)) {
        DisassemblyOptions disasm;
        disasm.offset = o.offset;
        disasm.count = o.count;
        disasm.max_bytes = o.max_bytes;
        disasm.from_entry = o.from_entry;
        disasm.syntax = o.syntax;
        auto result = disassemble_file(file.value(), disasm);
        if (!result) return result.error();
        return emit_result(format_disassembly(result.value(), o.json, o.syntax), o);
    }

    if (o.command == "hash") {
        auto hashes = hash_all(file.value().bytes());
        if (!hashes) return hashes.error();
        return emit_result(format_hashes(hashes.value(), o.json), o);
    }

    return run_format_specific(o, file.value());
}

} // namespace binx
