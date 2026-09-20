#include "binx/cli/analysis_output.hpp"
#include "binx/core/text.hpp"
#include <iomanip>
#include <sstream>

namespace binx {

std::string format_strings(const std::vector<ExtractedString>& v, bool json) {
    std::ostringstream out;
    if (json) {
        out << "{\"schema_version\":4,\"strings\":[";
        for (std::size_t i = 0; i < v.size(); ++i) {
            if (i) out << ",";
            out << "{\"offset\":\"" << hex_u64(v[i].offset)
                << "\",\"encoding\":\"" << string_encoding_name(v[i].encoding)
                << "\",\"text\":\"" << json_escape(v[i].text) << "\"}";
        }
        out << "]}\n";
        return out.str();
    }

    out << "STRINGS\n";
    for (const auto& s : v) {
        out << "  " << hex_u64(s.offset) << " [" << string_encoding_name(s.encoding)
            << "] " << s.text << "\n";
    }
    return out.str();
}

std::string format_hexdump(const std::vector<HexdumpLine>& v, bool json) {
    std::ostringstream out;
    if (json) {
        out << "{\"schema_version\":4,\"lines\":[";
        for (std::size_t i = 0; i < v.size(); ++i) {
            if (i) out << ",";
            out << "{\"offset\":\"" << hex_u64(v[i].offset) << "\",\"bytes\":\"";
            for (auto byte : v[i].bytes) {
                out << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
            }
            out << "\"}";
        }
        out << "]}\n";
        return out.str();
    }

    for (const auto& line : v) {
        out << std::hex << std::setw(8) << std::setfill('0') << line.offset << "  ";
        for (std::size_t i = 0; i < line.bytes.size(); ++i) {
            if (i == 8) out << " ";
            out << std::setw(2) << static_cast<unsigned>(line.bytes[i]) << " ";
        }
        out << std::setfill(' ') << " |";
        for (auto byte : line.bytes) {
            out << ((byte >= 32 && byte <= 126) ? static_cast<char>(byte) : '.');
        }
        out << "|\n";
    }
    return out.str();
}

std::string format_search(const std::vector<SearchMatch>& v, bool json) {
    std::ostringstream out;
    if (json) {
        out << "{\"schema_version\":4,\"matches\":[";
        for (std::size_t i = 0; i < v.size(); ++i) {
            if (i) out << ",";
            out << "{\"offset\":\"" << hex_u64(v[i].offset)
                << "\",\"length\":" << v[i].length << "}";
        }
        out << "]}\n";
        return out.str();
    }

    out << "SEARCH MATCHES: " << v.size() << "\n";
    for (const auto& match : v) {
        out << "  " << hex_u64(match.offset) << " (" << match.length << " bytes)\n";
    }
    return out.str();
}

std::string format_regions(const std::vector<BinaryRegion>& v, bool json) {
    std::ostringstream out;
    if (json) {
        out << "{\"schema_version\":4,\"regions\":[";
        for (std::size_t i = 0; i < v.size(); ++i) {
            if (i) out << ",";
            out << "{\"offset\":\"" << hex_u64(v[i].offset)
                << "\",\"size\":" << v[i].size
                << ",\"kind\":\"" << region_kind_name(v[i].kind) << "\"}";
        }
        out << "]}\n";
        return out.str();
    }

    out << "BINARY REGIONS\n";
    for (const auto& region : v) {
        out << "  " << hex_u64(region.offset) << " - " << region.size
            << " bytes  " << region_kind_name(region.kind) << "\n";
    }
    return out.str();
}

} // namespace binx
