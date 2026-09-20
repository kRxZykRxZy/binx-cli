#include "binx/cli/commands.hpp"

namespace binx {

bool is_pe_command(std::string_view c) {
    return c == "inspect" || c == "sections" || c == "imports" ||
           c == "exports" || c == "resources" || c == "relocations";
}

bool is_elf_command(std::string_view c) {
    return c == "inspect" || c == "sections" || c == "segments" ||
           c == "symbols" || c == "dynamic" || c == "notes" ||
           c == "relocations";
}

bool is_analysis_command(std::string_view c) {
    return c == "strings" || c == "hexdump" || c == "search" ||
           c == "regions" || c == "size";
}

bool is_diff_command(std::string_view c) {
    return c == "diff" || c == "compare";
}

bool is_dependency_command(std::string_view c) {
    return c == "deps" || c == "dependencies" || c == "graph";
}

bool is_disassembly_command(std::string_view c) {
    return c == "disasm" || c == "disassemble";
}

bool is_symbols_command(std::string_view c) {
    return c == "symbols" || c == "sym";
}

bool is_debug_command(std::string_view c) {
    return c == "debug" || c == "debug-info";
}

bool is_crash_command(std::string_view c) {
    return c == "crash" || c == "crash-analysis";
}

bool is_report_command(std::string_view c) {
    return c == "report" || c == "analyze";
}

bool is_supported_command(std::string_view c) {
    return c == "help" || c == "version" || c == "info" || c == "inspect" ||
           c == "hash" || is_analysis_command(c) || is_diff_command(c) ||
           is_dependency_command(c) || is_disassembly_command(c) ||
           is_symbols_command(c) || is_debug_command(c) ||
           is_crash_command(c) || is_report_command(c) ||
           is_pe_command(c) || is_elf_command(c);
}

} // namespace binx
