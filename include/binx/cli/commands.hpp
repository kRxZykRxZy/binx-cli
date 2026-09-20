#pragma once
#include <string_view>

namespace binx {

bool is_pe_command(std::string_view command);
bool is_elf_command(std::string_view command);
bool is_analysis_command(std::string_view command);
bool is_diff_command(std::string_view command);
bool is_dependency_command(std::string_view command);
bool is_disassembly_command(std::string_view command);
bool is_symbols_command(std::string_view command);
bool is_debug_command(std::string_view command);
bool is_crash_command(std::string_view command);
bool is_report_command(std::string_view command);
bool is_supported_command(std::string_view command);

} // namespace binx
