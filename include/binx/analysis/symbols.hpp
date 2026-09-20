#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include "binx/core/binary.hpp"
namespace binx {
enum class SymbolKind { Function, Object, Section, Import, Export, Debug, Unknown };
struct SymbolRecord {
 std::string name; SymbolKind kind=SymbolKind::Unknown; std::uint64_t address=0,size=0; std::optional<std::uint64_t> file_offset;
 std::string binding, source, module; bool external=false, weak=false;
};
struct DebugInfo {
 bool has_dwarf=false, has_pdb=false;
 std::string format;
 std::vector<std::string> dwarf_sections;
 std::size_t compilation_units=0;
 std::vector<std::string> pdb_files;
 std::string pdb_guid; std::uint32_t pdb_age=0;
};
Result<std::vector<SymbolRecord>> collect_symbols(const BinaryFile&);
Result<DebugInfo> collect_debug_info(const BinaryFile&);
const char* symbol_kind_name(SymbolKind);
std::string format_symbols(const std::vector<SymbolRecord>&, bool json);
std::string format_debug_info(const DebugInfo&, bool json);
}