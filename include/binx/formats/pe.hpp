#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>
#include "binx/core/binary.hpp"
#include "binx/error.hpp"

namespace binx {

enum class PEClass { PE32, PE64 };

enum class ParseStatus {
    NotPresent,
    NotParsed,
    Valid,
    PartiallyParsed,
    Malformed,
    Unsupported
};

enum class DiagnosticSeverity { Info, Warning, Error };

struct Diagnostic {
    DiagnosticSeverity severity = DiagnosticSeverity::Info;
    std::string code;
    std::string component;
    std::optional<std::uint64_t> file_offset;
    std::optional<std::uint64_t> rva;
    std::string message;
};

struct ByteRange {
    std::uint64_t start = 0;
    std::uint64_t size = 0;
};

struct DataDirectory {
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
    bool present = false;
    bool mapped = false;
};

struct COFFHeader {
    std::uint16_t machine = 0;
    std::uint16_t number_of_sections = 0;
    std::uint32_t timestamp = 0;
    std::uint32_t pointer_to_symbol_table = 0;
    std::uint32_t number_of_symbols = 0;
    std::uint16_t optional_header_size = 0;
    std::uint16_t characteristics = 0;
};

struct OptionalHeader {
    PEClass pe_class = PEClass::PE64;
    std::uint16_t magic = 0;
    std::uint8_t major_linker_version = 0;
    std::uint8_t minor_linker_version = 0;
    std::uint32_t size_of_code = 0;
    std::uint32_t size_of_initialized_data = 0;
    std::uint32_t size_of_uninitialized_data = 0;
    std::uint32_t address_of_entry_point = 0;
    std::uint32_t base_of_code = 0;
    std::uint64_t image_base = 0;
    std::uint32_t section_alignment = 0;
    std::uint32_t file_alignment = 0;
    std::uint16_t major_os_version = 0;
    std::uint16_t minor_os_version = 0;
    std::uint16_t major_image_version = 0;
    std::uint16_t minor_image_version = 0;
    std::uint16_t major_subsystem_version = 0;
    std::uint16_t minor_subsystem_version = 0;
    std::uint32_t win32_version_value = 0;
    std::uint32_t size_of_image = 0;
    std::uint32_t size_of_headers = 0;
    std::uint32_t checksum = 0;
    std::uint16_t subsystem = 0;
    std::uint16_t dll_characteristics = 0;
    std::uint64_t size_of_stack_reserve = 0;
    std::uint64_t size_of_stack_commit = 0;
    std::uint64_t size_of_heap_reserve = 0;
    std::uint64_t size_of_heap_commit = 0;
    std::uint32_t loader_flags = 0;
    std::uint32_t number_of_rva_and_sizes = 0;
};

struct PESection {
    std::size_t index = 0;
    std::string name;
    std::uint32_t virtual_size = 0;
    std::uint32_t virtual_address = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t raw_pointer = 0;
    std::uint32_t characteristics = 0;
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool discardable = false;
    bool shared = false;
};

struct ImportSymbol {
    std::optional<std::string> name;
    std::optional<std::uint16_t> hint;
    std::optional<std::uint16_t> ordinal;
    std::uint64_t lookup_rva = 0;
    std::uint64_t iat_rva = 0;
    std::optional<std::uint64_t> lookup_file_offset;
    std::optional<std::uint64_t> iat_file_offset;
    bool imported_by_name = false;
};

struct ImportModule {
    std::string dll_name;
    std::uint32_t descriptor_rva = 0;
    std::uint32_t lookup_rva = 0;
    std::uint32_t iat_rva = 0;
    std::uint32_t timestamp = 0;
    std::uint32_t forwarder_chain = 0;
    std::vector<ImportSymbol> symbols;
};

struct ImportTable {
    std::vector<ImportModule> modules;
};

struct ExportFunction {
    std::uint32_t ordinal = 0;
    std::uint32_t ordinal_index = 0;
    std::uint32_t rva = 0;
    std::optional<std::uint64_t> file_offset;
    std::optional<std::string> name;
    std::optional<std::string> forwarder;
    bool is_forwarder = false;
};

struct ExportTable {
    std::optional<std::string> dll_name;
    std::uint32_t ordinal_base = 0;
    std::vector<ExportFunction> functions;
};

struct RelocationEntry {
    std::uint8_t type = 0;
    std::uint16_t offset = 0;
    std::uint32_t target_rva = 0;
    std::optional<std::uint64_t> target_file_offset;
    bool supported = false;
};

struct RelocationBlock {
    std::uint32_t page_rva = 0;
    std::uint32_t block_size = 0;
    std::vector<RelocationEntry> entries;
};

struct RelocationTable {
    std::vector<RelocationBlock> blocks;
};

struct ResourceItem {
    std::vector<std::string> path;
    std::uint32_t language = 0;
    std::uint32_t data_rva = 0;
    std::uint32_t data_size = 0;
    std::uint32_t code_page = 0;
    std::optional<std::uint64_t> file_offset;
};

struct ResourceTree {
    std::vector<ResourceItem> items;
};

struct TLSCallback {
    std::uint64_t va = 0;
    std::optional<std::uint32_t> rva;
    std::optional<std::uint64_t> file_offset;
};

struct TLSDirectory {
    std::uint64_t raw_data_start_va = 0;
    std::uint64_t raw_data_end_va = 0;
    std::uint64_t address_of_index_va = 0;
    std::uint64_t address_of_callbacks_va = 0;
    std::uint32_t size_of_zero_fill = 0;
    std::uint32_t characteristics = 0;
    std::vector<TLSCallback> callbacks;
};

struct CodeViewInfo {
    std::string signature;
    std::string guid;
    std::uint32_t age = 0;
    std::string pdb_path;
};

struct DebugEntry {
    std::uint32_t characteristics = 0;
    std::uint32_t timestamp = 0;
    std::uint16_t major_version = 0;
    std::uint16_t minor_version = 0;
    std::uint32_t type = 0;
    std::uint32_t size_of_data = 0;
    std::uint32_t address_of_raw_data = 0;
    std::uint32_t pointer_to_raw_data = 0;
    std::optional<CodeViewInfo> codeview;
};

struct PEHeaders {
    std::uint32_t e_lfanew = 0;
    COFFHeader coff;
    OptionalHeader optional;
    std::vector<DataDirectory> directories;
    std::optional<std::uint64_t> entry_point_file_offset;
    std::optional<std::size_t> entry_point_section;
};

class RVAMapper {
public:
    RVAMapper() = default;
    RVAMapper(std::uint64_t file_size, std::uint32_t size_of_headers,
              std::vector<PESection> sections);

    Result<std::uint64_t> rva_to_file_offset(std::uint32_t rva) const;
    Result<std::uint32_t> file_offset_to_rva(std::uint64_t offset) const;
    Result<ByteRange> map_rva_range(std::uint32_t rva, std::uint64_t size) const;

private:
    std::uint64_t file_size_ = 0;
    std::uint32_t size_of_headers_ = 0;
    std::vector<PESection> sections_;
};

struct PEImage {
    PEHeaders headers;
    std::vector<PESection> sections;
    RVAMapper mapper;

    ParseStatus header_status = ParseStatus::NotParsed;
    ParseStatus section_status = ParseStatus::NotParsed;
    ParseStatus import_status = ParseStatus::NotParsed;
    ParseStatus export_status = ParseStatus::NotParsed;
    ParseStatus relocation_status = ParseStatus::NotParsed;
    ParseStatus resource_status = ParseStatus::NotParsed;
    ParseStatus tls_status = ParseStatus::NotParsed;
    ParseStatus debug_status = ParseStatus::NotParsed;

    std::optional<ImportTable> imports;
    std::optional<ExportTable> exports;
    std::optional<RelocationTable> relocations;
    std::optional<ResourceTree> resources;
    std::optional<TLSDirectory> tls;
    std::vector<DebugEntry> debug_entries;

    std::vector<Diagnostic> diagnostics;
};

bool identify_pe(std::span<const std::byte> data, Metadata& metadata);
Result<PEImage> parse_pe(std::span<const std::byte> data);

const char* pe_status_name(ParseStatus status);
const char* diagnostic_severity_name(DiagnosticSeverity severity);
const char* subsystem_name(std::uint16_t subsystem);
std::vector<std::string> coff_characteristic_names(std::uint16_t value);
std::vector<std::string> dll_characteristic_names(std::uint16_t value);
std::string machine_name(std::uint16_t machine);

}
