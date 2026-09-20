#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>
#include "binx/core/binary.hpp"
#include "binx/formats/pe.hpp"

namespace binx {
enum class ELFClass { ELF32, ELF64 };
struct ELFSection {
    std::size_t index=0; std::string name; std::uint32_t type=0; std::uint64_t flags=0;
    std::uint64_t address=0; std::uint64_t offset=0; std::uint64_t size=0;
    std::uint32_t link=0, info=0; std::uint64_t addralign=0, entsize=0;
};
struct ELFSegment {
    std::size_t index=0; std::uint32_t type=0, flags=0; std::uint64_t offset=0,vaddr=0,paddr=0,file_size=0,memory_size=0,align=0;
    std::optional<std::string> interpreter;
};
struct ELFSymbol {
    std::string name; std::uint8_t bind=0,type=0,visibility=0; std::uint16_t shndx=0;
    std::uint64_t value=0,size=0; std::optional<std::string> version;
};
struct ELFDynamic { std::int64_t tag=0; std::uint64_t value=0; std::optional<std::string> name; };
struct ELFNote { std::string name; std::uint32_t type=0; std::vector<std::byte> desc; };
struct ELFRelocation { std::uint64_t offset=0,info=0,addend=0; bool has_addend=false; std::uint64_t symbol=0,type=0; std::string symbol_name; };
struct ELFImage {
    ELFClass elf_class=ELFClass::ELF64; Endianness endianness=Endianness::Unknown;
    std::uint16_t type=0,machine=0; std::uint32_t version=0,flags=0;
    std::uint64_t entry=0,phoff=0,shoff=0; std::uint16_t phentsize=0,phnum=0,shentsize=0,shnum=0,shstrndx=0;
    std::vector<ELFSection> sections; std::vector<ELFSegment> segments; std::vector<ELFSymbol> symbols;
    std::vector<ELFDynamic> dynamic; std::vector<ELFNote> notes; std::vector<ELFRelocation> relocations;
    std::optional<std::string> interpreter;
    std::vector<Diagnostic> diagnostics;
    ParseStatus header_status=ParseStatus::NotParsed, section_status=ParseStatus::NotParsed, segment_status=ParseStatus::NotParsed;
    ParseStatus symbol_status=ParseStatus::NotParsed, dynamic_status=ParseStatus::NotParsed, note_status=ParseStatus::NotParsed, relocation_status=ParseStatus::NotParsed;
};
Result<ELFImage> parse_elf_image(std::span<const std::byte> data);
const char* elf_type_name(std::uint16_t);
const char* elf_machine_name(std::uint16_t);
const char* elf_section_type_name(std::uint32_t);
const char* elf_segment_type_name(std::uint32_t);
std::string elf_section_flags(std::uint64_t);
std::string elf_segment_flags(std::uint32_t);
const char* elf_symbol_bind_name(std::uint8_t);
const char* elf_symbol_type_name(std::uint8_t);
const char* elf_dynamic_tag_name(std::int64_t);
}
