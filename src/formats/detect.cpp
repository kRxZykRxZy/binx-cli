#include "binx/formats/detect.hpp"
#include "binx/formats/elf.hpp"
#include "binx/formats/macho.hpp"
#include "binx/formats/pe.hpp"
namespace binx {
Metadata detect_metadata(std::span<const std::byte> data) {
    Metadata m;
    if (identify_pe(data, m)) return m;
    if (auto er = parse_elf_image(data); er) { const auto& e = er.value(); m.platform="ELF"; m.format=e.elf_class==ELFClass::ELF64?BinaryFormat::ELF64:BinaryFormat::ELF32; m.endianness=e.endianness; m.raw_machine=e.machine; m.entry_point=e.entry; m.section_count=e.shnum; m.valid=e.header_status!=ParseStatus::Malformed; m.diagnostic=e.diagnostics.empty()?"":e.diagnostics.front().message; switch(e.machine){case 3:m.architecture=Architecture::X86;break;case 62:m.architecture=Architecture::X86_64;break;case 40:m.architecture=Architecture::ARM;break;case 183:m.architecture=Architecture::ARM64;break;case 243:m.architecture=e.elf_class==ELFClass::ELF64?Architecture::RISCV64:Architecture::RISCV32;break;default:break;} return m; }
    if (parse_macho(data, m)) return m;
    m.format = BinaryFormat::Raw;
    m.valid = true;
    m.diagnostic = "no recognized executable binary format";
    return m;
}
const char* format_name(BinaryFormat f) {
    switch(f) {
        case BinaryFormat::PE32:return "PE32"; case BinaryFormat::PE64:return "PE32+";
        case BinaryFormat::ELF32:return "ELF32"; case BinaryFormat::ELF64:return "ELF64";
        case BinaryFormat::MachO32:return "Mach-O 32"; case BinaryFormat::MachO64:return "Mach-O 64";
        case BinaryFormat::MachOFat:return "Mach-O Fat"; case BinaryFormat::Raw:return "Raw / unknown";
        default:return "Unknown / invalid";
    }
}
const char* architecture_name(Architecture a) {
    switch(a) {
        case Architecture::X86:return "x86"; case Architecture::X86_64:return "x86-64";
        case Architecture::ARM:return "ARM"; case Architecture::ARM64:return "ARM64";
        case Architecture::RISCV32:return "RISC-V 32"; case Architecture::RISCV64:return "RISC-V 64";
        default:return "unknown";
    }
}
const char* endianness_name(Endianness e) {
    switch(e) { case Endianness::Little:return "little"; case Endianness::Big:return "big"; default:return "unknown"; }
}
}
