#include "binx/formats/pe.hpp"
#include "binx/core/byte_reader.hpp"
#include <cstdint>
#include <cstring>
namespace binx {
namespace {
std::uint16_t le16(const std::byte* p) { return std::uint16_t(std::to_integer<unsigned char>(p[0])) | (std::uint16_t(std::to_integer<unsigned char>(p[1])) << 8); }
std::uint32_t le32(const std::byte* p) { return std::uint32_t(std::to_integer<unsigned char>(p[0])) | (std::uint32_t(std::to_integer<unsigned char>(p[1])) << 8) | (std::uint32_t(std::to_integer<unsigned char>(p[2])) << 16) | (std::uint32_t(std::to_integer<unsigned char>(p[3])) << 24); }
}
bool parse_pe(std::span<const std::byte> data, Metadata& m) {
    if (data.size() < 2 || std::to_integer<unsigned char>(data[0]) != 'M' || std::to_integer<unsigned char>(data[1]) != 'Z') return false;
    m.platform = "Windows";
    if (data.size() < 0x40) { m.valid=false; m.format=BinaryFormat::Unknown; m.diagnostic="DOS header is truncated"; return true; }
    const std::uint32_t pe_offset=le32(data.data()+0x3c);
    if (pe_offset > data.size()-4 || std::memcmp(data.data()+pe_offset,"PE\0\0",4)!=0) {
        m.valid=false; m.format=BinaryFormat::Unknown; m.diagnostic="MZ header found, but PE signature is missing or outside the file"; return true;
    }
    if (data.size()-pe_offset < 24) { m.valid=false; m.format=BinaryFormat::Unknown; m.diagnostic="PE/COFF header is truncated"; return true; }
    const auto machine=le16(data.data()+pe_offset+4);
    const auto sections=le16(data.data()+pe_offset+6);
    m.raw_machine=machine; m.section_count=sections; m.timestamp=le32(data.data()+pe_offset+8);
    const auto optional_size=le16(data.data()+pe_offset+20);
    const std::size_t optional_offset=static_cast<std::size_t>(pe_offset)+24;
    if (optional_offset>data.size() || optional_size>data.size()-optional_offset) { m.valid=false; m.format=BinaryFormat::Unknown; m.diagnostic="optional header extends past the end of the file"; return true; }
    if (optional_size<70) { m.valid=false; m.format=BinaryFormat::Unknown; m.diagnostic="optional header is too short for the v0.1 metadata fields"; return true; }
    const auto magic=le16(data.data()+optional_offset);
    m.format=magic==0x10b?BinaryFormat::PE32:magic==0x20b?BinaryFormat::PE64:BinaryFormat::Unknown;
    if(m.format==BinaryFormat::Unknown){m.valid=false;m.diagnostic="unsupported or invalid PE optional-header magic";return true;}
    if(machine==0x14c)m.architecture=Architecture::X86; else if(machine==0x8664)m.architecture=Architecture::X86_64; else if(machine==0x1c0)m.architecture=Architecture::ARM; else if(machine==0xaa64)m.architecture=Architecture::ARM64;
    m.endianness=Endianness::Little;
    try {
        ByteReader r(data);
        r.seek(optional_offset+16);
        const auto entry_rva=r.u32_le(); m.entry_point_rva=entry_rva;
        r.seek(optional_offset+(m.format==BinaryFormat::PE64?24:28));
        const auto image_base=m.format==BinaryFormat::PE64?r.u64_le():r.u32_le(); m.image_base=image_base;
        if(image_base<=UINT64_MAX-entry_rva)m.entry_point=image_base+entry_rva; else {m.valid=false;m.diagnostic="entry-point address overflows the image base";}
        r.seek(optional_offset+56);m.image_size=r.u32_le();
        r.seek(optional_offset+60);m.headers_size=r.u32_le();
        r.seek(optional_offset+68);m.subsystem=r.u16_le();
    } catch(...) {m.valid=false;m.diagnostic="failed to read required PE optional-header fields";}
    return true;
}
}
