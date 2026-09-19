#include "binx/formats/elf.hpp"
#include "binx/core/byte_reader.hpp"
#include <cstdint>
#include <cstring>
namespace binx {
namespace {
std::uint16_t read16(ByteReader& r, Endianness e){return e==Endianness::Little?r.u16_le():r.u16_be();}
std::uint32_t read32(ByteReader& r, Endianness e){return e==Endianness::Little?r.u32_le():r.u32_be();}
std::uint64_t read64(ByteReader& r, Endianness e){return e==Endianness::Little?r.u64_le():r.u64_be();}
}
bool parse_elf(std::span<const std::byte> data, Metadata& m){
    if(data.size()<4||std::to_integer<unsigned char>(data[0])!=0x7f||std::memcmp(data.data()+1,"ELF",3)!=0)return false;
    m.platform="ELF";
    if(data.size()<20){m.valid=false;m.format=BinaryFormat::Unknown;m.diagnostic="ELF header is truncated";return true;}
    const auto cls=std::to_integer<unsigned char>(data[4]), enc=std::to_integer<unsigned char>(data[5]);
    m.endianness=enc==1?Endianness::Little:enc==2?Endianness::Big:Endianness::Unknown;
    m.format=cls==1?BinaryFormat::ELF32:cls==2?BinaryFormat::ELF64:BinaryFormat::Unknown;
    if(m.format==BinaryFormat::Unknown||m.endianness==Endianness::Unknown){m.valid=false;m.diagnostic="unsupported ELF class or byte order";return true;}
    const std::size_t need=m.format==BinaryFormat::ELF64?64:52;
    if(data.size()<need){m.valid=false;m.format=BinaryFormat::Unknown;m.diagnostic="ELF header is truncated";return true;}
    try{
        ByteReader r(data);r.seek(16);
        (void)read16(r,m.endianness);const auto machine=read16(r,m.endianness);(void)read32(r,m.endianness);
        m.raw_machine=machine;
        if(machine==3)m.architecture=Architecture::X86;
        else if(machine==62)m.architecture=Architecture::X86_64;
        else if(machine==40)m.architecture=Architecture::ARM;
        else if(machine==183)m.architecture=Architecture::ARM64;
        else if(machine==243)m.architecture=cls==1?Architecture::RISCV32:Architecture::RISCV64;
        r.seek(24);m.entry_point=cls==2?read64(r,m.endianness):read32(r,m.endianness);
        r.seek(cls==2?60:48);m.section_count=read16(r,m.endianness);
    }catch(...){m.valid=false;m.diagnostic="failed to read required ELF header fields";}
    return true;
}
}
