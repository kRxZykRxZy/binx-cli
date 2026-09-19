#include "binx/formats/macho.hpp"
#include <cstdint>
namespace binx {
namespace {
enum class MagicKind{None,M32BE,M32LE,M64BE,M64LE,FatBE,FatLE,Fat64BE,Fat64LE};
MagicKind magic(std::uint32_t x){switch(x){case 0xfeedface:return MagicKind::M32BE;case 0xcefaedfe:return MagicKind::M32LE;case 0xfeedfacf:return MagicKind::M64BE;case 0xcffaedfe:return MagicKind::M64LE;case 0xcafebabe:return MagicKind::FatBE;case 0xbebafeca:return MagicKind::FatLE;case 0xcafebabf:return MagicKind::Fat64BE;case 0xbfbafeca:return MagicKind::Fat64LE;default:return MagicKind::None;}}
std::uint32_t be32(const std::byte*p){return(std::uint32_t(std::to_integer<unsigned char>(p[0]))<<24)|(std::uint32_t(std::to_integer<unsigned char>(p[1]))<<16)|(std::uint32_t(std::to_integer<unsigned char>(p[2]))<<8)|std::uint32_t(std::to_integer<unsigned char>(p[3]));}
std::uint32_t le32(const std::byte*p){return std::uint32_t(std::to_integer<unsigned char>(p[0]))|(std::uint32_t(std::to_integer<unsigned char>(p[1]))<<8)|(std::uint32_t(std::to_integer<unsigned char>(p[2]))<<16)|(std::uint32_t(std::to_integer<unsigned char>(p[3]))<<24);}
}
bool parse_macho(std::span<const std::byte> data, Metadata& m){
    if(data.size()<4)return false;
    const auto k=magic(be32(data.data()));
    if(k==MagicKind::None)return false;
    m.platform="Mach-O";
    m.endianness=(k==MagicKind::M32LE||k==MagicKind::M64LE||k==MagicKind::FatLE||k==MagicKind::Fat64LE)?Endianness::Little:Endianness::Big;
    if(k==MagicKind::FatBE||k==MagicKind::FatLE||k==MagicKind::Fat64BE||k==MagicKind::Fat64LE){
        m.format=BinaryFormat::MachOFat;
        if(data.size()<8){m.valid=false;m.format=BinaryFormat::Unknown;m.diagnostic="fat Mach-O header is truncated";}
        return true;
    }
    m.format=(k==MagicKind::M32BE||k==MagicKind::M32LE)?BinaryFormat::MachO32:BinaryFormat::MachO64;
    if(data.size()<8){m.valid=false;m.format=BinaryFormat::Unknown;m.diagnostic="Mach-O header is truncated";return true;}
    const auto cpu=m.endianness==Endianness::Little?le32(data.data()+4):be32(data.data()+4);
    const auto base=cpu&0x00ffffffu;
    if(base==7)m.architecture=(cpu&0x01000000u)?Architecture::X86_64:Architecture::X86;
    else if(base==12)m.architecture=(cpu&0x01000000u)?Architecture::ARM64:Architecture::ARM;
    return true;
}
}
