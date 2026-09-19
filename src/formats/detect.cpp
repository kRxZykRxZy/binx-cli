#include "binx/formats/detect.hpp"
#include "binx/core/byte_reader.hpp"
#include <cstring>
namespace binx {
static bool has(std::span<const std::byte> d, std::size_t n){return d.size()>=n;}
static std::uint32_t be32(const std::byte* p){return (std::uint32_t(std::to_integer<unsigned char>(p[0]))<<24)|(std::uint32_t(std::to_integer<unsigned char>(p[1]))<<16)|(std::uint32_t(std::to_integer<unsigned char>(p[2]))<<8)|std::uint32_t(std::to_integer<unsigned char>(p[3]));}
static std::uint32_t le32(const std::byte* p){return std::uint32_t(std::to_integer<unsigned char>(p[0]))|(std::uint32_t(std::to_integer<unsigned char>(p[1]))<<8)|(std::uint32_t(std::to_integer<unsigned char>(p[2]))<<16)|(std::uint32_t(std::to_integer<unsigned char>(p[3]))<<24);}
Metadata detect_metadata(std::span<const std::byte> d){
 Metadata m;
 if(has(d,20)&&std::to_integer<unsigned char>(d[0])==0x7f&&std::memcmp(d.data()+1,"ELF",3)==0){
  auto cls=std::to_integer<unsigned char>(d[4]), data=std::to_integer<unsigned char>(d[5]);
  m.format=cls==1?BinaryFormat::ELF32:cls==2?BinaryFormat::ELF64:BinaryFormat::Unknown;
  m.endianness=data==1?Endianness::Little:data==2?Endianness::Big:Endianness::Unknown;
  if(m.format!=BinaryFormat::Unknown){
   std::uint16_t machine=m.endianness==Endianness::Little?std::uint16_t(std::to_integer<unsigned char>(d[18]))|(std::uint16_t(std::to_integer<unsigned char>(d[19]))<<8):(std::uint16_t(std::to_integer<unsigned char>(d[18]))<<8)|std::to_integer<unsigned char>(d[19]);
   m.raw_machine=machine; if(machine==3)m.architecture=Architecture::X86; else if(machine==62)m.architecture=Architecture::X86_64; else if(machine==40)m.architecture=Architecture::ARM; else if(machine==183)m.architecture=Architecture::ARM64; else if(machine==243)m.architecture=Architecture::RISCV64;
   m.platform="ELF"; try{ByteReader r(d);r.seek(24);m.entry_point=m.format==BinaryFormat::ELF64?(m.endianness==Endianness::Little?r.u64_le():r.u64_be()):(m.endianness==Endianness::Little?r.u32_le():r.u32_be());}catch(...){}
  } return m;
 }
 if(has(d,2)&&std::to_integer<unsigned char>(d[0])=='M'&&std::to_integer<unsigned char>(d[1])=='Z'&&d.size()>=0x40){
  auto peoff=le32(d.data()+0x3c); if(peoff<=d.size()-4&&std::memcmp(d.data()+peoff,"PE\0\0",4)==0&&d.size()>=peoff+24){
   auto machine=le32(d.data()+peoff+4)&0xffffu, sections=le32(d.data()+peoff+6)&0xffffu, optsize=le32(d.data()+peoff+20)&0xffffu, opt=peoff+24ull;
   if(opt<=d.size()&&optsize>=2&&opt+optsize<=d.size()){
    auto magic=std::uint16_t(std::to_integer<unsigned char>(d[opt]))|(std::uint16_t(std::to_integer<unsigned char>(d[opt+1]))<<8);
    m.format=magic==0x10b?BinaryFormat::PE32:magic==0x20b?BinaryFormat::PE64:BinaryFormat::Unknown;m.raw_machine=machine;m.section_count=sections;m.endianness=Endianness::Little;m.platform="Windows";
    if(machine==0x14c)m.architecture=Architecture::X86;else if(machine==0x8664)m.architecture=Architecture::X86_64;else if(machine==0x1c0)m.architecture=Architecture::ARM;else if(machine==0xaa64)m.architecture=Architecture::ARM64;
    if(m.format==BinaryFormat::PE32||m.format==BinaryFormat::PE64)try{ByteReader r(d);r.seek(opt+16);m.entry_point=r.u32_le();r.seek(opt+(m.format==BinaryFormat::PE64?24:28));m.image_base=m.format==BinaryFormat::PE64?r.u64_le():r.u32_le();}catch(...){}
   }
   return m;
  }
 }
 if(has(d,4)){auto x=be32(d.data());if(x==0xfeedface||x==0xcefaedfe)m.format=BinaryFormat::MachO32;else if(x==0xfeedfacf||x==0xcffaedfe)m.format=BinaryFormat::MachO64;else if(x==0xcafebabe||x==0xbebafeca||x==0xcafebabf||x==0xbfbafeca)m.format=BinaryFormat::MachOFat;if(m.format!=BinaryFormat::Unknown)m.platform="Mach-O";}
 if(m.format==BinaryFormat::Unknown)m.format=BinaryFormat::Raw; return m;
}
const char* format_name(BinaryFormat f){switch(f){case BinaryFormat::PE32:return"PE32";case BinaryFormat::PE64:return"PE32+";case BinaryFormat::ELF32:return"ELF32";case BinaryFormat::ELF64:return"ELF64";case BinaryFormat::MachO32:return"Mach-O 32";case BinaryFormat::MachO64:return"Mach-O 64";case BinaryFormat::MachOFat:return"Mach-O Fat";case BinaryFormat::Raw:return"Raw / unknown";default:return"Unknown";}}
const char* architecture_name(Architecture a){switch(a){case Architecture::X86:return"x86";case Architecture::X86_64:return"x86-64";case Architecture::ARM:return"ARM";case Architecture::ARM64:return"ARM64";case Architecture::RISCV32:return"RISC-V 32";case Architecture::RISCV64:return"RISC-V 64";default:return"unknown";}}
const char* endianness_name(Endianness e){switch(e){case Endianness::Little:return"little";case Endianness::Big:return"big";default:return"unknown";}}
}