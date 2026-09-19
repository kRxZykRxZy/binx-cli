#include "binx/core/byte_reader.hpp"
#include "binx/formats/detect.hpp"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>
using namespace binx;
int main(){
 std::vector<std::byte> d={std::byte{0x78},std::byte{0x56},std::byte{0x34},std::byte{0x12},std::byte{0x01},std::byte{0x02}};
 ByteReader r(d); assert(r.u32_le()==0x12345678u); assert(r.u16_be()==0x0102u);
 bool threw=false;try{r.u8();}catch(...){threw=true;}assert(threw);
 std::vector<std::byte> elf(20); elf[0]=std::byte{0x7f};elf[1]=std::byte{'E'};elf[2]=std::byte{'L'};elf[3]=std::byte{'F'};elf[4]=std::byte{2};elf[5]=std::byte{1};elf[18]=std::byte{62};
 auto m=detect_metadata(elf);assert(m.format==BinaryFormat::ELF64);assert(m.endianness==Endianness::Little);assert(m.architecture==Architecture::X86_64);
 std::vector<std::byte> mz={std::byte{'M'},std::byte{'Z'}};auto raw=detect_metadata(mz);assert(raw.format==BinaryFormat::Raw);
 return 0;
}
