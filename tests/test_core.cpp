#include "binx/core/byte_reader.hpp"
#include "binx/formats/detect.hpp"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

using namespace binx;
int main(){
 std::vector<std::byte> d={std::byte{0x78},std::byte{0x56},std::byte{0x34},std::byte{0x12},std::byte{0x01},std::byte{0x02}};
 ByteReader r(d);
 assert(r.u32_le()==0x12345678u);
 assert(r.u16_be()==0x0102u);
 bool threw=false; try{r.u8();}catch(...){threw=true;} assert(threw);
 std::vector<std::byte> elf={std::byte{0x7f},std::byte{'E'},std::byte{'L'},std::byte{'F'},std::byte{2},std::byte{1},std::byte{1},std::byte{0}};
 auto m=detect_metadata(elf); assert(m.format==BinaryFormat::ELF64); assert(m.endianness==Endianness::Little);
 std::vector<std::byte> mz={std::byte{'M'},std::byte{'Z'}};
 auto raw=detect_metadata(mz); assert(raw.format==BinaryFormat::Raw);
 return 0;
}
