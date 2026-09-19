#include "binx/core/binary.hpp"
#include "binx/core/byte_reader.hpp"
#include "binx/formats/detect.hpp"
#include "binx/hashing/hasher.hpp"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
using namespace binx;
namespace {
void put16le(std::vector<std::byte>&b,std::size_t o,std::uint16_t v){b[o]=std::byte(v&0xff);b[o+1]=std::byte((v>>8)&0xff);}
void put32le(std::vector<std::byte>&b,std::size_t o,std::uint32_t v){for(int i=0;i<4;++i)b[o+i]=std::byte((v>>(8*i))&0xff);}
void put64le(std::vector<std::byte>&b,std::size_t o,std::uint64_t v){for(int i=0;i<8;++i)b[o+i]=std::byte((v>>(8*i))&0xff);}
std::vector<std::byte>pe(){std::vector<std::byte>b(0x220);b[0]=std::byte{'M'};b[1]=std::byte{'Z'};put32le(b,0x3c,0x80);b[0x80]=std::byte{'P'};b[0x81]=std::byte{'E'};put16le(b,0x84,0x8664);put16le(b,0x86,3);put32le(b,0x88,0x12345678);put16le(b,0x94,0xf0);put16le(b,0x98,0x20b);put32le(b,0xa8,0x1000);put64le(b,0xb0,0x140000000ull);put32le(b,0xd0,0x5000);put32le(b,0xd4,0x400);put16le(b,0xdc,3);return b;}
std::vector<std::byte>elf(){std::vector<std::byte>b(64);b[0]=std::byte{0x7f};b[1]=std::byte{'E'};b[2]=std::byte{'L'};b[3]=std::byte{'F'};b[4]=std::byte{2};b[5]=std::byte{1};put16le(b,18,62);put64le(b,24,0x401000);put16le(b,60,7);return b;}
}
int main(){
 std::vector<std::byte>d={std::byte{0x78},std::byte{0x56},std::byte{0x34},std::byte{0x12},std::byte{0x01},std::byte{0x02}};ByteReader r(d);assert(r.u32_le()==0x12345678u);assert(r.u16_be()==0x0102u);bool threw=false;try{r.u8();}catch(...){threw=true;}assert(threw);r.seek(d.size());assert(!r.can_read(1));
 auto p=detect_metadata(pe());assert(p.valid&&p.format==BinaryFormat::PE64&&p.architecture==Architecture::X86_64);assert(p.entry_point_rva&&*p.entry_point_rva==0x1000);assert(p.entry_point&&*p.entry_point==0x140001000ull);assert(p.image_base&&*p.image_base==0x140000000ull);assert(p.section_count&&*p.section_count==3);assert(p.image_size&&*p.image_size==0x5000);
 auto e=detect_metadata(elf());assert(e.valid&&e.format==BinaryFormat::ELF64&&e.architecture==Architecture::X86_64);assert(e.entry_point&&*e.entry_point==0x401000ull);assert(e.section_count&&*e.section_count==7);
 std::vector<std::byte>m(8);m[0]=std::byte{0xcf};m[1]=std::byte{0xfa};m[2]=std::byte{0xed};m[3]=std::byte{0xfe};m[4]=std::byte{0x07};m[5]=std::byte{0x00};m[6]=std::byte{0x00};m[7]=std::byte{0x01};auto mo=detect_metadata(m);assert(mo.valid&&mo.format==BinaryFormat::MachO64&&mo.architecture==Architecture::X86_64&&mo.endianness==Endianness::Little);
 std::vector<std::byte>bad(64);bad[0]=std::byte{'M'};bad[1]=std::byte{'Z'};put32le(bad,0x3c,0xffffff00u);auto invalid=detect_metadata(bad);assert(!invalid.valid&&invalid.format==BinaryFormat::Unknown);
 const std::vector<std::byte>abc={std::byte{'a'},std::byte{'b'},std::byte{'c'}};auto h=hash_all(abc);assert(h);assert(h.value().md5=="900150983cd24fb0d6963f7d28e17f72");assert(h.value().sha1=="a9993e364706816aba3e25717850c26c9cd0d89d");assert(h.value().sha256=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
 const auto temp=std::filesystem::temp_directory_path()/"binx_v01_test.bin";{std::ofstream f(temp,std::ios::binary|std::ios::trunc);f<<"BINX";}auto loaded=BinaryFile::open(temp);assert(loaded&&loaded.value().size()==4&&loaded.value().bytes()[0]==std::byte{'B'});std::filesystem::remove(temp);
 return 0;
}
