#include "binx/core/byte_reader.hpp"
#include "binx/formats/pe.hpp"
#include "binx/formats/detect.hpp"
#include "binx/formats/elf.hpp"
#include "binx/hashing/hasher.hpp"
#include "binx/analysis/byte_analysis.hpp"
#include "binx/analysis/dependencies.hpp"
#include "binx/analysis/disassembly.hpp"
#include "binx/analysis/symbols.hpp"
#include "binx/analysis/diff.hpp"
#include "binx/analysis/crash.hpp"
#include "binx/analysis/report.hpp"
#include "binx/core/text.hpp"
#include <fstream>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <iterator>
using namespace binx;
namespace {
void p16(std::vector<std::byte>&b,std::size_t o,std::uint16_t v){b[o]=std::byte(v&255);b[o+1]=std::byte((v>>8)&255);}
void p32(std::vector<std::byte>&b,std::size_t o,std::uint32_t v){for(int i=0;i<4;++i)b[o+i]=std::byte((v>>(8*i))&255);}
void p64(std::vector<std::byte>&b,std::size_t o,std::uint64_t v){for(int i=0;i<8;++i)b[o+i]=std::byte((v>>(8*i))&255);}
void put(std::vector<std::byte>&b,std::size_t o,const char*s){for(std::size_t i=0;s[i];++i)b[o+i]=std::byte{static_cast<unsigned char>(s[i])};}
std::vector<std::byte> fixture(){
 std::vector<std::byte>b(0x2000);b[0]=std::byte{'M'};b[1]=std::byte{'Z'};p32(b,0x3c,0x80);b[0x80]=std::byte{'P'};b[0x81]=std::byte{'E'};p16(b,0x84,0x8664);p16(b,0x86,3);p16(b,0x94,0xF0);
 const std::size_t o=0x98;p16(b,o,0x20b);p32(b,o+16,0x1000);p64(b,o+24,0x140000000ull);p32(b,o+32,0x1000);p32(b,o+36,0x200);p32(b,o+56,0x4000);p32(b,o+60,0x400);p16(b,o+68,3);p16(b,o+70,0x8160);p32(b,o+108,16);
 const std::size_t d=o+112;p32(b,d+0*8,0x2200);p32(b,d+0*8+4,0x100);p32(b,d+1*8,0x2100);p32(b,d+1*8+4,0x80);p32(b,d+2*8,0x3000);p32(b,d+2*8+4,0x100);p32(b,d+5*8,0x2300);p32(b,d+5*8+4,0x0c);p32(b,d+6*8,0x2500);p32(b,d+6*8+4,28);p32(b,d+9*8,0x2400);p32(b,d+9*8+4,40);
 const std::size_t s=o+0xF0;const char*names[]={".text",".rdata",".rsrc"};for(int i=0;i<3;++i){for(int j=0;j<6;++j)b[s+i*40+j]=std::byte{static_cast<unsigned char>(names[i][j])};p32(b,s+i*40+8,0x1000);p32(b,s+i*40+12,0x1000*(i+1));p32(b,s+i*40+16,0x600);p32(b,s+i*40+20,0x400+0x600*i);p32(b,s+i*40+36,i==0?0x60000020:(i==1?0x40000040:0xC0000040));}
 p32(b,0xB00,0x2120);p32(b,0xB0C,0x2160);p32(b,0xB10,0x2140);p32(b,0xB20,0x2170);p32(b,0xB40,0x2170);put(b,0xB60,"KERNEL32.dll");p16(b,0xB70,1);put(b,0xB72,"GetProcAddress");
 p32(b,0xC00+16,1);p32(b,0xC00+20,1);p32(b,0xC00+24,1);p32(b,0xC00+28,0x2228);p32(b,0xC00+32,0x222C);p32(b,0xC00+36,0x2230);p32(b,0xC28,0x1100);p32(b,0xC2C,0x2290);p16(b,0xC30,0);put(b,0xC80,"fixture.dll");put(b,0xC90,"Init");
 p32(b,0xD00,0x1000);p32(b,0xD04,12);p16(b,0xD08,0xA008);p16(b,0xD0A,0);
 p16(b,0x1000+12,0);p16(b,0x1000+14,1);p32(b,0x1010,24);p32(b,0x1014,0x80000020u);p16(b,0x1020+12,0);p16(b,0x1020+14,1);p32(b,0x1030,1);p32(b,0x1034,0x80000040u);p16(b,0x1040+12,0);p16(b,0x1040+14,1);p32(b,0x1050,1033);p32(b,0x1054,0x80);p32(b,0x1080,0x3100);p32(b,0x1084,4);p32(b,0x1088,1200);put(b,0x1100,"MNF!");
 p64(b,0xE00,0x140003800ull);p64(b,0xE08,0x140003808ull);p64(b,0xE10,0x140002900ull);p64(b,0xE18,0x140003600ull);p32(b,0xE20,0);p32(b,0xE24,0);p64(b,0x1600,0x140001100ull);p64(b,0x1608,0);
 p32(b,0xF00+12,2);p32(b,0xF00+16,36);p32(b,0xF00+20,0x2D00);p32(b,0xF00+24,0x1700);put(b,0x1700,"RSDS");for(int i=0;i<16;++i)b[0x1704+i]=std::byte{static_cast<unsigned char>(i)};p32(b,0x1714,1);put(b,0x1718,"fixture.pdb");
 return b;
}
}
std::vector<std::byte> elf_fixture(){
 std::vector<std::byte>b(0x500);
 b[0]=std::byte{0x7f};b[1]=std::byte{'E'};b[2]=std::byte{'L'};b[3]=std::byte{'F'};b[4]=std::byte{2};b[5]=std::byte{1};b[6]=std::byte{1};
 p16(b,16,3);p16(b,18,62);p32(b,20,1);p64(b,24,0x400000);p64(b,32,0x40);p64(b,40,0x200);p32(b,48,0);p16(b,52,64);p16(b,54,56);p16(b,56,1);p16(b,58,64);p16(b,60,4);p16(b,62,3);
 p32(b,0x40,1);p32(b,0x44,5);p64(b,0x48,0);p64(b,0x50,0x400000);p64(b,0x58,0x400000);p64(b,0x60,0x400);p64(b,0x68,0x400);p64(b,0x70,0x1000);
 b[0x300]=std::byte{0x90};b[0x301]=std::byte{0x90};b[0x302]=std::byte{0xC3};b[0x303]=std::byte{0};
 put(b,0x320,"");put(b,0x321,".text");put(b,0x327,".shstrtab");put(b,0x331,".symtab");put(b,0x339,"func");
 const std::size_t a=0x200+64;
 p32(b,a+0,1);p32(b,a+4,1);p64(b,a+8,6);p64(b,a+16,0x400000);p64(b,a+24,0x300);p64(b,a+32,4);p32(b,a+40,0);p32(b,a+44,0);p64(b,a+48,16);p64(b,a+56,0);
 p32(b,a+64+0,7);p32(b,a+64+4,3);p64(b,a+64+8,0);p64(b,a+64+16,0);p64(b,a+64+24,0x320);p64(b,a+64+32,30);p32(b,a+64+40,0);p32(b,a+64+44,0);p64(b,a+64+48,1);p64(b,a+64+56,0);
 p32(b,a+128+0,17);p32(b,a+128+4,2);p64(b,a+128+8,0);p64(b,a+128+16,0);p64(b,a+128+24,0x380);p64(b,a+128+32,48);p32(b,a+128+40,2);p32(b,a+128+44,1);p64(b,a+128+48,8);p64(b,a+128+56,24);
 p32(b,0x380,25);b[0x384]=std::byte{0x12};b[0x385]=std::byte{0};p16(b,0x386,1);p64(b,0x388,0x400000);p64(b,0x390,4);
 return b;
}
std::vector<std::byte> elf_be_fixture(){
 std::vector<std::byte>b(64);b[0]=std::byte{0x7f};b[1]=std::byte{'E'};b[2]=std::byte{'L'};b[3]=std::byte{'F'};b[4]=std::byte{1};b[5]=std::byte{2};b[6]=std::byte{1};
 b[16]=std::byte{0};b[17]=std::byte{2};b[18]=std::byte{0};b[19]=std::byte{40};b[20]=std::byte{0};b[21]=std::byte{0};b[22]=std::byte{0};b[23]=std::byte{1};b[24]=std::byte{0};b[25]=std::byte{0};b[26]=std::byte{0};b[27]=std::byte{0};return b;
}
std::vector<std::byte> macho_dependency_fixture(){
 std::vector<std::byte>b(128);b[0]=std::byte{0xcf};b[1]=std::byte{0xfa};b[2]=std::byte{0xed};b[3]=std::byte{0xfe};
 p32(b,4,0x01000007u);p32(b,8,3);p32(b,12,2);p32(b,16,1);p32(b,20,40);p32(b,24,0);
 p32(b,32,0xcu);p32(b,36,40);p32(b,40,24);put(b,56,"/usr/lib/libSystem.B.dylib");return b;
}
int main(){
 std::vector<std::byte>d={std::byte{0x78},std::byte{0x56},std::byte{0x34},std::byte{0x12},std::byte{1},std::byte{2}};ByteReader r(d);assert(r.u32_le()==0x12345678u);assert(r.u16_be()==0x0102u);bool threw=false;try{r.u8();}catch(...){threw=true;}assert(threw);
 auto be=elf_be_fixture();auto bei=parse_elf_image(be);assert(bei&&bei.value().endianness==Endianness::Big&&bei.value().elf_class==ELFClass::ELF32&&bei.value().machine==40);auto bad=std::vector<std::byte>{std::byte{0x7f},std::byte{'E'},std::byte{'L'},std::byte{'F'},std::byte{2}};auto br=parse_elf_image(bad);assert(!br);auto ef=elf_fixture();auto ei=parse_elf_image(ef);assert(ei);assert(ei.value().elf_class==ELFClass::ELF64&&ei.value().machine==62&&ei.value().entry==0x400000);assert(ei.value().segments.size()==1&&ei.value().sections.size()==4);assert(ei.value().symbols.size()==1&&ei.value().symbols[0].name=="func");auto emd=detect_metadata(ef);assert(emd.format==BinaryFormat::ELF64&&emd.architecture==Architecture::X86_64);
 auto f=fixture();auto md=detect_metadata(f);assert(md.format==BinaryFormat::PE64&&md.architecture==Architecture::X86_64);auto pe=parse_pe(f);assert(pe);const auto&im=pe.value();assert(im.headers.coff.number_of_sections==3&&im.sections.size()==3);assert(im.mapper.rva_to_file_offset(0x1000).value()==0x400);assert(im.headers.entry_point_file_offset&&*im.headers.entry_point_file_offset==0x400);
 assert(im.imports&&im.imports->modules.size()==1&&im.imports->modules[0].symbols.size()==1&&im.imports->modules[0].symbols[0].name&&*im.imports->modules[0].symbols[0].name=="GetProcAddress");
 assert(im.exports&&im.exports->functions.size()==1&&im.exports->functions[0].name&&*im.exports->functions[0].name=="Init");
 assert(im.relocations&&im.relocations->blocks.size()==1&&im.relocations->blocks[0].entries.size()==2);
 assert(im.resources&&im.resources->items.size()==1&&im.resources->items[0].language==1033);
 assert(im.tls&&im.tls->callbacks.size()==1&&im.tls->callbacks[0].rva&&*im.tls->callbacks[0].rva==0x1100);
 assert(im.debug_entries.size()==1&&im.debug_entries[0].codeview&&im.debug_entries[0].codeview->pdb_path=="fixture.pdb");
 const std::vector<std::byte> analysis={std::byte{'H'},std::byte{'e'},std::byte{'l'},std::byte{'l'},std::byte{'o'},std::byte{0},std::byte{'H'},std::byte{'i'},std::byte{0},std::byte{0xFF},std::byte{'X'},std::byte{'Y'},std::byte{'Z'}};
 auto ascii=extract_strings(analysis,StringEncoding::ASCII,4);assert(ascii.size()==1&&ascii[0].text=="Hello"&&ascii[0].offset==0);
 auto u16=std::vector<std::byte>{std::byte{'H'},std::byte{0},std::byte{'i'},std::byte{0},std::byte{0},std::byte{0}};auto us=extract_strings(u16,StringEncoding::UTF16LE,2);assert(us.size()==1&&us[0].text=="Hi"&&us[0].offset==0);
 auto hd=make_hexdump(analysis,1,4,2);assert(hd.size()==2&&hd[0].offset==1&&hd[0].bytes.size()==2);
 auto needle=search_text(analysis,"Hello",StringEncoding::UTF8);assert(needle.size()==1&&needle[0].offset==0);
 std::vector<int>hp;assert(parse_hex_pattern("48 65 ?? 6c 6f",hp)&&hp.size()==5&&hp[2]==-1);assert(parse_hex_pattern("4865??6c6f",hp)&&hp.size()==5);
 auto matches=search_bytes(analysis,std::span<const std::byte>(analysis.data(),5));assert(matches.size()==1&&matches[0].offset==0);
 auto regs=classify_regions(analysis,2);assert(!regs.empty());
 auto mtemp=std::filesystem::temp_directory_path()/"binx-v05-tests";std::error_code mec;std::filesystem::create_directories(mtemp,mec);auto rootp=mtemp/"root.exe";auto depb=mtemp/"KERNEL32.dll";{std::ofstream froot(rootp,std::ios::binary);auto x=fixture();froot.write(reinterpret_cast<const char*>(x.data()),static_cast<std::streamsize>(x.size()));std::ofstream fd(depb,std::ios::binary);x=fixture();p32(x,0x98+112+8,0);fd.write(reinterpret_cast<const char*>(x.data()),static_cast<std::streamsize>(x.size()));}
 auto root=BinaryFile::open(rootp);assert(root);auto direct=extract_dependencies(root.value());assert(direct.size()==1&&direct[0].name=="KERNEL32.dll"&&direct[0].kind==DependencyKind::PEImport);
 auto graph=build_dependency_graph(rootp,{},2,8);assert(graph&&graph.value().nodes.size()==2&&graph.value().edges.size()==1&&graph.value().unresolved.empty()&&graph.value().cycles.empty());
 auto dot=dependency_graph_dot(graph.value());assert(dot.find("KERNEL32.dll")!=std::string::npos);
 std::filesystem::remove_all(mtemp,mec);
 auto mtemp2=std::filesystem::temp_directory_path()/"binx-v05-macho-tests";std::filesystem::create_directories(mtemp2,mec);auto mp=mtemp2/"app";{std::ofstream mf(mp,std::ios::binary);auto x=macho_dependency_fixture();mf.write(reinterpret_cast<const char*>(x.data()),static_cast<std::streamsize>(x.size()));}auto mb=BinaryFile::open(mp);assert(mb&&mb.value().metadata().format==BinaryFormat::MachO64);auto mdps=extract_dependencies(mb.value());assert(mdps.size()==1&&mdps[0].name=="/usr/lib/libSystem.B.dylib"&&mdps[0].kind==DependencyKind::MachODylib);std::filesystem::remove_all(mtemp2,mec);
 auto dbgtest=std::filesystem::temp_directory_path()/"binx-symbol-test.bin";{std::ofstream sf(dbgtest,std::ios::binary);auto z=fixture();sf.write(reinterpret_cast<const char*>(z.data()),static_cast<std::streamsize>(z.size()));}auto bf=BinaryFile::open(dbgtest);assert(bf);auto sy=collect_symbols(bf.value());assert(sy);bool found=false;for(auto&s:sy.value())if(s.name=="GetProcAddress"&&s.kind==SymbolKind::Import)found=true;assert(found);auto di=collect_debug_info(bf.value());assert(di&&di.value().has_pdb&&di.value().pdb_guid.size()==36&&di.value().pdb_age==1);std::filesystem::remove(dbgtest);
 auto code=std::vector<std::byte>{std::byte{0x55},std::byte{0x48},std::byte{0x89},std::byte{0xE5},std::byte{0x90},std::byte{0xE8},std::byte{0x02},std::byte{0},std::byte{0},std::byte{0},std::byte{0xC3}};auto ds=disassemble_x86(code,0x1000,0,20);assert(ds&&ds.value().size()==5);assert(ds.value()[0].mnemonic=="push"&&ds.value()[1].mnemonic=="mov"&&ds.value()[2].mnemonic=="nop"&&ds.value()[3].mnemonic=="call"&&ds.value()[3].branch_target&&*ds.value()[3].branch_target==0x100b&&ds.value()[4].mnemonic=="ret");
 const auto abc=std::vector<std::byte>{std::byte{'a'},std::byte{'b'},std::byte{'c'}};auto h=hash_all(abc);assert(h);assert(h.value().md5=="900150983cd24fb0d6963f7d28e17f72");assert(h.value().sha1=="a9993e364706816aba3e25717850c26c9cd0d89d");assert(h.value().sha256=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
 auto t1=std::filesystem::temp_directory_path()/"binx-diff-a.bin";auto t2=std::filesystem::temp_directory_path()/"binx-diff-b.bin";{std::ofstream fa(t1,std::ios::binary),fb(t2,std::ios::binary);fa<<"abcdef";fb<<"abXdefg";}auto ba=BinaryFile::open(t1);auto bb=BinaryFile::open(t2);assert(ba&&bb);auto dr=compare_binaries(ba.value(),bb.value());assert(dr&&dr.value().changed_bytes==1&&dr.value().added_bytes==1&&dr.value().removed_bytes==0&&dr.value().hunks.size()==1);auto sr=analyze_size(ba.value());assert(sr&&sr.value().file_size==6);auto rr=build_binary_report(ba.value());assert(rr&&rr.value().file_size==6&&rr.value().format==BinaryFormat::Unknown&&rr.value().dependencies.empty());auto rj=format_binary_report(rr.value(),true);assert(rj.find("\\\"schema_version\\\":5")!=std::string::npos);assert(json_escape("\n")== "\\n");std::filesystem::remove(t1);std::filesystem::remove(t2);
 auto crashp=std::filesystem::temp_directory_path()/"binx-v1-minidump.dmp";{
  std::vector<std::byte>dmp(0x500);
  dmp[0]=std::byte{'M'};dmp[1]=std::byte{'D'};dmp[2]=std::byte{'M'};dmp[3]=std::byte{'P'};
  p32(dmp,8,4);p32(dmp,12,32);p32(dmp,16,7);p32(dmp,20,2);p32(dmp,24,0);
  p32(dmp,0x20,7);p32(dmp,0x24,2);p32(dmp,0x28,0x200);
  p32(dmp,0x2c,6);p32(dmp,0x30,168);p32(dmp,0x34,0x220);
  p32(dmp,0x38,4);p32(dmp,0x3c,112);p32(dmp,0x40,0x2d0);
  p32(dmp,0x44,3);p32(dmp,0x48,52);p32(dmp,0x4c,0x350);
  p16(dmp,0x200,9);
  p32(dmp,0x220,42);p32(dmp,0x228,0xC0000005u);p64(dmp,0x238,0x140012345ull);
  p32(dmp,0x2d0,1);p64(dmp,0x2d4,0x140000000ull);p32(dmp,0x2dc,0x2000);p32(dmp,0x2e8,0x400);
  p32(dmp,0x350,1);p32(dmp,0x354,42);p64(dmp,0x36c,0x7000ull);p32(dmp,0x374,0x100);
  p32(dmp,0x400,3);dmp[0x404]=std::byte{'m'};dmp[0x406]=std::byte{'o'};dmp[0x408]=std::byte{'d'};
  std::ofstream df(crashp,std::ios::binary);df.write(reinterpret_cast<const char*>(dmp.data()),static_cast<std::streamsize>(dmp.size()));
 }
 auto cf=BinaryFile::open(crashp);assert(cf);auto cr=analyze_crash_dump(cf.value());assert(cr&&cr.value().format==CrashDumpFormat::WindowsMinidump&&cr.value().architecture==Architecture::X86_64&&cr.value().exception_code==0xC0000005u&&cr.value().fault_address==0x140012345ull&&cr.value().crashing_thread==42&&cr.value().thread_count==1&&cr.value().module_count==1&&cr.value().threads[0].stack_start==0x7000ull&&cr.value().modules[0].name=="mod");
 std::filesystem::remove(crashp);
 auto corep=std::filesystem::temp_directory_path()/"binx-v09-core";{
  std::vector<std::byte>core(0x300);core[0]=std::byte{0x7f};core[1]=std::byte{'E'};core[2]=std::byte{'L'};core[3]=std::byte{'F'};core[4]=std::byte{2};core[5]=std::byte{1};core[6]=std::byte{1};
  p16(core,16,4);p16(core,18,62);p64(core,32,0x40);p16(core,54,56);p16(core,56,1);p32(core,0x40,4);p32(core,0x44,0);p64(core,0x48,0x100);p64(core,0x60,0x20);
  p32(core,0x100,0);p32(core,0x104,0);p32(core,0x108,1);p32(core,0x10c,0);p32(core,0x110,4);p32(core,0x114,0x53494749u);p32(core,0x118,11);
  std::ofstream efc(corep,std::ios::binary);efc.write(reinterpret_cast<const char*>(core.data()),static_cast<std::streamsize>(core.size()));
 }
 auto cof=BinaryFile::open(corep);assert(cof);auto cor=analyze_crash_dump(cof.value());assert(cor&&cor.value().format==CrashDumpFormat::ELFCore&&cor.value().architecture==Architecture::X86_64&&cor.value().thread_count==1&&cor.value().signal==11);
 std::filesystem::remove(corep);
 return 0;
}