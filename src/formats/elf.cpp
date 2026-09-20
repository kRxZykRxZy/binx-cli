#include "binx/formats/elf.hpp"
#include <algorithm>
#include <cstring>
#include <limits>
#include <set>
namespace binx {
namespace {
struct R { std::span<const std::byte> d; bool le;
 bool ok(std::uint64_t o,std::uint64_t n=1)const{return o<=d.size()&&n<=d.size()-o;}
 std::uint16_t u16(std::uint64_t o)const{if(!ok(o,2))throw 1;auto b=[&](int i){return std::to_integer<unsigned char>(d[o+i]);};return le?std::uint16_t(b(0)|b(1)<<8):std::uint16_t(b(0)<<8|b(1));}
 std::uint32_t u32(std::uint64_t o)const{if(!ok(o,4))throw 1;std::uint32_t v=0;for(int i=0;i<4;i++)v=le?v|std::uint32_t(std::to_integer<unsigned char>(d[o+i]))<<(8*i):v<<8|std::to_integer<unsigned char>(d[o+i]);return v;}
 std::uint64_t u64(std::uint64_t o)const{if(!ok(o,8))throw 1;std::uint64_t v=0;for(int i=0;i<8;i++)v=le?v|std::uint64_t(std::to_integer<unsigned char>(d[o+i]))<<(8*i):v<<8|std::to_integer<unsigned char>(d[o+i]);return v;}
 std::uint64_t ux(std::uint64_t o,bool x)const{return x?u64(o):u32(o);}
 std::int64_t sx(std::uint64_t o,bool x)const{return x?static_cast<std::int64_t>(u64(o)):static_cast<std::int32_t>(u32(o));}
};
void diag(ELFImage&i,DiagnosticSeverity s,const char*c,const char*m){i.diagnostics.push_back({s,c,"ELF",{}, {},m});}
std::string strtab(R&r,const ELFSection&sec,std::uint32_t n){if(n>=sec.size||!r.ok(sec.offset+n))return{};std::string s;for(std::uint64_t p=sec.offset+n;p<sec.offset+sec.size&&r.ok(p);++p){char c=char(std::to_integer<unsigned char>(r.d[p]));if(!c)break;s+=c;if(s.size()>4096)break;}return s;}
}
Result<ELFImage> parse_elf_image(std::span<const std::byte>d){
 if(d.size()<16||std::to_integer<unsigned char>(d[0])!=0x7f||std::to_integer<unsigned char>(d[1])!='E'||std::to_integer<unsigned char>(d[2])!='L'||std::to_integer<unsigned char>(d[3])!='F')return Error{ErrorCode::UnsupportedFormat,"input is not an ELF image"};
 if(d[4]!=std::byte{1}&&d[4]!=std::byte{2})return Error{ErrorCode::UnsupportedFormat,"unsupported ELF class"};
 if(d[5]!=std::byte{1}&&d[5]!=std::byte{2})return Error{ErrorCode::UnsupportedFormat,"unsupported ELF byte order"};
 ELFImage i;i.elf_class=d[4]==std::byte{2}?ELFClass::ELF64:ELFClass::ELF32;i.endianness=d[5]==std::byte{1}?Endianness::Little:Endianness::Big;R r{d,i.endianness==Endianness::Little};const bool x=i.elf_class==ELFClass::ELF64;const std::uint64_t hs=x?64:52;
 try{
  if(d.size()<hs){diag(i,DiagnosticSeverity::Error,"ELF_HEADER_TRUNCATED","ELF header is truncated");i.header_status=ParseStatus::Malformed;return i;}
  i.type=r.u16(16);i.machine=r.u16(18);i.version=r.u32(20);i.entry=r.ux(24,x);i.phoff=r.ux(x?32:28,x);i.shoff=r.ux(x?40:32,x);i.flags=r.u32(x?48:36);i.phentsize=r.u16(x?54:42);i.phnum=r.u16(x?56:44);i.shentsize=r.u16(x?58:46);i.shnum=r.u16(x?60:48);i.shstrndx=r.u16(x?62:50);i.header_status=ParseStatus::Valid;
  if(i.phnum&&(!i.phentsize||i.phentsize<(x?56:32)||i.phoff> d.size()||std::uint64_t(i.phnum)*i.phentsize>d.size()-i.phoff)){diag(i,DiagnosticSeverity::Error,"ELF_PHDR_RANGE","program header table exceeds file");i.segment_status=ParseStatus::Malformed;}
  else {
   for(std::uint16_t n=0;n<i.phnum;n++){auto o=i.phoff+std::uint64_t(n)*i.phentsize;ELFSegment s;s.index=n;s.type=r.u32(o);s.flags=x?r.u32(o+4):r.u32(o+24);s.offset=r.ux(o+(x?8:4),x);s.vaddr=r.ux(o+(x?16:8),x);s.paddr=r.ux(o+(x?24:12),x);s.file_size=r.ux(o+(x?32:16),x);s.memory_size=r.ux(o+(x?40:20),x);s.align=r.ux(o+(x?48:28),x);if(s.offset<=d.size()&&s.file_size<=d.size()-s.offset&&s.type==3){std::string q;for(std::uint64_t p=s.offset;p<s.offset+s.file_size&&r.ok(p);p++){auto c=char(std::to_integer<unsigned char>(d[p]));if(!c)break;q+=c;}s.interpreter=q;i.interpreter=q;}i.segments.push_back(std::move(s));}i.segment_status=ParseStatus::Valid;
  }
  std::vector<ELFSection> sections; 
  if(i.shnum&&(!i.shentsize||i.shentsize<(x?64:40)||i.shoff>d.size()||std::uint64_t(i.shnum)*i.shentsize>d.size()-i.shoff)){diag(i,DiagnosticSeverity::Error,"ELF_SHDR_RANGE","section header table exceeds file");i.section_status=ParseStatus::Malformed;}
  else {
   for(std::uint16_t n=0;n<i.shnum;n++){auto o=i.shoff+std::uint64_t(n)*i.shentsize;ELFSection s;s.index=n;s.type=r.u32(o+4);s.flags=r.ux(o+8,x);s.address=r.ux(o+16,x);s.offset=r.ux(o+(x?24:16),x);s.size=r.ux(o+(x?32:20),x);s.link=r.u32(o+(x?40:24));s.info=r.u32(o+(x?44:28));s.addralign=r.ux(o+(x?48:32),x);s.entsize=r.ux(o+(x?56:36),x);if(s.type!=8&&(s.offset>d.size()||s.size>d.size()-s.offset))diag(i,DiagnosticSeverity::Warning,"ELF_SECTION_RANGE","section extends beyond file");sections.push_back(std::move(s));}
   i.sections=std::move(sections);i.section_status=ParseStatus::Valid;
   if(i.shstrndx<i.sections.size()){auto&st=i.sections[i.shstrndx];for(auto& s:i.sections)s.name=strtab(r,st,0); // replaced below
    for(auto& s:i.sections){const auto shoff=i.shoff+std::uint64_t(s.index)*i.shentsize;const auto no=r.u32(shoff);s.name=strtab(r,st,no);}
   } else if(i.shnum)diag(i,DiagnosticSeverity::Warning,"ELF_SHSTRNDX","section-name string table index is invalid");
  }
  // symbols
  std::set<std::pair<std::uint64_t,std::uint64_t>> sym_seen;
  for(const auto&s:i.sections)if(s.type==2||s.type==11){if(s.entsize==0)continue;const std::uint64_t count=s.size/s.entsize;if(count>1'000'000){diag(i,DiagnosticSeverity::Warning,"ELF_SYMBOL_LIMIT","symbol table is unusually large");continue;}if(s.link>=i.sections.size())continue;for(std::uint64_t n=0;n<count;n++){auto o=s.offset+n*s.entsize;if(!r.ok(o,s.entsize))break;ELFSymbol z;auto no=r.u32(o);z.name=strtab(r,i.sections[s.link],no);auto info=std::to_integer<unsigned char>(r.d[o+(x?4:12)]);z.bind=info>>4;z.type=info&15;z.visibility=std::to_integer<unsigned char>(r.d[o+(x?5:13)])&3;z.shndx=r.u16(o+(x?6:14));z.value=r.ux(o+(x?8:0),x);z.size=r.ux(o+(x?16:8),x);i.symbols.push_back(std::move(z));} } 
  i.symbol_status=ParseStatus::Valid;
  // dynamic
  for(const auto&s:i.sections)if(s.type==6&&s.entsize){std::uint64_t n=s.size/s.entsize;for(std::uint64_t k=0;k<n;k++){auto o=s.offset+k*s.entsize;ELFDynamic z;z.tag=r.sx(o,x);z.value=r.ux(o+(x?8:4),x);i.dynamic.push_back(z);if(z.tag==0)break;}i.dynamic_status=ParseStatus::Valid;break;}
  // relocations
  for(const auto&s:i.sections)if(s.type==4||s.type==9){if(!s.entsize)continue;auto n=s.size/s.entsize;for(std::uint64_t k=0;k<n;k++){auto o=s.offset+k*s.entsize;if(!r.ok(o,s.entsize))break;ELFRelocation z;z.offset=r.ux(o,x);z.info=r.ux(o+(x?8:4),x);if(s.type==4){z.addend=r.sx(o+(x?16:8),x);z.has_addend=true;}z.type=x?z.info&0xffffffffu:z.info&0xff;z.symbol=x?z.info>>32:z.info>>8;if(z.symbol<i.symbols.size())z.symbol_name=i.symbols[z.symbol].name;i.relocations.push_back(z);}i.relocation_status=ParseStatus::Valid;}
  // notes
  for(const auto&s:i.sections)if(s.type==7){std::uint64_t p=s.offset,end=s.offset+s.size;while(p+12<=end&&r.ok(p,12)){auto ns=r.u32(p),ds=r.u32(p+4),ty=r.u32(p+8);p+=12;if(p+((ns+3)&~3u)+((ds+3)&~3u)>end)break;ELFNote z;z.type=ty;for(std::uint32_t k=0;k<ns&&r.ok(p+k);k++){auto c=std::to_integer<unsigned char>(d[p+k]);if(c)z.name+=char(c);}p+=(ns+3)&~3u;z.desc.assign(d.begin()+p,d.begin()+p+ds);p+=(ds+3)&~3u;i.notes.push_back(std::move(z));}i.note_status=ParseStatus::Valid;}
 }catch(...){diag(i,DiagnosticSeverity::Error,"ELF_PARSE_EXCEPTION","ELF structure is truncated or inconsistent");}
 return i;
}
const char* elf_type_name(std::uint16_t v){switch(v){case 0:return "NONE";case 1:return "REL";case 2:return "EXEC";case 3:return "DYN";case 4:return "CORE";default:return "OS/processor";}}
const char* elf_machine_name(std::uint16_t v){switch(v){case 3:return "x86";case 40:return "ARM";case 62:return "x86-64";case 183:return "AArch64";case 243:return "RISC-V";case 8:return "MIPS";default:return "unknown";}}
const char* elf_section_type_name(std::uint32_t v){switch(v){case 0:return "NULL";case 1:return "PROGBITS";case 2:return "SYMTAB";case 3:return "STRTAB";case 4:return "RELA";case 5:return "HASH";case 6:return "DYNAMIC";case 7:return "NOTE";case 8:return "NOBITS";case 9:return "REL";case 11:return "DYNSYM";case 14:return "INIT_ARRAY";case 15:return "FINI_ARRAY";default:return "OTHER";}}
const char* elf_segment_type_name(std::uint32_t v){switch(v){case 0:return "NULL";case 1:return "LOAD";case 2:return "DYNAMIC";case 3:return "INTERP";case 4:return "NOTE";case 5:return "SHLIB";case 6:return "PHDR";case 7:return "TLS";default:return "OTHER";}}
std::string elf_section_flags(std::uint64_t v){std::string s;s+=v&4?'W':'-';s+=v&2?'A':'-';s+=v&4?'X':'-';return s;}
std::string elf_segment_flags(std::uint32_t v){return std::string((v&4)?"R":"-")+((v&2)?"W":"-")+((v&1)?"X":"-");}
const char* elf_symbol_bind_name(std::uint8_t v){switch(v){case 0:return "LOCAL";case 1:return "GLOBAL";case 2:return "WEAK";default:return "OTHER";}}
const char* elf_symbol_type_name(std::uint8_t v){switch(v){case 0:return "NOTYPE";case 1:return "OBJECT";case 2:return "FUNC";case 3:return "SECTION";case 4:return "FILE";case 6:return "TLS";default:return "OTHER";}}
const char* elf_dynamic_tag_name(std::int64_t v){switch(v){case 0:return "NULL";case 1:return "NEEDED";case 3:return "PLTGOT";case 5:return "STRTAB";case 6:return "SYMTAB";case 7:return "RELA";case 8:return "RELASZ";case 9:return "RELAENT";case 10:return "STRSZ";case 11:return "SYMENT";case 12:return "INIT";case 13:return "FINI";case 23:return "JMPREL";default:return "OTHER";}}
}