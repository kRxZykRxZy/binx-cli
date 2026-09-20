#include "binx/analysis/disassembly.hpp"
#include "binx/core/text.hpp"
#include "binx/formats/elf.hpp"
#include "binx/formats/pe.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>
namespace binx {
namespace {
std::uint8_t u8(std::span<const std::byte>d,std::size_t i){return std::to_integer<std::uint8_t>(d[i]);}
std::uint32_t le32(std::span<const std::byte>d,std::size_t i){return std::uint32_t(u8(d,i))|(std::uint32_t(u8(d,i+1))<<8)|(std::uint32_t(u8(d,i+2))<<16)|(std::uint32_t(u8(d,i+3))<<24);}
std::int32_t s32(std::span<const std::byte>d,std::size_t i){return static_cast<std::int32_t>(le32(d,i));}
std::int8_t s8(std::span<const std::byte>d,std::size_t i){return static_cast<std::int8_t>(u8(d,i));}
std::string hex(std::uint64_t x){return hex_u64(x);}
std::string reg(unsigned n,bool w){static const char*r64[]={"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};static const char*r32[]={"eax","ecx","edx","ebx","esp","ebp","esi","edi","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};return w?r64[n&15]:r32[n&15];}
Instruction decode(std::span<const std::byte>d,std::uint64_t addr,std::uint64_t fo,DisassemblySyntax){
 Instruction x;x.address=addr;x.file_offset=fo;if(d.empty())return x;std::size_t n=0;std::uint8_t rex=0;while(n<d.size()&&u8(d,n)>=0x40&&u8(d,n)<=0x4f){rex=u8(d,n++);}
 if(n>=d.size()){x.valid=false;x.mnemonic="db";x.operands=hex(u8(d,0));x.bytes={d[0]};return x;}const auto op=u8(d,n++);
 auto rel=[&](std::int64_t r){x.branch=true;x.branch_target=static_cast<std::uint64_t>(static_cast<std::int64_t>(addr)+static_cast<std::int64_t>(n)+r);};
 if(op==0x90)x.mnemonic="nop";else if(op==0xC3)x.mnemonic="ret";else if(op==0xCC)x.mnemonic="int3";else if(op==0xC9)x.mnemonic="leave";else if(op==0xF4)x.mnemonic="hlt";else if(op==0x0F&&n<d.size()&&u8(d,n)==0x05){++n;x.mnemonic="syscall";}
 else if(op==0xE8&&n+4<=d.size()){auto r=s32(d,n);n+=4;x.mnemonic="call";rel(r);}
 else if(op==0xE9&&n+4<=d.size()){auto r=s32(d,n);n+=4;x.mnemonic="jmp";rel(r);}
 else if(op==0xEB&&n<d.size()){auto r=s8(d,n++);x.mnemonic="jmp";rel(r);}
 else if(op>=0x70&&op<=0x7F&&n<d.size()){static const char*cc[]={"jo","jno","jb","jae","je","jne","jbe","ja","js","jns","jp","jnp","jl","jge","jle","jg"};auto r=s8(d,n++);x.mnemonic=cc[op-0x70];rel(r);}
 else if(op==0x0F&&n<d.size()&&u8(d,n)>=0x80&&u8(d,n)<=0x8F&&n+5<=d.size()){static const char*cc[]={"jo","jno","jb","jae","je","jne","jbe","ja","js","jns","jp","jnp","jl","jge","jle","jg"};auto ccop=u8(d,n++);auto r=s32(d,n);n+=4;x.mnemonic=cc[ccop-0x80];rel(r);}
 else if(op>=0x50&&op<=0x5F){x.mnemonic=op<0x58?"push":"pop";x.operands=reg((op&7)|(rex&1?8:0),rex&8);}
 else if(op>=0xB8&&op<=0xBF){unsigned r=(op-0xB8)|(rex&1?8:0);std::size_t sz=rex&8?8:4;if(n+sz<=d.size()){std::uint64_t imm=0;for(std::size_t i=0;i<sz;++i)imm|=std::uint64_t(u8(d,n+i))<<(8*i);n+=sz;x.mnemonic="mov";x.operands=reg(r,rex&8)+", "+hex(imm);}}
 else if(op==0xC2&&n+2<=d.size()){x.mnemonic="ret";x.operands=hex(u8(d,n)|std::uint64_t(u8(d,n+1))<<8);n+=2;}
 else if(op==0x31&&n<d.size()){auto m=u8(d,n++);if((m>>6)==3){x.mnemonic="xor";x.operands=reg(((m>>3)&7)|(rex&4?8:0),rex&8)+", "+reg((m&7)|(rex&1?8:0),rex&8);}else{x.valid=false;x.mnemonic="db";x.operands=hex(op);}}
  else if((op==0x89||op==0x8B)&&n<d.size()){auto m=u8(d,n++);if((m>>6)==3){const auto dst=reg((m&7)|(rex&1?8:0),rex&8);const auto src=reg(((m>>3)&7)|(rex&4?8:0),rex&8);x.mnemonic="mov";x.operands=(op==0x89)?(dst+", "+src):(src+", "+dst);}else{x.valid=false;x.mnemonic="db";x.operands=hex(op);}}
 else {x.valid=false;x.mnemonic="db";x.operands=hex(op);}
 if(n==0)n=1;
 if(n>d.size())n=d.size();
 x.bytes.assign(d.begin(),d.begin()+static_cast<std::ptrdiff_t>(n));
 return x;
}
std::string bytes_hex(const std::vector<std::byte>&b){std::ostringstream o;for(auto v:b)o<<std::setw(2)<<std::setfill('0')<<std::hex<<std::uppercase<<unsigned(std::to_integer<unsigned char>(v))<<" ";return o.str();}
}
Result<std::vector<Instruction>> disassemble_x86(std::span<const std::byte>d,std::uint64_t a,std::uint64_t fo,std::size_t count,DisassemblySyntax syn){std::vector<Instruction>o;std::size_t p=0;while(p<d.size()&&o.size()<count){auto x=decode(d.subspan(p),a+p,fo+p,syn);if(x.bytes.empty())break;p+=x.bytes.size();o.push_back(std::move(x));}return o;}
Result<std::vector<DisassemblyBlock>> disassemble_file(const BinaryFile&f,const DisassemblyOptions&o){
 std::vector<DisassemblyBlock>out;auto add=[&](std::string n,std::uint64_t fo,std::uint64_t va,std::uint64_t sz){if(fo>=f.size()||!sz)return;sz=std::min<std::uint64_t>(sz,f.size()-fo);if(o.max_bytes)sz=std::min(sz,o.max_bytes);auto r=disassemble_x86(f.bytes().subspan(static_cast<std::size_t>(fo),static_cast<std::size_t>(sz)),va,fo,o.count,o.syntax);if(r)out.push_back({std::move(n),fo,va,sz,std::move(r.value())});};
 const auto&m=f.metadata();
 if(m.format==BinaryFormat::PE32||m.format==BinaryFormat::PE64){auto p=parse_pe(f.bytes());if(!p)return p.error();for(const auto&s:p.value().sections)if(s.executable){auto fo=p.value().mapper.rva_to_file_offset(s.virtual_address);if(fo)add(s.name,fo.value(),p.value().headers.optional.image_base+s.virtual_address,s.raw_size);}}
 else if(m.format==BinaryFormat::ELF32||m.format==BinaryFormat::ELF64){auto e=parse_elf_image(f.bytes());if(!e)return e.error();for(const auto&s:e.value().sections)if((s.flags&4u)&&s.size)add(s.name,s.offset,s.address,s.size);}
 else add("raw",o.offset,o.offset,f.size()-o.offset);
 if(o.from_entry){std::vector<DisassemblyBlock>one;for(auto&z:out)if(m.entry_point&&m.entry_point.value()>=z.virtual_address&&m.entry_point.value()<z.virtual_address+z.size){auto delta=m.entry_point.value()-z.virtual_address;auto r=disassemble_x86(f.bytes().subspan(static_cast<std::size_t>(z.file_offset+delta),static_cast<std::size_t>(z.size-delta)),m.entry_point.value(),z.file_offset+delta,o.count,o.syntax);if(r)one.push_back({z.section,z.file_offset+delta,m.entry_point.value(),z.size-delta,std::move(r.value())});}return one;}
 return out;
}
std::string format_disassembly(const std::vector<DisassemblyBlock>&b,bool json,DisassemblySyntax){
 std::ostringstream o;
 if(json){o<<"{\n  \"schema_version\":4,\n  \"blocks\":[";for(std::size_t i=0;i<b.size();++i){if(i)o<<",";o<<"{\"section\":\""<<json_escape(b[i].section)<<"\",\"file_offset\":"<<b[i].file_offset<<",\"virtual_address\":\"0x"<<std::hex<<b[i].virtual_address<<std::dec<<"\",\"instructions\":[";for(std::size_t j=0;j<b[i].instructions.size();++j){if(j)o<<",";auto&x=b[i].instructions[j];o<<"{\"address\":\"0x"<<std::hex<<x.address<<std::dec<<"\",\"file_offset\":"<<x.file_offset<<",\"bytes\":\""<<bytes_hex(x.bytes)<<"\",\"mnemonic\":\""<<x.mnemonic<<"\",\"operands\":\""<<json_escape(x.operands)<<"\",\"valid\":"<<(x.valid?"true":"false");if(x.branch_target)o<<",\"branch_target\":\"0x"<<std::hex<<*x.branch_target<<std::dec<<"\"";o<<"}";}o<<"]}";}o<<"]\n}\n";return o.str();}
 for(const auto&z:b){o<<"DISASSEMBLY "<<z.section<<" @ 0x"<<std::hex<<z.virtual_address<<std::dec<<"\n";for(const auto&x:z.instructions)o<<"  0x"<<std::hex<<x.address<<std::dec<<"  "<<std::left<<std::setw(24)<<bytes_hex(x.bytes)<<std::setw(8)<<x.mnemonic<<" "<<x.operands<<(x.valid?"":"  ; unknown")<<"\n";o<<"\n";}return o.str();
}
}