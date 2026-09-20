#include "binx/analysis/crash.hpp"
#include "binx/formats/detect.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <sstream>
namespace binx {
namespace {
std::string esc(const std::string&s){std::string o;for(char c:s){if(c=='"')o+="\\\"";else if(c=='\\')o+="\\\\";else if(static_cast<unsigned char>(c)<0x20)o+="?";else o+=c;}return o;}
using B=std::span<const std::byte>;
std::uint16_t u16(B b,std::size_t o){return o+2<=b.size()?static_cast<std::uint16_t>(std::to_integer<unsigned char>(b[o])|(std::to_integer<unsigned char>(b[o+1])<<8)):0;}
std::uint32_t u32(B b,std::size_t o){std::uint32_t v=0;for(int i=0;i<4&&o+static_cast<std::size_t>(i)<b.size();++i)v|=std::uint32_t(std::to_integer<unsigned char>(b[o+i]))<<(8*i);return v;}
std::uint64_t u64(B b,std::size_t o){std::uint64_t v=0;for(int i=0;i<8&&o+static_cast<std::size_t>(i)<b.size();++i)v|=std::uint64_t(std::to_integer<unsigned char>(b[o+i]))<<(8*i);return v;}
bool range(B b,std::uint64_t o,std::uint64_t n){return o<=b.size()&&n<=b.size()-o;}
std::string minidump_string(B b,std::uint32_t rva){if(!range(b,rva,4))return {};auto chars=u32(b,rva);auto bytes=std::uint64_t(chars)*2;if(!range(b,std::uint64_t(rva)+4,bytes))return {};std::string s;for(std::uint32_t i=0;i<chars;++i){auto c=u16(b,rva+4+std::size_t(i)*2);s.push_back(c<128?static_cast<char>(c):'?');}return s;}
Architecture arch_from_elf_machine(std::uint16_t m){switch(m){case 3:return Architecture::X86;case 62:return Architecture::X86_64;case 40:return Architecture::ARM;case 183:return Architecture::ARM64;case 243:return Architecture::RISCV64;default:return Architecture::Unknown;}}
bool note_align_ok(std::uint64_t x){return x<=0x10000000ull;}
void parse_minidump(B b,CrashReport&r){
 if(b.size()<32)return;auto streams=u32(b,8);auto dir_rva=u32(b,12);
 if(streams>4096||!range(b,dir_rva,std::uint64_t(streams)*12))return;
 for(std::uint32_t i=0;i<streams;++i){auto p=std::size_t(dir_rva)+std::size_t(i)*12;auto type=u32(b,p),size=u32(b,p+4),rva=u32(b,p+8);if(!range(b,rva,size))continue;
  if(type==4&&size>=4){auto n=u32(b,rva);r.module_count=0;auto base=std::uint64_t(rva)+4;for(std::uint32_t j=0;j<r.module_count&&range(b,base,108);++j,base+=108){CrashModule m;m.base=u64(b,base);m.size=u32(b,base+8);m.name=minidump_string(b,u32(b,base+20));r.modules.push_back(std::move(m));++r.module_count;}}
  else if(type==3&&size>=4){auto n=u32(b,rva);r.thread_count=0;auto pth=std::uint64_t(rva)+4;for(std::uint32_t j=0;j<r.thread_count&&range(b,pth,48);++j,pth+=48){CrashThread t;t.id=u32(b,pth);t.stack_start=u64(b,pth+24);t.stack_size=u32(b,pth+32);r.threads.push_back(t);++r.thread_count;}}
  else if(type==6&&size>=168){r.crashing_thread=u32(b,rva);r.exception_code=u32(b,rva+8);r.fault_address=u64(b,rva+24);}
  else if(type==7&&size>=2){auto a=u16(b,rva);switch(a){case 0:r.architecture=Architecture::X86;break;case 9:r.architecture=Architecture::X86_64;break;case 5:r.architecture=Architecture::ARM;break;case 12:r.architecture=Architecture::ARM64;break;default:break;}}
 }
}
void parse_elf_core(B b,CrashReport&r){
 if(b.size()<64)return;bool is64=b[4]==std::byte{2};bool be=b[5]==std::byte{2};if(be)return;
 auto type=u16(b,16);if(type!=4)return;
 auto machine=u16(b,18);r.architecture=arch_from_elf_machine(machine);auto phoff=is64?u64(b,32):u32(b,28);auto phentsz=u16(b,is64?54:42);auto phnum=u16(b,is64?56:44);if(phnum>4096||phentsz< (is64?56:32)||!range(b,phoff,std::uint64_t(phentsz)*phnum))return;
 for(std::uint16_t i=0;i<phnum;++i){auto p=std::size_t(phoff)+std::size_t(i)*phentsz;auto ptype=u32(b,p);auto off=is64?u64(b,p+8):u32(b,p+4);auto filesz=is64?u64(b,p+32):u32(b,p+16);if(ptype!=4||!range(b,off,filesz)||filesz<12)continue;
  std::uint64_t q=off,end=off+filesz;while(q+12<=end){auto namesz=u32(b,q),descsz=u32(b,q+4),ntype=u32(b,q+8);if(!note_align_ok(namesz)||!note_align_ok(descsz))break;auto no=((std::uint64_t(namesz)+3)/4)*4,nd=((std::uint64_t(descsz)+3)/4)*4;if(q+12+no+nd>end)break;auto desc=q+12+no;
   if(ntype==1)++r.thread_count;
   if(ntype==0x53494749&&descsz>=4)r.signal=u32(b,desc);
   q+=12+no+nd;
  }
 }
}
}
const char* crash_dump_format_name(CrashDumpFormat f){switch(f){case CrashDumpFormat::WindowsMinidump:return "Windows minidump";case CrashDumpFormat::ELFCore:return "ELF core dump";default:return "unknown";}}
Result<CrashReport> analyze_crash_dump(const BinaryFile&file){
 CrashReport r;auto b=file.bytes();
 if(b.size()>=4&&b[0]==std::byte{'M'}&&b[1]==std::byte{'D'}&&b[2]==std::byte{'M'}&&b[3]==std::byte{'P'}){r.format=CrashDumpFormat::WindowsMinidump;parse_minidump(b,r);}
 else if(b.size()>=20&&b[0]==std::byte{0x7f}&&b[1]==std::byte{'E'}&&b[2]==std::byte{'L'}&&b[3]==std::byte{'F'}&&u16(b,16)==4){r.format=CrashDumpFormat::ELFCore;parse_elf_core(b,r);}
 else return Error{ErrorCode::UnsupportedFormat,"input is not a supported Windows minidump or ELF core dump"};
 r.architecture_name=architecture_name(r.architecture);
  return r;
}
std::string format_crash_report(const CrashReport&r,const BinaryFile&f,bool json){
 std::ostringstream o;
 if(json){o<<"{\n  \"schema_version\":7,\n  \"file\":\""<<f.path().filename().string()<<"\",\n  \"format\":\""<<crash_dump_format_name(r.format)<<"\",\n  \"architecture\":\""<<r.architecture_name<<"\",\n  \"threads\":"<<r.thread_count<<",\n  \"modules\":"<<r.module_count<<",\n  \"exception_code\":"<<r.exception_code<<",\n  \"signal\":"<<r.signal<<",\n  \"fault_address\":\"0x"<<std::hex<<r.fault_address<<"\",\n  \"crashing_thread\":"<<std::dec<<r.crashing_thread<<",\n  \"module_list\":[";for(std::size_t i=0;i<r.modules.size();++i){if(i)o<<",";auto&m=r.modules[i];o<<"{\"base\":\"0x"<<std::hex<<m.base<<"\",\"size\":"<<std::dec<<m.size<<",\"name\":\""<<esc(m.name)<<"\"}";}o<<"]\n}\n";return o.str();}
 o<<"BINX CRASH ANALYSIS\n\nFILE\n  "<<f.path().filename().string()<<"\n  Format:          "<<crash_dump_format_name(r.format)<<"\n  Architecture:   "<<r.architecture_name<<"\n\nCRASH\n";if(r.exception_code)o<<"  Exception code:  0x"<<std::hex<<r.exception_code<<"\n";if(r.signal)o<<"  Signal:          "<<std::dec<<r.signal<<"\n";o<<"  Fault address:   0x"<<std::hex<<r.fault_address<<"\n  Crashing thread: "<<std::dec<<r.crashing_thread<<"\n\nSUMMARY\n  Threads:         "<<r.thread_count<<"\n  Modules:         "<<r.module_count<<"\n";if(!r.modules.empty()){o<<"\nMODULES\n";for(const auto&m:r.modules)o<<"  0x"<<std::hex<<m.base<<" + 0x"<<m.size<<"  "<<m.name<<"\n";}return o.str();
}
}
