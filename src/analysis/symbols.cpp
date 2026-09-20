#include "binx/analysis/symbols.hpp"
#include "binx/formats/elf.hpp"
#include "binx/formats/pe.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>
namespace binx {
namespace {
std::string hx(std::uint64_t v){std::ostringstream o;o<<"0x"<<std::hex<<std::uppercase<<v;return o.str();}
}
const char* symbol_kind_name(SymbolKind k){switch(k){case SymbolKind::Function:return"function";case SymbolKind::Object:return"object";case SymbolKind::Section:return"section";case SymbolKind::Import:return"import";case SymbolKind::Export:return"export";case SymbolKind::Debug:return"debug";default:return"unknown";}}
Result<std::vector<SymbolRecord>> collect_symbols(const BinaryFile&f){
 std::vector<SymbolRecord> out; auto fmt=f.metadata().format;
 if(fmt==BinaryFormat::ELF32||fmt==BinaryFormat::ELF64){auto e=parse_elf_image(f.bytes());if(!e)return e.error();for(const auto&s:e.value().symbols){if(s.name.empty())continue;SymbolRecord r;r.name=s.name;r.address=s.value;r.size=s.size;r.source="ELF";r.binding=elf_symbol_bind_name(s.bind);r.weak=s.bind==2;r.external=s.shndx==0;r.kind=s.type==2?SymbolKind::Function:s.type==1?SymbolKind::Object:s.type==3?SymbolKind::Section:SymbolKind::Unknown;out.push_back(std::move(r));}}
 else if(fmt==BinaryFormat::PE32||fmt==BinaryFormat::PE64){auto p=parse_pe(f.bytes());if(!p)return p.error();if(p.value().exports)for(const auto&e:p.value().exports->functions){if(!e.name)continue;SymbolRecord r;r.name=*e.name;r.address=e.rva;r.file_offset=e.file_offset;r.kind=SymbolKind::Export;r.source="PE export";r.external=true;out.push_back(std::move(r));}if(p.value().imports)for(const auto&m:p.value().imports->modules)for(const auto&s:m.symbols){if(!s.name)continue;SymbolRecord r;r.name=*s.name;r.kind=SymbolKind::Import;r.source="PE import";r.module=m.dll_name;r.external=true;out.push_back(std::move(r));}for(const auto&d:p.value().debug_entries)if(d.codeview){SymbolRecord r;r.name=d.codeview->pdb_path;r.kind=SymbolKind::Debug;r.source="PDB";r.module=d.codeview->guid;r.address=d.codeview->age;r.external=true;out.push_back(std::move(r));}}
 else return Error{ErrorCode::UnsupportedFormat,"symbol extraction is supported for PE and ELF images"};
 std::sort(out.begin(),out.end(),[](const auto&a,const auto&b){return a.address==b.address?a.name<b.name:a.address<b.address;});return out;
}
Result<DebugInfo> collect_debug_info(const BinaryFile&f){
 DebugInfo d;auto fmt=f.metadata().format;
 if(fmt==BinaryFormat::ELF32||fmt==BinaryFormat::ELF64){auto e=parse_elf_image(f.bytes());if(!e)return e.error();d.format="ELF";for(const auto&s:e.value().sections)if(s.name.rfind(".debug_",0)==0){d.has_dwarf=true;d.dwarf_sections.push_back(s.name);}
 // Count well-formed DWARF .debug_info compilation-unit headers (v2-v5, 32-bit length only).
 for(const auto&s:e.value().sections)if(s.name==".debug_info"&&s.offset+s.size<=f.size()){auto b=f.bytes().subspan((std::size_t)s.offset,(std::size_t)s.size);std::size_t p=0;while(p+11<=b.size()){auto u32=[&](std::size_t q){return std::uint32_t(std::to_integer<unsigned char>(b[q]))|(std::uint32_t(std::to_integer<unsigned char>(b[q+1]))<<8)|(std::uint32_t(std::to_integer<unsigned char>(b[q+2]))<<16)|(std::uint32_t(std::to_integer<unsigned char>(b[q+3]))<<24);};auto len=u32(p);if(len==0||len> b.size()-p-4)break;if(p+6>b.size())break;auto ver=std::uint16_t(std::to_integer<unsigned char>(b[p+4]))|(std::uint16_t(std::to_integer<unsigned char>(b[p+5]))<<8);if(ver<2||ver>5)break;++d.compilation_units;p+=4+len;}}
 } else if(fmt==BinaryFormat::PE32||fmt==BinaryFormat::PE64){auto p=parse_pe(f.bytes());if(!p)return p.error();d.format="PE";for(const auto&e:p.value().debug_entries)if(e.codeview){d.has_pdb=true;d.pdb_files.push_back(e.codeview->pdb_path);d.pdb_guid=e.codeview->guid;d.pdb_age=e.codeview->age;}}
 else return Error{ErrorCode::UnsupportedFormat,"debug information is supported for PE and ELF images"};
 return d;
}
std::string format_symbols(const std::vector<SymbolRecord>&v,bool json){std::ostringstream o;if(json){o<<"{\n  \"schema_version\":5,\n  \"symbols\":[";for(std::size_t i=0;i<v.size();++i){if(i)o<<",";auto&s=v[i];o<<"{\"name\":\""<<s.name<<"\",\"kind\":\""<<symbol_kind_name(s.kind)<<"\",\"address\":\""<<hx(s.address)<<"\",\"size\":"<<s.size<<",\"source\":\""<<s.source<<"\",\"external\":"<<(s.external?"true":"false")<<"}";}o<<"]\n}\n";return o.str();}o<<"SYMBOLS ("<<v.size()<<")\n";for(auto&s:v)o<<std::setw(18)<<hx(s.address)<<" "<<std::setw(9)<<symbol_kind_name(s.kind)<<" "<<std::setw(12)<<s.source<<" "<<s.name<<(s.module.empty()?"":" ["+s.module+"]")<<"\n";return o.str();}
std::string format_debug_info(const DebugInfo&d,bool json){std::ostringstream o;if(json){o<<"{\n  \"schema_version\":5,\n  \"format\":\""<<d.format<<"\",\n  \"dwarf\":{"<<"\"present\":"<<(d.has_dwarf?"true":"false")<<",\"compilation_units\":"<<d.compilation_units<<",\"sections\":[";for(std::size_t i=0;i<d.dwarf_sections.size();++i){if(i)o<<",";o<<"\""<<d.dwarf_sections[i]<<"\"";}o<<"]},\n  \"pdb\":{"<<"\"present\":"<<(d.has_pdb?"true":"false")<<",\"age\":"<<d.pdb_age<<",\"guid\":\""<<d.pdb_guid<<"\",\"files\":[";for(std::size_t i=0;i<d.pdb_files.size();++i){if(i)o<<",";o<<"\""<<d.pdb_files[i]<<"\"";}o<<"]}\n}\n";return o.str();}o<<"DEBUG INFORMATION\n  Format: "<<d.format<<"\n  DWARF: "<<(d.has_dwarf?"present":"not present")<<"\n  Compilation units: "<<d.compilation_units<<"\n";for(auto&s:d.dwarf_sections)o<<"    "<<s<<"\n";o<<"  PDB: "<<(d.has_pdb?"present":"not present")<<"\n";if(d.has_pdb){o<<"  GUID: "<<d.pdb_guid<<"\n  Age: "<<d.pdb_age<<"\n";for(auto&s:d.pdb_files)o<<"  File: "<<s<<"\n";}return o.str();}
}