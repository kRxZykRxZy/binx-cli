#include "binx/analysis/report.hpp"
#include "binx/analysis/byte_analysis.hpp"
#include "binx/analysis/dependencies.hpp"
#include "binx/analysis/diff.hpp"
#include "binx/analysis/symbols.hpp"
#include "binx/formats/detect.hpp"
#include <iomanip>
#include <sstream>
namespace binx {
namespace {
std::string esc(const std::string&s){std::string o;for(char c:s){if(c=='"')o+="\\\"";else if(c=='\\')o+="\\\\";else if(static_cast<unsigned char>(c)<0x20)o+="?";else o+=c;}return o;}
std::string hx(std::uint64_t v){std::ostringstream o;o<<"0x"<<std::hex<<std::uppercase<<v;return o.str();}
}
Result<BinaryReport> build_binary_report(const BinaryFile&f){
 BinaryReport r;const auto&m=f.metadata();r.file_name=f.path().filename().string();r.file_size=m.file_size;r.format=m.format;r.architecture=m.architecture;r.endianness=endianness_name(m.endianness);r.platform=m.platform;
 for(const auto&d:extract_dependencies(f))r.dependencies.push_back(d.name);
 auto sy=collect_symbols(f);if(sy)r.symbol_count=sy.value().size();
 auto di=collect_debug_info(f);if(di){r.debug_compilation_units=di.value().compilation_units;r.has_dwarf=di.value().has_dwarf;r.has_pdb=di.value().has_pdb;}
 auto sz=analyze_size(f);if(sz){r.code_size=sz.value().code_size;r.initialized_data=sz.value().initialized_data;r.uninitialized_data=sz.value().uninitialized_data;}
 auto strings=extract_strings(f.bytes(),StringEncoding::ASCII,6,10);for(const auto&s:strings)r.sample_strings.push_back(s.text);
 return r;
}
std::string format_binary_report(const BinaryReport&r,bool json){
 std::ostringstream o;
 if(json){o<<"{\n  \"schema_version\":5,\n  \"file\":{\"name\":\""<<esc(r.file_name)<<"\",\"size\":"<<r.file_size<<"},\n  \"format\":\""<<format_name(r.format)<<"\",\n  \"architecture\":\""<<architecture_name(r.architecture)<<"\",\n  \"endianness\":\""<<esc(r.endianness)<<"\",\n  \"platform\":\""<<esc(r.platform)<<"\",\n  \"dependencies\":[";for(std::size_t i=0;i<r.dependencies.size();++i){if(i)o<<",";o<<"\""<<esc(r.dependencies[i])<<"\"";}o<<"],\n  \"symbols\":"<<r.symbol_count<<",\n  \"debug\":{\"dwarf\":"<<(r.has_dwarf?"true":"false")<<",\"pdb\":"<<(r.has_pdb?"true":"false")<<",\"compilation_units\":"<<r.debug_compilation_units<<"},\n  \"size\":{\"code\":"<<r.code_size<<",\"initialized_data\":"<<r.initialized_data<<",\"uninitialized_data\":"<<r.uninitialized_data<<"},\n  \"sample_strings\":[";for(std::size_t i=0;i<r.sample_strings.size();++i){if(i)o<<",";o<<"\""<<esc(r.sample_strings[i])<<"\"";}o<<"]\n}\n";return o.str();}
 o<<"BINX BINARY REPORT\n\nFILE\n  Name:            "<<r.file_name<<"\n  Size:            "<<r.file_size<<" bytes\n\nFORMAT\n  Type:            "<<format_name(r.format)<<"\n  Architecture:   "<<architecture_name(r.architecture)<<"\n  Endianness:     "<<r.endianness<<"\n  Platform:       "<<(r.platform.empty()?"unknown":r.platform)<<"\n\nANALYSIS\n  Dependencies:   "<<r.dependencies.size()<<"\n  Symbols:        "<<r.symbol_count<<"\n  DWARF:          "<<(r.has_dwarf?"yes":"no")<<"\n  PDB:            "<<(r.has_pdb?"yes":"no")<<"\n  Code:           "<<r.code_size<<" bytes\n  Init data:      "<<r.initialized_data<<" bytes\n  Uninit data:    "<<r.uninitialized_data<<" bytes\n";
 if(!r.dependencies.empty()){o<<"\nDEPENDENCIES\n";for(const auto&d:r.dependencies)o<<"  "<<d<<"\n";}
 if(!r.sample_strings.empty()){o<<"\nSTRING SAMPLES\n";for(const auto&s:r.sample_strings)o<<"  "<<s<<"\n";}
 return o.str();
}
}