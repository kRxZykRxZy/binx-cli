#include "binx/analysis/diff.hpp"
#include "binx/core/text.hpp"
#include "binx/formats/elf.hpp"
#include "binx/formats/pe.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <unordered_map>
namespace binx {
namespace {
std::string hx(std::uint64_t v){return hex_u64(v);}
struct Sec {std::string name;std::uint64_t off=0,size=0,vsize=0;std::string kind;};
std::vector<Sec> secs(const BinaryFile&f){
 std::vector<Sec> r; auto fmt=f.metadata().format;
 if(fmt==BinaryFormat::PE32||fmt==BinaryFormat::PE64){auto p=parse_pe(f.bytes());if(!p)return r;for(const auto&s:p.value().sections)r.push_back({s.name,s.raw_pointer,s.raw_size,s.virtual_size,(s.executable?"code":s.writable?"data":"other")});}
 else if(fmt==BinaryFormat::ELF32||fmt==BinaryFormat::ELF64){auto e=parse_elf_image(f.bytes());if(!e)return r;for(const auto&s:e.value().sections)r.push_back({s.name,s.offset,s.size,s.size,((s.flags&4u)?"code":(s.flags&1u)?"data":"other")});}
 return r;
}
}
Result<BinaryDiff> compare_binaries(const BinaryFile&a,const BinaryFile&b,std::size_t max_hunks){
 BinaryDiff d;d.old_size=a.size();d.new_size=b.size();d.common_size=std::min(a.size(),b.size());
 auto x=a.bytes(),y=b.bytes();std::size_t i=0;
 while(i<d.common_size){if(x[i]==y[i]){++i;continue;}auto start=i;while(i<d.common_size&&x[i]!=y[i])++i;d.changed_bytes+=i-start;if(d.hunks.size()<max_hunks)d.hunks.push_back({start,i-start,start,start});}
 d.added_bytes=d.new_size>d.common_size?d.new_size-d.common_size:0;d.removed_bytes=d.old_size>d.common_size?d.old_size-d.common_size:0;
 const auto denom=std::max(d.old_size,d.new_size);d.similarity=denom?static_cast<double>(d.common_size-d.changed_bytes)/static_cast<double>(denom):1.0;
 auto as=secs(a),bs=secs(b);std::unordered_map<std::string,Sec> am,bm;for(auto&s:as)am.emplace(s.name,s);for(auto&s:bs)bm.emplace(s.name,s);
 for(const auto&[name,s]:am){auto it=bm.find(name);if(it==bm.end()){d.sections.push_back({name,s.size,0,-static_cast<std::int64_t>(s.size),0,false,true});continue;}auto t=it->second;std::uint64_t changed=0;auto n=std::min(s.size,t.size);if(s.off+s.size<=a.size()&&t.off+t.size<=b.size())for(std::uint64_t j=0;j<n;++j)if(x[static_cast<std::size_t>(s.off+j)]!=y[static_cast<std::size_t>(t.off+j)])++changed;d.sections.push_back({name,s.size,t.size,static_cast<std::int64_t>(t.size)-static_cast<std::int64_t>(s.size),changed,false,false});}
 for(const auto&[name,s]:bm)if(am.find(name)==am.end())d.sections.push_back({name,0,s.size,static_cast<std::int64_t>(s.size),0,true,false});
 std::sort(d.sections.begin(),d.sections.end(),[](const auto&a,const auto&b){return a.name<b.name;});return d;
}
Result<SizeReport> analyze_size(const BinaryFile&f){
 SizeReport r;r.file_size=f.size();auto m=f.metadata();r.image_size=m.image_size.value_or(0);r.headers_size=m.headers_size.value_or(0);
 if(m.format==BinaryFormat::PE32||m.format==BinaryFormat::PE64){auto p=parse_pe(f.bytes());if(!p)return p.error();r.code_size=p.value().headers.optional.size_of_code;r.initialized_data=p.value().headers.optional.size_of_initialized_data;r.uninitialized_data=p.value().headers.optional.size_of_uninitialized_data;for(const auto&s:p.value().sections)r.sections.push_back({s.name,s.raw_size,s.virtual_size,s.executable?"code":s.writable?"data":"other"});}
 else if(m.format==BinaryFormat::ELF32||m.format==BinaryFormat::ELF64){auto e=parse_elf_image(f.bytes());if(!e)return e.error();for(const auto&s:e.value().sections){auto kind=(s.flags&4u)?"code":(s.flags&1u)?"data":"other";r.sections.push_back({s.name,s.size,s.size,kind});if(kind=="code")r.code_size+=s.size;else if(kind=="data")r.initialized_data+=s.size;}}
 else r.sections.push_back({"<raw>",f.size(),f.size,"other"});
 return r;
}
std::string format_binary_diff(const BinaryDiff&d,const BinaryFile&a,const BinaryFile&b,bool json){
 std::ostringstream o;if(json){o<<"{\n  \"schema_version\":6,\n  \"old\":\""<<json_escape(a.path().filename().string())<<"\",\n  \"new\":\""<<json_escape(b.path().filename().string())<<"\",\n  \"old_size\":"<<d.old_size<<",\n  \"new_size\":"<<d.new_size<<",\n  \"common_size\":"<<d.common_size<<",\n  \"changed_bytes\":"<<d.changed_bytes<<",\n  \"added_bytes\":"<<d.added_bytes<<",\n  \"removed_bytes\":"<<d.removed_bytes<<",\n  \"similarity\":"<<std::fixed<<std::setprecision(6)<<d.similarity<<",\n  \"hunks\":[";for(std::size_t i=0;i<d.hunks.size();++i){if(i)o<<",";auto&h=d.hunks[i];o<<"{\"offset\":\""<<hx(h.offset)<<"\",\"length\":"<<h.length<<"}";}o<<"],\n  \"sections\":[";for(std::size_t i=0;i<d.sections.size();++i){if(i)o<<",";auto&s=d.sections[i];o<<"{\"name\":\""<<json_escape(s.name)<<"\",\"old_size\":"<<s.old_size<<",\"new_size\":"<<s.new_size<<",\"delta\":"<<s.delta<<",\"changed_bytes\":"<<s.changed_bytes<<",\"added\":"<<(s.added?"true":"false")<<",\"removed\":"<<(s.removed?"true":"false")<<"}";}o<<"]\n}\n";return o.str();}
 o<<"BINX BINARY DIFF\n\nOLD  "<<a.path().filename().string()<<"  "<<d.old_size<<" bytes\nNEW  "<<b.path().filename().string()<<"  "<<d.new_size<<" bytes\n\nCHANGES\n  Changed bytes: "<<d.changed_bytes<<"\n  Added bytes:   "<<d.added_bytes<<"\n  Removed bytes: "<<d.removed_bytes<<"\n  Similarity:    "<<std::fixed<<std::setprecision(2)<<(d.similarity*100.0)<<"%\n\nHUNKS ("<<d.hunks.size()<<")\n";for(auto&h:d.hunks)o<<"  "<<hx(h.offset)<<"  "<<h.length<<" bytes\n";o<<"\nSECTIONS\n";for(auto&s:d.sections)o<<"  "<<std::left<<std::setw(16)<<s.name<<std::right<<" "<<std::setw(8)<<s.old_size<<" -> "<<std::setw(8)<<s.new_size<<"  delta="<<s.delta<<"  changed="<<s.changed_bytes<<(s.added?"  ADDED":s.removed?"  REMOVED":"")<<"\n";return o.str();
}
std::string format_size_report(const SizeReport&r,const BinaryFile&f,bool json){
 std::ostringstream o;if(json){o<<"{\n  \"schema_version\":6,\n  \"file\":\""<<json_escape(f.path().filename().string())<<"\",\n  \"file_size\":"<<r.file_size<<",\n  \"image_size\":"<<r.image_size<<",\n  \"headers_size\":"<<r.headers_size<<",\n  \"code_size\":"<<r.code_size<<",\n  \"initialized_data\":"<<r.initialized_data<<",\n  \"uninitialized_data\":"<<r.uninitialized_data<<",\n  \"sections\":[";for(std::size_t i=0;i<r.sections.size();++i){if(i)o<<",";auto&s=r.sections[i];o<<"{\"name\":\""<<json_escape(s.name)<<"\",\"raw_size\":"<<s.raw_size<<",\"virtual_size\":"<<s.virtual_size<<",\"kind\":\""<<s.kind<<"\"}";}o<<"]\n}\n";return o.str();}
 o<<"BINX SIZE REPORT\n\nFILE\n  "<<f.path().filename().string()<<": "<<r.file_size<<" bytes\n  Image size:        "<<r.image_size<<" bytes\n  Headers:           "<<r.headers_size<<" bytes\n  Code:              "<<r.code_size<<" bytes\n  Initialized data:  "<<r.initialized_data<<" bytes\n  Uninitialized:     "<<r.uninitialized_data<<" bytes\n\nSECTIONS\n";for(auto&s:r.sections)o<<"  "<<std::left<<std::setw(16)<<s.name<<std::right<<" raw="<<std::setw(8)<<s.raw_size<<" virtual="<<std::setw(8)<<s.virtual_size<<" "<<s.kind<<"\n";return o.str();
}
}