#include "binx/analysis/dependencies.hpp"
#include "binx/formats/detect.hpp"
#include "binx/formats/elf.hpp"
#include "binx/formats/macho.hpp"
#include "binx/formats/pe.hpp"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <queue>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace binx {
namespace {
std::uint32_t le32(const std::byte*p){return std::uint32_t(std::to_integer<unsigned char>(p[0]))|(std::uint32_t(std::to_integer<unsigned char>(p[1]))<<8)|(std::uint32_t(std::to_integer<unsigned char>(p[2]))<<16)|(std::uint32_t(std::to_integer<unsigned char>(p[3]))<<24);}
std::uint32_t be32(const std::byte*p){return std::uint32_t(std::to_integer<unsigned char>(p[0]))<<24|(std::uint32_t(std::to_integer<unsigned char>(p[1]))<<16)|(std::uint32_t(std::to_integer<unsigned char>(p[2]))<<8)|std::uint32_t(std::to_integer<unsigned char>(p[3]));}
std::uint64_t le64(const std::byte*p){return std::uint64_t(le32(p))|(std::uint64_t(le32(p+4))<<32);}
std::uint64_t be64(const std::byte*p){return std::uint64_t(be32(p))<<32|be32(p+4);}
std::uint32_t rd32(std::span<const std::byte>d,std::size_t o,bool le){return le?le32(d.data()+o):be32(d.data()+o);}
std::uint64_t rd64(std::span<const std::byte>d,std::size_t o,bool le){return le?le64(d.data()+o):be64(d.data()+o);}
std::string cstr(std::span<const std::byte>d,std::uint64_t off,std::size_t max){if(off>=d.size())return{};std::size_t p=static_cast<std::size_t>(off);const auto end=std::min(d.size(),p+max);std::string s;for(;p<end;++p){auto c=std::to_integer<unsigned char>(d[p]);if(!c)break;if(c<0x20||c>0x7e)return{};s.push_back(static_cast<char>(c));}return s;}
bool read_file(const std::filesystem::path&p,std::vector<std::byte>&out){std::ifstream f(p,std::ios::binary);if(!f)return false;f.seekg(0,std::ios::end);const auto n=f.tellg();if(n<0)return false;f.seekg(0);out.resize(static_cast<std::size_t>(n));if(!out.empty())f.read(reinterpret_cast<char*>(out.data()),static_cast<std::streamsize>(n));return static_cast<bool>(f)||out.empty();}
std::vector<Dependency> unique_dependencies(std::vector<Dependency> in){std::vector<Dependency>out;std::set<std::pair<std::string,DependencyKind>>seen;for(auto&d:in)if(seen.emplace(d.name,d.kind).second)out.push_back(std::move(d));return out;}
std::vector<Dependency> pe_deps(const BinaryFile&f){std::vector<Dependency>out;auto p=parse_pe(f.bytes());if(p&&p.value().imports)for(const auto&m:p.value().imports->modules)if(!m.dll_name.empty())out.push_back({m.dll_name,DependencyKind::PEImport,false,false});return unique_dependencies(std::move(out));}
std::vector<Dependency> elf_deps(const BinaryFile&f){
 std::vector<Dependency>out;const auto d=f.bytes();if(d.size()<0x34||std::to_integer<unsigned char>(d[0])!=0x7f||std::to_integer<unsigned char>(d[1])!='E'||std::to_integer<unsigned char>(d[2])!='L'||std::to_integer<unsigned char>(d[3])!='F')return out;
 const bool x=d[4]==std::byte{2};const bool le=d[5]==std::byte{1};if(!x&&d[4]!=std::byte{1})return out;if(!le&&d[5]!=std::byte{2})return out;
 const std::size_t phoff_off=x?32:28, phentsize_off=x?54:42, phnum_off=x?56:44;const std::uint64_t phoff=x?rd64(d,phoff_off,le):rd32(d,phoff_off,le);const auto phentsize=static_cast<std::size_t>(rd32(d,phentsize_off,le)&0xffffu);const auto phnum=static_cast<std::size_t>(rd32(d,phnum_off,le)&0xffffu);if(!phentsize||phnum>4096||phoff>d.size()||std::uint64_t(phnum)*phentsize>d.size()-phoff)return out;
 struct Load{std::uint64_t off=0,vaddr=0,filesz=0,memsz=0;};std::vector<Load>loads;std::uint64_t dyn_off=0,dyn_size=0;
 for(std::size_t n=0;n<phnum;++n){const auto o=phoff+std::uint64_t(n)*phentsize;if(o+phentsize>d.size())break;const auto type=rd32(d,static_cast<std::size_t>(o),le);if(type==1){Load l;l.off=x?rd64(d,static_cast<std::size_t>(o+8),le):rd32(d,static_cast<std::size_t>(o+4),le);l.vaddr=x?rd64(d,static_cast<std::size_t>(o+16),le):rd32(d,static_cast<std::size_t>(o+8),le);l.filesz=x?rd64(d,static_cast<std::size_t>(o+32),le):rd32(d,static_cast<std::size_t>(o+16),le);l.memsz=x?rd64(d,static_cast<std::size_t>(o+40),le):rd32(d,static_cast<std::size_t>(o+20),le);loads.push_back(l);}else if(type==2){dyn_off=x?rd64(d,static_cast<std::size_t>(o+8),le):rd32(d,static_cast<std::size_t>(o+4),le);dyn_size=x?rd64(d,static_cast<std::size_t>(o+32),le):rd32(d,static_cast<std::size_t>(o+16),le);}}
 auto va_to_file=[&](std::uint64_t va)->std::optional<std::uint64_t>{for(const auto&l:loads)if(va>=l.vaddr&&va-l.vaddr<l.filesz)return l.off+(va-l.vaddr);return{};};
 if(!dyn_off){return out;}if(dyn_off>d.size()||dyn_size>d.size()-dyn_off)return out;
 const std::size_t ent=x?16:8;std::uint64_t strtab_va=0,strsz=0;std::vector<std::uint64_t>needed;
 for(std::uint64_t o=dyn_off;o+ent<=dyn_off+dyn_size;o+=ent){const auto tag=x?static_cast<std::int64_t>(rd64(d,static_cast<std::size_t>(o),le)):static_cast<std::int32_t>(rd32(d,static_cast<std::size_t>(o),le));const auto value=x?rd64(d,static_cast<std::size_t>(o+8),le):rd32(d,static_cast<std::size_t>(o+4),le);if(tag==0)break;if(tag==1)needed.push_back(value);else if(tag==5)strtab_va=value;else if(tag==10)strsz=value;}
 auto str_file=va_to_file(strtab_va);if(!str_file)return out;
 for(auto n:needed){if(n>=strsz)continue;auto name=cstr(d,*str_file+n,static_cast<std::size_t>(std::min<std::uint64_t>(4096,strsz-n)));if(!name.empty())out.push_back({name,DependencyKind::ELFNeeded,false,false});}
 return unique_dependencies(std::move(out));
}
std::vector<Dependency> macho_deps(std::span<const std::byte>d){
 std::vector<Dependency>out;if(d.size()<4)return out;auto magic=be32(d.data());bool le=false,is64=false,fat=false;
 if(magic==0xfeedface){}else if(magic==0xcefaedfe)le=true;else if(magic==0xfeedfacf)is64=true;else if(magic==0xcffaedfe){le=true;is64=true;}else if(magic==0xcafebabe||magic==0xbebafeca||magic==0xcafebabf||magic==0xbfbafeca){fat=true;le=(magic==0xbebafeca||magic==0xbfbafeca);if(d.size()<8)return out;const auto n=rd32(d,4,le);if(!n)return out;const auto ent=(magic==0xcafebabf||magic==0xbfbafeca)?32u:20u;if(8u+ent>d.size())return out;const auto off=rd32(d,8+8,le);if(off>=d.size())return out;magic=be32(d.data()+off);le=(magic==0xcefaedfe||magic==0xcffaedfe);is64=(magic==0xfeedfacf||magic==0xcffaedfe);}else return out;
 std::size_t base=0;if(fat)base=rd32(d,16,le);const std::size_t header=is64?32:28;if(base+header>d.size())return out;const auto ncmd=rd32(d,base+16,le),cmdbytes=rd32(d,base+20,le);std::size_t p=base+header,end=std::min<std::size_t>(d.size(),p+cmdbytes);for(std::uint32_t i=0;i<ncmd&&p+8<=end;++i){const auto cmd=rd32(d,p,le),sz=rd32(d,p+4,le);if(sz<8||p+sz>end)break;const bool weak=cmd==0x80000018u,reexport=cmd==0x8000001fu;const bool dylib=cmd==0xcu||cmd==0x20u||cmd==0x80000018u||cmd==0x8000001fu||cmd==0x80000023u;if(dylib&&sz>=24){const auto noff=rd32(d,p+8,le);if(noff<sz){auto n=cstr(d,p+noff,sz-noff);if(!n.empty())out.push_back({n,DependencyKind::MachODylib,weak,reexport});}}p+=sz;}return unique_dependencies(std::move(out));
}
std::string key_path(const std::filesystem::path&p){std::error_code ec;const auto q=std::filesystem::weakly_canonical(p,ec);return (ec?p.lexically_normal():q).string();}
std::optional<std::filesystem::path> resolve(const std::filesystem::path&parent,const std::filesystem::path&executable_parent,const std::string&name,const std::vector<std::filesystem::path>&search){
 std::string expanded=name;const std::string a="@loader_path/",b="@executable_path/",o1="$ORIGIN/",o2="$ORIGIN\\";
 if(expanded.rfind(a,0)==0)expanded=(parent/expanded.substr(a.size())).string();else if(expanded.rfind(b,0)==0)expanded=(executable_parent/expanded.substr(b.size())).string();else if(expanded.rfind(o1,0)==0)expanded=(parent/expanded.substr(o1.size())).string();else if(expanded.rfind(o2,0)==0)expanded=(parent/expanded.substr(o2.size())).string();
 std::vector<std::filesystem::path>candidates;const auto n=std::filesystem::path(expanded);if(n.is_absolute())candidates.push_back(n);else{candidates.push_back(parent/n);for(const auto&s:search)candidates.push_back(s/n);if(n.filename()!=n){const auto base=n.filename();candidates.push_back(parent/base);for(const auto&s:search)candidates.push_back(s/base);}}
 for(const auto&c:candidates){std::error_code ec;if(std::filesystem::is_regular_file(c,ec))return std::filesystem::weakly_canonical(c,ec);}
 return {};
}
void find_cycles(const DependencyGraph&g,std::vector<std::vector<std::size_t>>&out){std::vector<int>state(g.nodes.size());std::vector<std::size_t>stack;std::function<void(std::size_t)>dfs=[&](std::size_t u){state[u]=1;stack.push_back(u);for(const auto&e:g.edges)if(e.from==u){if(state[e.to]==0)dfs(e.to);else if(state[e.to]==1){auto it=std::find(stack.begin(),stack.end(),e.to);if(it!=stack.end())out.emplace_back(it,stack.end());}}state[u]=2;stack.pop_back();};for(std::size_t i=0;i<g.nodes.size();++i)if(state[i]==0)dfs(i);}
}
std::string normalize_library_name(const std::string&s){const auto p=s.find_last_of("/\\\\");return p==std::string::npos?s:s.substr(p+1);}
std::string dependency_kind_name(DependencyKind k){switch(k){case DependencyKind::PEImport:return"pe-import";case DependencyKind::ELFNeeded:return"elf-needed";case DependencyKind::MachODylib:return"macho-dylib";}return"unknown";}
std::vector<Dependency> extract_dependencies(const BinaryFile&f){switch(f.metadata().format){case BinaryFormat::PE32:case BinaryFormat::PE64:return pe_deps(f);case BinaryFormat::ELF32:case BinaryFormat::ELF64:return elf_deps(f);case BinaryFormat::MachO32:case BinaryFormat::MachO64:case BinaryFormat::MachOFat:return macho_deps(f.bytes());default:return{};}}
Result<DependencyGraph> build_dependency_graph(const std::filesystem::path&root,const std::vector<std::filesystem::path>&search,std::size_t max_depth,std::size_t max_nodes){
 std::vector<std::byte>bytes;if(!read_file(root,bytes))return Error{ErrorCode::FileNotFound,"unable to read dependency root '"+root.string()+"'"};
 DependencyGraph g;std::unordered_map<std::string,std::size_t>ids;std::queue<std::pair<std::size_t,std::size_t>> q;
 auto add_node=[&](const std::filesystem::path&p,bool resolved)->std::optional<std::size_t>{const auto k=key_path(p);if(auto it=ids.find(k);it!=ids.end())return it->second;if(g.nodes.size()>=max_nodes)return{};auto f=BinaryFile::open(p);if(!f)return{};DependencyNode n;n.id=g.nodes.size();n.path=std::filesystem::path(k);n.resolved=resolved;n.format=f.value().metadata().format;n.architecture=f.value().metadata().architecture;n.file_size=f.value().size();g.nodes.push_back(n);ids[k]=n.id;return n.id;};
 auto rid=add_node(root,true);if(!rid)return Error{ErrorCode::Analysis,"unable to initialize dependency graph root"};q.push({*rid,0});std::unordered_set<std::size_t>expanded;std::set<std::string>unresolved;
 while(!q.empty()){auto [u,depth]=q.front();q.pop();if(expanded.count(u))continue;expanded.insert(u);if(depth>max_depth)continue;auto f=BinaryFile::open(g.nodes[u].path);if(!f)continue;for(auto dep:extract_dependencies(f.value())){auto resolved=resolve(g.nodes[u].path.parent_path(),std::filesystem::path(g.nodes[*rid].path).parent_path(),dep.name,search);if(!resolved){unresolved.insert(dep.name);continue;}auto v=add_node(*resolved,true);if(!v){if(g.nodes.size()>=max_nodes)return Error{ErrorCode::Analysis,"dependency graph node limit exceeded"};continue;}g.edges.push_back({u,*v,dep});if(depth+1<=max_depth)q.push({*v,depth+1});}}
 g.unresolved.assign(unresolved.begin(),unresolved.end());find_cycles(g,g.cycles);return g;
}
std::string dependency_graph_dot(const DependencyGraph&g){
 auto esc=[](const std::string&s){std::string o;for(char c:s){if(c=='"')o+="\\\"";else if(c=='\\')o+="\\\\";
 else o+=c;}return o;};
 std::ostringstream o;o<<"digraph binx_dependencies {\n  rankdir=LR;\n";
 for(const auto&n:g.nodes)o<<"  n"<<n.id<<" [label=\""<<esc(n.path.filename().string())<<"\"];\n";
 for(const auto&e:g.edges)o<<"  n"<<e.from<<" -> n"<<e.to<<" [label=\""<<esc(dependency_kind_name(e.dependency.kind))<<"\"];\n";
 o<<"}\n";return o.str();
}
}
