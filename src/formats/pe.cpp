#include "binx/formats/pe.hpp"
#include "binx/core/byte_reader.hpp"
#include <algorithm>
#include <cstring>
#include <functional>
#include <iomanip>
#include <limits>
#include <sstream>
#include <unordered_set>

namespace binx {
namespace {
std::uint16_t le16(const std::byte* p) { return std::uint16_t(std::to_integer<unsigned char>(p[0])) | (std::uint16_t(std::to_integer<unsigned char>(p[1])) << 8); }
std::uint32_t le32(const std::byte* p) { return std::uint32_t(std::to_integer<unsigned char>(p[0])) | (std::uint32_t(std::to_integer<unsigned char>(p[1])) << 8) | (std::uint32_t(std::to_integer<unsigned char>(p[2])) << 16) | (std::uint32_t(std::to_integer<unsigned char>(p[3])) << 24); }
std::uint64_t le64(const std::byte* p) { return std::uint64_t(le32(p)) | (std::uint64_t(le32(p + 4)) << 32); }
bool add_u64(std::uint64_t a, std::uint64_t b, std::uint64_t& out) { if (a > std::numeric_limits<std::uint64_t>::max() - b) return false; out = a + b; return true; }
void diag(PEImage& image, DiagnosticSeverity severity, const char* code, const char* component, const std::string& message, std::optional<std::uint64_t> file_offset = {}, std::optional<std::uint64_t> rva = {}) { image.diagnostics.push_back({severity, code, component, file_offset, rva, message}); }
std::string ascii_at(std::span<const std::byte> data, std::uint64_t offset, std::size_t max_len) {
    if (offset >= data.size()) return {};
    const auto start = static_cast<std::size_t>(offset);
    const auto end = std::min(data.size(), start + max_len);
    std::string out;
    for (std::size_t i=start;i<end;++i) { const auto c=std::to_integer<unsigned char>(data[i]); if(c==0)break; if(c<0x20||c>0x7e)return{}; out.push_back(static_cast<char>(c)); }
    return out;
}
std::string utf16_display(std::span<const std::byte> data, std::uint64_t offset, std::size_t units) {
    if(units>4096||offset>data.size()||units> (data.size()-static_cast<std::size_t>(offset))/2) return {};
    std::string out;
    for(std::size_t i=0;i<units;++i){const auto ch=le16(data.data()+static_cast<std::size_t>(offset)+i*2);out.push_back(ch>=0x20&&ch<=0x7e?static_cast<char>(ch):'?');}
    return out;
}
std::optional<std::uint32_t> va_to_rva(std::uint64_t va, std::uint64_t base){if(va<base)return{};const auto r=va-base;if(r>std::numeric_limits<std::uint32_t>::max())return{};return static_cast<std::uint32_t>(r);}
std::string guid_string(const unsigned char* p){
    const auto d1=std::uint32_t(p[0])|(std::uint32_t(p[1])<<8)|(std::uint32_t(p[2])<<16)|(std::uint32_t(p[3])<<24);
    const auto d2=std::uint16_t(p[4])|(std::uint16_t(p[5])<<8);
    const auto d3=std::uint16_t(p[6])|(std::uint16_t(p[7])<<8);
    std::ostringstream o;o<<std::hex<<std::setfill('0')<<std::uppercase<<std::setw(8)<<d1<<"-"<<std::setw(4)<<d2<<"-"<<std::setw(4)<<d3<<"-"<<std::setw(2)<<unsigned(p[8])<<std::setw(2)<<unsigned(p[9])<<"-"<<std::setw(2)<<unsigned(p[10])<<std::setw(2)<<unsigned(p[11])<<std::setw(2)<<unsigned(p[12])<<std::setw(2)<<unsigned(p[13])<<std::setw(2)<<unsigned(p[14])<<std::setw(2)<<unsigned(p[15]);return o.str();
}
const DataDirectory* directory(const PEImage& image,std::size_t index){return index<image.headers.directories.size()?&image.headers.directories[index]:nullptr;}
bool dir_present(const PEImage& image,std::size_t index){const auto*d=directory(image,index);return d&&d->present&&d->size!=0;}
Result<std::uint16_t> read_rva16(std::span<const std::byte> data,const RVAMapper& m,std::uint32_t rva){auto o=m.rva_to_file_offset(rva);if(!o)return o.error();if(o.value()>data.size()||data.size()-static_cast<std::size_t>(o.value())<2)return Error{ErrorCode::InvalidBinary,"RVA has fewer than two file bytes"};return le16(data.data()+static_cast<std::size_t>(o.value()));}
Result<std::uint32_t> read_rva32(std::span<const std::byte> data,const RVAMapper& m,std::uint32_t rva){auto o=m.rva_to_file_offset(rva);if(!o)return o.error();if(o.value()>data.size()||data.size()-static_cast<std::size_t>(o.value())<4)return Error{ErrorCode::InvalidBinary,"RVA has fewer than four file bytes"};return le32(data.data()+static_cast<std::size_t>(o.value()));}
Result<std::uint64_t> read_rva64(std::span<const std::byte> data,const RVAMapper& m,std::uint32_t rva){auto o=m.rva_to_file_offset(rva);if(!o)return o.error();if(o.value()>data.size()||data.size()-static_cast<std::size_t>(o.value())<8)return Error{ErrorCode::InvalidBinary,"RVA has fewer than eight file bytes"};return le64(data.data()+static_cast<std::size_t>(o.value()));}
std::string ascii_rva(std::span<const std::byte> data,const RVAMapper&m,std::uint32_t rva,std::size_t max_len){auto o=m.rva_to_file_offset(rva);return o?ascii_at(data,o.value(),max_len):std::string{};}
bool map_directory(PEImage& image,std::size_t index,const char* code){
    auto*d=index<image.headers.directories.size()?&image.headers.directories[index]:nullptr;
    if(!d||!d->present||d->size==0)return false;
    if(!image.mapper.map_rva_range(d->rva,d->size)){diag(image,DiagnosticSeverity::Warning,code,"directories","directory is not backed by a valid file range",{},d->rva);return false;}
    d->mapped=true;return true;
}
void parse_sections(std::span<const std::byte> data,PEImage& image,std::size_t offset){
    const auto declared=image.headers.coff.number_of_sections;
    if(offset>data.size()){image.section_status=ParseStatus::Malformed;diag(image,DiagnosticSeverity::Error,"PE_SECTION_TABLE_RANGE","sections","section table starts outside the file",offset);return;}
    const auto available=(data.size()-offset)/40;
    const auto count=std::min<std::size_t>(declared,available);
    image.section_status=count==declared?ParseStatus::Valid:ParseStatus::PartiallyParsed;
    if(count!=declared)diag(image,DiagnosticSeverity::Error,"PE_SECTION_TABLE_TRUNCATED","sections","declared section table extends beyond the file",offset);
    image.sections.reserve(count);
    for(std::size_t i=0;i<count;++i){
        const auto*p=data.data()+offset+i*40;PESection s;s.index=i+1;
        for(std::size_t j=0;j<8;++j){const auto c=static_cast<char>(std::to_integer<unsigned char>(p[j]));if(c==0)break;s.name.push_back(c);}
        s.virtual_size=le32(p+8);s.virtual_address=le32(p+12);s.raw_size=le32(p+16);s.raw_pointer=le32(p+20);s.characteristics=le32(p+36);
        s.executable=(s.characteristics&0x20000000u)!=0;s.readable=(s.characteristics&0x40000000u)!=0;s.writable=(s.characteristics&0x80000000u)!=0;s.discardable=(s.characteristics&0x02000000u)!=0;s.shared=(s.characteristics&0x10000000u)!=0;
        image.sections.push_back(std::move(s));
    }
    for(const auto&s:image.sections){
        std::uint64_t end=0;if(!add_u64(s.raw_pointer,s.raw_size,end)||end>data.size())diag(image,DiagnosticSeverity::Warning,"PE_SECTION_RAW_RANGE","sections","section raw range extends beyond the file",s.raw_pointer);
        const auto span=std::max(s.virtual_size,s.raw_size);if(!add_u64(s.virtual_address,span,end))diag(image,DiagnosticSeverity::Warning,"PE_SECTION_VA_OVERFLOW","sections","section virtual range overflows",{},s.virtual_address);else if(image.headers.optional.size_of_image&&end>image.headers.optional.size_of_image)diag(image,DiagnosticSeverity::Warning,"PE_SECTION_IMAGE_RANGE","sections","section virtual range exceeds SizeOfImage",{},s.virtual_address);
    }
    for(std::size_t i=0;i<image.sections.size();++i)for(std::size_t j=i+1;j<image.sections.size();++j){
        const auto&a=image.sections[i],&b=image.sections[j];const auto av=std::uint64_t(a.virtual_address)+std::max(a.virtual_size,a.raw_size);const auto bv=std::uint64_t(b.virtual_address)+std::max(b.virtual_size,b.raw_size);
        const auto ar=std::uint64_t(a.raw_pointer)+a.raw_size,const br=std::uint64_t(b.raw_pointer)+b.raw_size;
        if(a.virtual_address<bv&&b.virtual_address<av)diag(image,DiagnosticSeverity::Warning,"PE_SECTION_VIRTUAL_OVERLAP","sections","section virtual ranges overlap",{},std::max(a.virtual_address,b.virtual_address));
        if(a.raw_size&&b.raw_size&&a.raw_pointer<br&&b.raw_pointer<ar)diag(image,DiagnosticSeverity::Warning,"PE_SECTION_RAW_OVERLAP","sections","section raw file ranges overlap",std::min(a.raw_pointer,b.raw_pointer));
    }
    if(image.headers.optional.section_alignment==0)diag(image,DiagnosticSeverity::Warning,"PE_SECTION_ALIGNMENT","headers","SectionAlignment is zero");
    if(image.headers.optional.file_alignment==0)diag(image,DiagnosticSeverity::Warning,"PE_FILE_ALIGNMENT","headers","FileAlignment is zero");
}
void parse_imports(std::span<const std::byte> data,PEImage& image){
    if(!dir_present(image,1)){image.import_status=ParseStatus::NotPresent;return;}
    if(!map_directory(image,1,"PE_IMPORT_DIRECTORY_RANGE")){image.import_status=ParseStatus::Malformed;return;}
    const auto d=*directory(image,1);ImportTable table;const std::size_t max_desc=d.size/20;bool descriptor_term=false;
    for(std::size_t i=0;i<max_desc;++i){
        const auto rr=std::uint64_t(d.rva)+i*20;if(rr>std::numeric_limits<std::uint32_t>::max())break;auto o=image.mapper.rva_to_file_offset(static_cast<std::uint32_t>(rr));if(!o||o.value()>data.size()||data.size()-static_cast<std::size_t>(o.value())<20)break;
        const auto*p=data.data()+static_cast<std::size_t>(o.value());const auto oft=le32(p),ts=le32(p+4),fwd=le32(p+8),name_rva=le32(p+12),ft=le32(p+16);if(!oft&&!ts&&!fwd&&!name_rva&&!ft){descriptor_term=true;break;}
        ImportModule mod;mod.descriptor_rva=static_cast<std::uint32_t>(rr);mod.lookup_rva=oft?oft:ft;mod.iat_rva=ft;mod.timestamp=ts;mod.forwarder_chain=fwd;mod.dll_name=ascii_rva(data,image.mapper,name_rva,1024);
        if(mod.dll_name.empty())diag(image,DiagnosticSeverity::Warning,"PE_IMPORT_NAME","imports","unable to decode imported DLL name",o.value()+12,name_rva);
        const std::size_t width=image.headers.optional.pe_class==PEClass::PE64?8:4;bool thunk_term=false;
        for(std::size_t n=0;n<1000000;++n){
            const auto delta=std::uint64_t(n)*width, lrva64=std::uint64_t(mod.lookup_rva)+delta, irva64=std::uint64_t(mod.iat_rva)+delta;if(lrva64>std::numeric_limits<std::uint32_t>::max()||irva64>std::numeric_limits<std::uint32_t>::max())break;
            std::uint64_t value=0;if(width==8){auto x=read_rva64(data,image.mapper,static_cast<std::uint32_t>(lrva64));if(!x)break;value=x.value();}else{auto x=read_rva32(data,image.mapper,static_cast<std::uint32_t>(lrva64));if(!x)break;value=x.value();}
            if(value==0){thunk_term=true;break;}
            ImportSymbol sym;sym.lookup_rva=lrva64;sym.iat_rva=irva64;if(auto x=image.mapper.rva_to_file_offset(static_cast<std::uint32_t>(lrva64));x)sym.lookup_file_offset=x.value();if(auto x=image.mapper.rva_to_file_offset(static_cast<std::uint32_t>(irva64));x)sym.iat_file_offset=x.value();
            const auto ordinal_flag=width==8?(value&0x8000000000000000ull)!=0:(value&0x80000000ull)!=0;
            if(ordinal_flag){sym.ordinal=static_cast<std::uint16_t>(value&0xffffu);}
            else{if(value>std::numeric_limits<std::uint32_t>::max()){diag(image,DiagnosticSeverity::Warning,"PE_IMPORT_NAME_RVA","imports","import name RVA exceeds 32-bit range");break;}const auto nrva=static_cast<std::uint32_t>(value);auto hint=read_rva16(data,image.mapper,nrva);if(!hint){diag(image,DiagnosticSeverity::Warning,"PE_IMPORT_NAME_RVA","imports","import-by-name RVA is not mapped",{},nrva);break;}sym.imported_by_name=true;sym.hint=hint.value();if(nrva>std::numeric_limits<std::uint32_t>::max()-2)break;auto name=ascii_rva(data,image.mapper,nrva+2,1024);if(!name.empty())sym.name=name;else diag(image,DiagnosticSeverity::Warning,"PE_IMPORT_NAME","imports","unable to decode imported symbol name",{},nrva);}
            mod.symbols.push_back(std::move(sym));
        }
        if(!thunk_term)diag(image,DiagnosticSeverity::Warning,"PE_IMPORT_UNTERMINATED","imports","import thunk table has no valid terminator",{},mod.lookup_rva);
        table.modules.push_back(std::move(mod));
    }
    if(!descriptor_term)diag(image,DiagnosticSeverity::Warning,"PE_IMPORT_UNTERMINATED","imports","import descriptor table has no valid terminator",{},d.rva);
    image.imports=std::move(table);image.import_status=ParseStatus::Valid;
}
void parse_exports(std::span<const std::byte> data,PEImage& image){
    if(!dir_present(image,0)){image.export_status=ParseStatus::NotPresent;return;}
    if(!map_directory(image,0,"PE_EXPORT_DIRECTORY_RANGE")){image.export_status=ParseStatus::Malformed;return;}
    const auto d=*directory(image,0);auto o=image.mapper.rva_to_file_offset(d.rva);if(!o||o.value()>data.size()||data.size()-static_cast<std::size_t>(o.value())<40){image.export_status=ParseStatus::Malformed;diag(image,DiagnosticSeverity::Error,"PE_EXPORT_HEADER","exports","export directory is truncated",o?std::optional(o.value()):std::nullopt,d.rva);return;}
    const auto*p=data.data()+static_cast<std::size_t>(o.value());const auto base=le32(p+16),nf=le32(p+20),nn=le32(p+24),fr=le32(p+28),nr=le32(p+32),orv=le32(p+36);if(nf>1000000||nn>1000000){image.export_status=ParseStatus::Malformed;diag(image,DiagnosticSeverity::Error,"PE_EXPORT_COUNT","exports","export table declares an unreasonable number of entries");return;}
    ExportTable table;table.ordinal_base=base;auto dll=ascii_rva(data,image.mapper,le32(p+12),1024);if(!dll.empty())table.dll_name=dll;
    std::vector<std::uint32_t> funcs(nf);for(std::uint32_t i=0;i<nf;++i){const auto rr=std::uint64_t(fr)+std::uint64_t(i)*4;if(rr>std::numeric_limits<std::uint32_t>::max()){diag(image,DiagnosticSeverity::Warning,"PE_EXPORT_FUNCTION_RANGE","exports","function address table overflows RVA space");break;}auto x=read_rva32(data,image.mapper,static_cast<std::uint32_t>(rr));if(!x){diag(image,DiagnosticSeverity::Warning,"PE_EXPORT_FUNCTION_RANGE","exports","function address table is truncated",{},static_cast<std::uint32_t>(rr));break;}funcs[i]=x.value();}
    std::vector<std::uint32_t>names(nn);std::vector<std::uint16_t>ords(nn);for(std::uint32_t i=0;i<nn;++i){const auto a=std::uint64_t(nr)+std::uint64_t(i)*4,b=std::uint64_t(orv)+std::uint64_t(i)*2;if(a>std::numeric_limits<std::uint32_t>::max()||b>std::numeric_limits<std::uint32_t>::max())break;auto x=read_rva32(data,image.mapper,static_cast<std::uint32_t>(a));auto y=read_rva16(data,image.mapper,static_cast<std::uint32_t>(b));if(!x||!y)break;names[i]=x.value();ords[i]=y.value();}
    for(std::uint32_t i=0;i<nf;++i){ExportFunction f;f.ordinal=base+i;f.ordinal_index=i;f.rva=funcs[i];if(auto x=image.mapper.rva_to_file_offset(f.rva);x)f.file_offset=x.value();for(std::uint32_t n=0;n<nn;++n)if(ords[n]==i){auto s=ascii_rva(data,image.mapper,names[n],1024);if(!s.empty())f.name=s;break;}std::uint64_t dend=std::uint64_t(d.rva)+d.size;if(f.rva>=d.rva&&f.rva<dend){auto s=ascii_rva(data,image.mapper,f.rva,1024);if(!s.empty()){f.forwarder=s;f.is_forwarder=true;}}table.functions.push_back(std::move(f));}
    image.exports=std::move(table);image.export_status=ParseStatus::Valid;
}
void parse_relocations(std::span<const std::byte> data,PEImage& image){
    if(!dir_present(image,5)){image.relocation_status=ParseStatus::NotPresent;return;}
    if(!map_directory(image,5,"PE_RELOC_DIRECTORY_RANGE")){image.relocation_status=ParseStatus::Malformed;return;}
    const auto d=*directory(image,5);RelocationTable table;std::uint64_t pos=0;while(pos+8<=d.size){const auto rr=std::uint64_t(d.rva)+pos;if(rr>std::numeric_limits<std::uint32_t>::max())break;auto o=image.mapper.rva_to_file_offset(static_cast<std::uint32_t>(rr));if(!o||o.value()>data.size()||data.size()-static_cast<std::size_t>(o.value())<8)break;const auto*p=data.data()+static_cast<std::size_t>(o.value());const auto page=le32(p),size=le32(p+4);if(size<8||size>d.size-pos){diag(image,DiagnosticSeverity::Error,"PE_RELOC_INVALID_BLOCK","relocations","relocation block size is invalid",o.value(),rr);break;}RelocationBlock b;b.page_rva=page;b.block_size=size;const auto count=(size-8)/2;for(std::uint32_t i=0;i<count;++i){const auto er=rr+8+std::uint64_t(i)*2;if(er>std::numeric_limits<std::uint32_t>::max())break;auto x=read_rva16(data,image.mapper,static_cast<std::uint32_t>(er));if(!x)break;const auto w=x.value();RelocationEntry e;e.type=static_cast<std::uint8_t>(w>>12);e.offset=static_cast<std::uint16_t>(w&0xfff);const auto tr=std::uint64_t(page)+e.offset;if(tr<=std::numeric_limits<std::uint32_t>::max()){e.target_rva=static_cast<std::uint32_t>(tr);if(auto z=image.mapper.rva_to_file_offset(e.target_rva);z)e.target_file_offset=z.value();}e.supported=e.type==0||(e.type==3&&image.headers.optional.pe_class==PEClass::PE32)||(e.type==10&&image.headers.optional.pe_class==PEClass::PE64)||(e.type==7&&image.headers.coff.machine==0xaa64);b.entries.push_back(e);}table.blocks.push_back(std::move(b));pos+=size;}
    image.relocations=std::move(table);image.relocation_status=image.relocations->blocks.empty()?ParseStatus::PartiallyParsed:ParseStatus::Valid;
}
void parse_resources(std::span<const std::byte> data,PEImage& image){
    if(!dir_present(image,2)){image.resource_status=ParseStatus::NotPresent;return;}
    if(!map_directory(image,2,"PE_RESOURCE_DIRECTORY_RANGE")){image.resource_status=ParseStatus::Malformed;return;}
    const auto d=*directory(image,2);ResourceTree tree;std::unordered_set<std::uint32_t> visited;std::size_t nodes=0;
    std::function<void(std::uint32_t,std::vector<std::string>,std::size_t)> walk;
    walk=[&](std::uint32_t rel,std::vector<std::string> path,std::size_t depth){
        if(depth>32){diag(image,DiagnosticSeverity::Warning,"PE_RESOURCE_DEPTH","resources","resource directory nesting limit reached",{},d.rva+rel);return;}
        if(++nodes>100000){diag(image,DiagnosticSeverity::Warning,"PE_RESOURCE_NODE_LIMIT","resources","resource node limit reached",{},d.rva+rel);return;}
        if(!visited.insert(rel).second){diag(image,DiagnosticSeverity::Warning,"PE_RESOURCE_CYCLE","resources","resource directory cycle detected",{},d.rva+rel);return;}
        const auto abs=std::uint64_t(d.rva)+rel;if(abs>std::numeric_limits<std::uint32_t>::max()||std::uint64_t(rel)+16>d.size)return;auto fo=image.mapper.rva_to_file_offset(static_cast<std::uint32_t>(abs));if(!fo||fo.value()>data.size()||data.size()-static_cast<std::size_t>(fo.value())<16)return;
        const auto*h=data.data()+static_cast<std::size_t>(fo.value());const auto total=std::uint32_t(le16(h+12))+le16(h+14);if(std::uint64_t(rel)+16+std::uint64_t(total)*8>d.size){diag(image,DiagnosticSeverity::Warning,"PE_RESOURCE_ENTRY_RANGE","resources","resource entry array is outside the directory",fo.value(),abs);return;}
        for(std::uint32_t i=0;i<total;++i){const auto er=abs+16+std::uint64_t(i)*8;if(er>std::numeric_limits<std::uint32_t>::max())continue;auto eo=image.mapper.rva_to_file_offset(static_cast<std::uint32_t>(er));if(!eo||eo.value()>data.size()||data.size()-static_cast<std::size_t>(eo.value())<8)continue;const auto*ep=data.data()+static_cast<std::size_t>(eo.value());const auto name_raw=le32(ep),child_raw=le32(ep+4);auto next=path;
            if(name_raw&0x80000000u){const auto noff=name_raw&0x7fffffffu;const auto nr=std::uint64_t(d.rva)+noff;if(nr<=std::numeric_limits<std::uint32_t>::max()){auto nfo=image.mapper.rva_to_file_offset(static_cast<std::uint32_t>(nr));if(nfo&&nfo.value()+2<=data.size()){const auto len=le16(data.data()+static_cast<std::size_t>(nfo.value()));auto s=utf16_display(data,nfo.value()+2,len);next.push_back(s.empty()?"<unnamed>":s);}else next.push_back("<invalid-name>");}else next.push_back("<invalid-name>");}else next.push_back("#"+std::to_string(name_raw));
            if(child_raw&0x80000000u){walk(child_raw&0x7fffffffu,std::move(next),depth+1);}else{const auto de=std::uint64_t(d.rva)+(child_raw&0x7fffffffu);if(de>std::numeric_limits<std::uint32_t>::max())continue;auto df=image.mapper.rva_to_file_offset(static_cast<std::uint32_t>(de));if(!df||df.value()>data.size()||data.size()-static_cast<std::size_t>(df.value())<16)continue;const auto*dp=data.data()+static_cast<std::size_t>(df.value());ResourceItem item;item.path=std::move(next);item.data_rva=le32(dp);item.data_size=le32(dp+4);item.code_page=le32(dp+8);if(auto z=image.mapper.rva_to_file_offset(item.data_rva);z)item.file_offset=z.value();if(item.path.size()>=3&&item.path[2].rfind("#",0)==0){try{item.language=static_cast<std::uint32_t>(std::stoul(item.path[2].substr(1)));}catch(...){}}tree.items.push_back(std::move(item));}
        }
    };
    walk(0,{},0);image.resources=std::move(tree);image.resource_status=image.resources->items.empty()?ParseStatus::PartiallyParsed:ParseStatus::Valid;
}
void parse_tls(std::span<const std::byte> data,PEImage& image){
    if(!dir_present(image,9)){image.tls_status=ParseStatus::NotPresent;return;}
    if(!map_directory(image,9,"PE_TLS_DIRECTORY_RANGE")){image.tls_status=ParseStatus::Malformed;return;}
    const auto d=*directory(image,9);const std::size_t need=image.headers.optional.pe_class==PEClass::PE64?40:24;auto fo=image.mapper.rva_to_file_offset(d.rva);if(!fo||d.size<need||fo.value()>data.size()||data.size()-static_cast<std::size_t>(fo.value())<need){image.tls_status=ParseStatus::Malformed;diag(image,DiagnosticSeverity::Error,"PE_TLS_HEADER","tls","TLS directory is truncated",fo?std::optional(fo.value()):std::nullopt,d.rva);return;}
    const auto*p=data.data()+static_cast<std::size_t>(fo.value());TLSDirectory t;if(image.headers.optional.pe_class==PEClass::PE64){t.raw_data_start_va=le64(p);t.raw_data_end_va=le64(p+8);t.address_of_index_va=le64(p+16);t.address_of_callbacks_va=le64(p+24);t.size_of_zero_fill=le32(p+32);t.characteristics=le32(p+36);}else{t.raw_data_start_va=le32(p);t.raw_data_end_va=le32(p+4);t.address_of_index_va=le32(p+8);t.address_of_callbacks_va=le32(p+12);t.size_of_zero_fill=le32(p+16);t.characteristics=le32(p+20);}
    const auto cb=va_to_rva(t.address_of_callbacks_va,image.headers.optional.image_base);if(cb){const auto width=image.headers.optional.pe_class==PEClass::PE64?8:4;for(std::size_t i=0;i<4096;++i){const auto rr=std::uint64_t(*cb)+std::uint64_t(i)*width;if(rr>std::numeric_limits<std::uint32_t>::max())break;TLSCallback c;Result<std::uint64_t> rv=Error{ErrorCode::InvalidBinary,"callback unreadable"};if(width==8){rv=read_rva64(data,image.mapper,static_cast<std::uint32_t>(rr));}else{auto x=read_rva32(data,image.mapper,static_cast<std::uint32_t>(rr));if(x)rv=x.value();else rv=x.error();}if(!rv||rv.value()==0)break;c.va=rv.value();c.rva=va_to_rva(c.va,image.headers.optional.image_base);if(c.rva){if(auto z=image.mapper.rva_to_file_offset(*c.rva);z)c.file_offset=z.value();}t.callbacks.push_back(c);}}else diag(image,DiagnosticSeverity::Warning,"PE_TLS_CALLBACKS_UNMAPPED","tls","TLS callback array address is not mappable");
    image.tls=std::move(t);image.tls_status=ParseStatus::Valid;
}
void parse_debug(std::span<const std::byte> data,PEImage& image){
    if(!dir_present(image,6)){image.debug_status=ParseStatus::NotPresent;return;}
    if(!map_directory(image,6,"PE_DEBUG_DIRECTORY_RANGE")){image.debug_status=ParseStatus::Malformed;return;}
    const auto d=*directory(image,6);const auto count=d.size/28;for(std::size_t i=0;i<count;++i){const auto rr=std::uint64_t(d.rva)+std::uint64_t(i)*28;if(rr>std::numeric_limits<std::uint32_t>::max())break;auto fo=image.mapper.rva_to_file_offset(static_cast<std::uint32_t>(rr));if(!fo||fo.value()>data.size()||data.size()-static_cast<std::size_t>(fo.value())<28)break;const auto*p=data.data()+static_cast<std::size_t>(fo.value());DebugEntry e;e.characteristics=le32(p);e.timestamp=le32(p+4);e.major_version=le16(p+8);e.minor_version=le16(p+10);e.type=le32(p+12);e.size_of_data=le32(p+16);e.address_of_raw_data=le32(p+20);e.pointer_to_raw_data=le32(p+24);
        if(e.type==2&&e.size_of_data>=24){std::optional<std::uint64_t> raw;if(std::uint64_t(e.pointer_to_raw_data)+e.size_of_data<=data.size())raw=e.pointer_to_raw_data;else if(auto z=image.mapper.rva_to_file_offset(e.address_of_raw_data);z&&z.value()+e.size_of_data<=data.size())raw=z.value();if(raw&&std::memcmp(data.data()+static_cast<std::size_t>(*raw),"RSDS",4)==0){CodeViewInfo cv;cv.signature="RSDS";cv.guid=guid_string(reinterpret_cast<const unsigned char*>(data.data()+static_cast<std::size_t>(*raw)+4));cv.age=le32(data.data()+static_cast<std::size_t>(*raw)+20);if(e.size_of_data>24)cv.pdb_path=ascii_at(data,*raw+24,e.size_of_data-24);e.codeview=cv;}else diag(image,DiagnosticSeverity::Warning,"PE_DEBUG_CODEVIEW","debug","CodeView entry is present but raw data is unavailable or invalid",fo.value(),rr);}
        image.debug_entries.push_back(std::move(e));}
    image.debug_status=image.debug_entries.empty()?ParseStatus::PartiallyParsed:ParseStatus::Valid;
}
}
RVAMapper::RVAMapper(std::uint64_t file_size,std::uint32_t headers,std::vector<PESection>sections):file_size_(file_size),size_of_headers_(headers),sections_(std::move(sections)){}
Result<std::uint64_t> RVAMapper::rva_to_file_offset(std::uint32_t rva)const{if(rva<size_of_headers_){if(rva<file_size_)return static_cast<std::uint64_t>(rva);return Error{ErrorCode::InvalidBinary,"header RVA is outside the file"};}for(const auto&s:sections_){if(rva<s.virtual_address)continue;const auto delta=std::uint64_t(rva)-s.virtual_address;const auto span=std::max(s.virtual_size,s.raw_size);if(delta<span){if(delta>=s.raw_size)return Error{ErrorCode::InvalidBinary,"RVA is inside a virtual-only section tail"};const auto off=std::uint64_t(s.raw_pointer)+delta;if(off>file_size_)return Error{ErrorCode::InvalidBinary,"RVA maps beyond the file"};return off;}}return Error{ErrorCode::InvalidBinary,"RVA is not file-backed"};}
Result<std::uint32_t> RVAMapper::file_offset_to_rva(std::uint64_t offset)const{if(offset<size_of_headers_&&offset<file_size_)return static_cast<std::uint32_t>(offset);for(const auto&s:sections_){if(offset<s.raw_pointer)continue;const auto delta=offset-s.raw_pointer;if(delta<s.raw_size){const auto r=std::uint64_t(s.virtual_address)+delta;if(r>std::numeric_limits<std::uint32_t>::max())return Error{ErrorCode::InvalidBinary,"RVA overflows 32-bit space"};return static_cast<std::uint32_t>(r);}}return Error{ErrorCode::InvalidBinary,"file offset is not file-backed"};}
Result<ByteRange> RVAMapper::map_rva_range(std::uint32_t rva,std::uint64_t size)const{auto o=rva_to_file_offset(rva);if(!o)return o.error();std::uint64_t end=0;if(size==0)return ByteRange{o.value(),0};if(!add_u64(o.value(),size,end)||end>file_size_)return Error{ErrorCode::InvalidBinary,"RVA range extends beyond file"};return ByteRange{o.value(),size};}
bool identify_pe(std::span<const std::byte> data,Metadata& metadata){if(data.size()<2||std::to_integer<unsigned char>(data[0])!='M'||std::to_integer<unsigned char>(data[1])!='Z')return false;metadata.platform="Windows";metadata.endianness=Endianness::Little;if(data.size()<0x40){metadata.format=BinaryFormat::Unknown;return true;}const auto e=le32(data.data()+0x3c);if(e>data.size()-4||std::memcmp(data.data()+e,"PE\0\0",4)!=0||data.size()-e<24){metadata.format=BinaryFormat::Unknown;return true;}const auto machine=le16(data.data()+e+4),sections=le16(data.data()+e+6),osize=le16(data.data()+e+20);metadata.raw_machine=machine;metadata.section_count=sections;const auto oo=std::size_t(e)+24;if(osize<2||oo>data.size()||osize>data.size()-oo){metadata.format=BinaryFormat::Unknown;return true;}const auto magic=le16(data.data()+oo);metadata.format=magic==0x10b?BinaryFormat::PE32:magic==0x20b?BinaryFormat::PE64:BinaryFormat::Unknown;if(machine==0x14c)metadata.architecture=Architecture::X86;else if(machine==0x8664)metadata.architecture=Architecture::X86_64;else if(machine==0x1c0)metadata.architecture=Architecture::ARM;else if(machine==0xaa64)metadata.architecture=Architecture::ARM64;if(metadata.format==BinaryFormat::PE32||metadata.format==BinaryFormat::PE64){metadata.entry_point=le32(data.data()+oo+16);metadata.image_base=metadata.format==BinaryFormat::PE64?le64(data.data()+oo+24):le32(data.data()+oo+28);}return true;}
Result<PEImage> parse_pe(std::span<const std::byte> data){
    if(data.size()<2||std::to_integer<unsigned char>(data[0])!='M'||std::to_integer<unsigned char>(data[1])!='Z')return Error{ErrorCode::UnsupportedFormat,"input is not a PE image"};PEImage image;
    if(data.size()<0x40){image.header_status=ParseStatus::Malformed;diag(image,DiagnosticSeverity::Error,"PE_DOS_TRUNCATED","headers","DOS header is truncated");return image;}
    image.headers.e_lfanew=le32(data.data()+0x3c);if(image.headers.e_lfanew>data.size()-4||std::memcmp(data.data()+image.headers.e_lfanew,"PE\0\0",4)!=0){image.header_status=ParseStatus::Malformed;diag(image,DiagnosticSeverity::Error,"PE_BAD_SIGNATURE","headers","PE signature is missing or outside the file",image.headers.e_lfanew);return image;}
    const auto nt=image.headers.e_lfanew;if(data.size()-nt<24){image.header_status=ParseStatus::Malformed;diag(image,DiagnosticSeverity::Error,"PE_COFF_TRUNCATED","headers","COFF header is truncated",nt);return image;}
    const auto*c=data.data()+nt+4;auto&h=image.headers.coff;h.machine=le16(c);h.number_of_sections=le16(c+2);h.timestamp=le32(c+4);h.pointer_to_symbol_table=le32(c+8);h.number_of_symbols=le32(c+12);h.optional_header_size=le16(c+16);h.characteristics=le16(c+18);
    const std::size_t oo=std::size_t(nt)+24;if(h.optional_header_size<2||oo>data.size()||h.optional_header_size>data.size()-oo){image.header_status=ParseStatus::Malformed;diag(image,DiagnosticSeverity::Error,"PE_OPTIONAL_RANGE","headers","optional header extends beyond file",oo);return image;}
    auto&o=image.headers.optional;o.magic=le16(data.data()+oo);if(o.magic==0x10b)o.pe_class=PEClass::PE32;else if(o.magic==0x20b)o.pe_class=PEClass::PE64;else{image.header_status=ParseStatus::Unsupported;diag(image,DiagnosticSeverity::Error,"PE_OPTIONAL_MAGIC","headers","unsupported PE optional-header magic",oo);return image;}
    const std::size_t min_common=o.pe_class==PEClass::PE64?112:96;if(h.optional_header_size<min_common){image.header_status=ParseStatus::Malformed;diag(image,DiagnosticSeverity::Error,"PE_OPTIONAL_TRUNCATED","headers","optional header is too short");return image;}
    const auto r16=[&](std::size_t x){return le16(data.data()+oo+x);};const auto r32=[&](std::size_t x){return le32(data.data()+oo+x);};const auto r64=[&](std::size_t x){return le64(data.data()+oo+x);};
    o.major_linker_version=std::to_integer<unsigned char>(data[oo+2]);o.minor_linker_version=std::to_integer<unsigned char>(data[oo+3]);o.size_of_code=r32(4);o.size_of_initialized_data=r32(8);o.size_of_uninitialized_data=r32(12);o.address_of_entry_point=r32(16);o.base_of_code=r32(20);o.image_base=o.pe_class==PEClass::PE64?r64(24):r32(28);o.section_alignment=r32(32);o.file_alignment=r32(36);o.major_os_version=r16(40);o.minor_os_version=r16(42);o.major_image_version=r16(44);o.minor_image_version=r16(46);o.major_subsystem_version=r16(48);o.minor_subsystem_version=r16(50);o.win32_version_value=r32(52);o.size_of_image=r32(56);o.size_of_headers=r32(60);o.checksum=r32(64);o.subsystem=r16(68);o.dll_characteristics=r16(70);
    if(o.pe_class==PEClass::PE64){o.size_of_stack_reserve=r64(72);o.size_of_stack_commit=r64(80);o.size_of_heap_reserve=r64(88);o.size_of_heap_commit=r64(96);o.loader_flags=r32(104);o.number_of_rva_and_sizes=r32(108);}else{o.size_of_stack_reserve=r32(72);o.size_of_stack_commit=r32(76);o.size_of_heap_reserve=r32(80);o.size_of_heap_commit=r32(84);o.loader_flags=r32(88);o.number_of_rva_and_sizes=r32(92);}
    const auto dd_start=oo+(o.pe_class==PEClass::PE64?112:96);const auto available_dirs=(h.optional_header_size-(o.pe_class==PEClass::PE64?112u:96u))/8u;const auto count=std::min<std::uint32_t>(std::min(o.number_of_rva_and_sizes,16u),available_dirs);image.headers.directories.resize(count);for(std::size_t i=0;i<count;++i){auto&d=image.headers.directories[i];d.rva=le32(data.data()+dd_start+i*8);d.size=le32(data.data()+dd_start+i*8+4);d.present=d.rva!=0||d.size!=0;}
    image.header_status=ParseStatus::Valid;
    const auto section_offset=oo+h.optional_header_size;parse_sections(data,image,section_offset);image.mapper=RVAMapper(data.size(),o.size_of_headers,image.sections);
    if(o.section_alignment&&o.file_alignment&&o.file_alignment>o.section_alignment)diag(image,DiagnosticSeverity::Warning,"PE_ALIGNMENT_RELATION","headers","FileAlignment is larger than SectionAlignment");
    if(o.size_of_headers>data.size())diag(image,DiagnosticSeverity::Warning,"PE_HEADERS_SIZE_RANGE","headers","SizeOfHeaders exceeds file size");
    std::uint64_t image_end=0;for(const auto&s:image.sections)image_end=std::max(image_end,std::uint64_t(s.virtual_address)+std::max(s.virtual_size,s.raw_size));if(o.size_of_image&&image_end>o.size_of_image)diag(image,DiagnosticSeverity::Warning,"PE_SIZE_OF_IMAGE_MISMATCH","headers","section ranges extend beyond declared SizeOfImage");
    if(auto ep=image.mapper.rva_to_file_offset(o.address_of_entry_point);ep){image.headers.entry_point_file_offset=ep.value();for(std::size_t i=0;i<image.sections.size();++i){const auto&s=image.sections[i];if(o.address_of_entry_point>=s.virtual_address&&std::uint64_t(o.address_of_entry_point)-s.virtual_address<std::max(s.virtual_size,s.raw_size)){image.headers.entry_point_section=i;break;}}}else diag(image,DiagnosticSeverity::Warning,"PE_ENTRYPOINT_UNMAPPED","headers","entry point RVA has no file-backed mapping",{},o.address_of_entry_point);
    for(auto&i:image.headers.directories)if(i.present&&i.size){if(image.mapper.map_rva_range(i.rva,i.size))i.mapped=true;}
    parse_imports(data,image);parse_exports(data,image);parse_relocations(data,image);parse_resources(data,image);parse_tls(data,image);parse_debug(data,image);return image;
}
const char*pe_status_name(ParseStatus s){switch(s){case ParseStatus::NotPresent:return"not present";case ParseStatus::NotParsed:return"not parsed";case ParseStatus::Valid:return"valid";case ParseStatus::PartiallyParsed:return"partial";case ParseStatus::Malformed:return"malformed";case ParseStatus::Unsupported:return"unsupported";}return"unknown";}
const char*diagnostic_severity_name(DiagnosticSeverity s){switch(s){case DiagnosticSeverity::Info:return"info";case DiagnosticSeverity::Warning:return"warning";case DiagnosticSeverity::Error:return"error";}return"unknown";}
std::string machine_name(std::uint16_t m){switch(m){case 0x14c:return"i386";case 0x8664:return"AMD64";case 0x1c0:return"ARM";case 0xaa64:return"ARM64";case 0x1c4:return"ARM Thumb-2";case 0x5032:return"RISC-V 32";case 0x5064:return"RISC-V 64";default:return"Unknown";}}
const char*subsystem_name(std::uint16_t s){switch(s){case 1:return"Native";case 2:return"Windows GUI";case 3:return"Windows CUI";case 7:return"POSIX CUI";case 10:return"EFI application";case 11:return"EFI boot service";case 12:return"EFI runtime";case 13:return"EFI ROM";case 14:return"Xbox";case 16:return"Windows boot application";default:return"Unknown";}}
std::vector<std::string>coff_characteristic_names(std::uint16_t v){std::vector<std::string>r;if(v&0x0002)r.push_back("executable");if(v&0x0020)r.push_back("large-address-aware");if(v&0x0100)r.push_back("32-bit-machine");if(v&0x0200)r.push_back("debug-stripped");if(v&0x0001)r.push_back("relocations-stripped");if(v&0x2000)r.push_back("DLL");if(v&0x1000)r.push_back("system");return r;}
std::vector<std::string>dll_characteristic_names(std::uint16_t v){std::vector<std::string>r;if(v&0x0040)r.push_back("dynamic-base");if(v&0x0100)r.push_back("NX-compatible");if(v&0x0020)r.push_back("high-entropy-VA");if(v&0x4000)r.push_back("guard-CF");if(v&0x8000)r.push_back("terminal-server-aware");return r;}
}
