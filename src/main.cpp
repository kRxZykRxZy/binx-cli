#include "binx/cli/output.hpp"
#include "binx/core/binary.hpp"
#include "binx/formats/detect.hpp"
#include "binx/formats/elf.hpp"
#include "binx/formats/pe.hpp"
#include "binx/hashing/hasher.hpp"
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
using namespace binx;
namespace {
struct Options{std::string command;std::filesystem::path input;std::filesystem::path output;bool has_output=false;bool json=false;bool quiet=false;bool verbose=false;};
void err(const std::string&s){std::cerr<<"binx: "<<s<<"\n";}
bool parse(int argc,char**argv,Options&o){
    if(argc<2)return false;
    o.command=argv[1];
    if(o.command=="--help"||o.command=="-h"){o.command="help";return true;}
    if(o.command=="--version"){o.command="version";return true;}
    std::vector<std::string>pos;
    for(int i=2;i<argc;++i){const std::string a=argv[i];
        if(a=="--json")o.json=true;else if(a=="--quiet")o.quiet=true;else if(a=="--verbose")o.verbose=true;
        else if(a=="--help"||a=="-h"){o.command="help";return true;}
        else if(a=="--output"||a=="-o"){if(i+1>=argc){err("--output requires a path");return false;}o.output=argv[++i];o.has_output=true;}
        else if(!a.empty()&&a[0]=='-'){err("unknown option '"+a+"'");return false;}else pos.push_back(a);
    }
    if(o.command=="help"||o.command=="version")return true;
    if(pos.size()!=1){err(pos.empty()?"missing input file":"too many input files");return false;}o.input=pos[0];return true;
}
bool emit(const std::string&s,const Options&o){if(o.quiet)return true;if(!o.has_output){std::cout<<s;return static_cast<bool>(std::cout);}std::ofstream f(o.output,std::ios::binary|std::ios::trunc);if(!f){err("unable to open output file '"+o.output.string()+"'");return false;}f.write(s.data(),static_cast<std::streamsize>(s.size()));return static_cast<bool>(f);}
bool is_pe(const BinaryFormat f){return f==BinaryFormat::PE32||f==BinaryFormat::PE64;}
bool pe_command(const std::string&c){return c=="inspect"||c=="sections"||c=="imports"||c=="exports"||c=="resources"||c=="relocations";}
bool elf_command(const std::string&c){return c=="inspect"||c=="sections"||c=="segments"||c=="symbols"||c=="dynamic"||c=="notes"||c=="relocations";}
}
int main(int argc,char**argv){
    Options o;if(!parse(argc,argv,o)){std::cerr<<format_help();return static_cast<int>(ErrorCode::InvalidArguments);}
    if(o.command=="help"){std::cout<<format_help();return 0;}
    if(o.command=="version"){std::cout<<format_version();return 0;}
    if(o.command!="info"&&o.command!="inspect"&&o.command!="hash"&&!pe_command(o.command)&&!elf_command(o.command)){err("unknown command '"+o.command+"'");return static_cast<int>(ErrorCode::InvalidArguments);}
    auto file=BinaryFile::open(o.input);if(!file){err(file.error().message);return static_cast<int>(file.error().code);}
    if(o.command=="hash"){auto h=hash_all(file.value().bytes());if(!h){err(h.error().message);return static_cast<int>(h.error().code);}return emit(format_hashes(h.value(),o.json),o)?0:static_cast<int>(ErrorCode::FileAccess);}
    if(!pe_command(o.command)&&!elf_command(o.command)){if(o.verbose)std::cerr<<"[binx] detected "<<format_name(file.value().metadata().format)<<"\n";return emit(format_info(file.value(),o.json,o.command=="inspect"),o)?0:static_cast<int>(ErrorCode::FileAccess);}
    if(elf_command(o.command)&&(file.value().metadata().format==BinaryFormat::ELF32||file.value().metadata().format==BinaryFormat::ELF64)){auto elf=parse_elf_image(file.value().bytes());if(!elf){err(elf.error().message);return static_cast<int>(elf.error().code);}if(o.verbose)std::cerr<<"[binx] ELF parser: "<<pe_status_name(elf.value().header_status)<<", sections="<<elf.value().sections.size()<<", segments="<<elf.value().segments.size()<<"\\n";return emit(format_elf_command(elf.value(),o.command,o.json,o.command=="inspect"),o)?0:static_cast<int>(ErrorCode::FileAccess);}
    if(elf_command(o.command)){err("command requires an ELF image");return static_cast<int>(ErrorCode::UnsupportedFormat);}
    if(o.command=="inspect"&&!is_pe(file.value().metadata().format))return emit(format_info(file.value(),o.json,true),o)?0:static_cast<int>(ErrorCode::FileAccess);
    auto pe=parse_pe(file.value().bytes());if(!pe){err(pe.error().message);return static_cast<int>(pe.error().code);}
    const auto&image=pe.value();if(o.verbose)std::cerr<<"[binx] PE parser: "<<pe_status_name(image.header_status)<<", sections="<<image.sections.size()<<", diagnostics="<<image.diagnostics.size()<<"\n";
    if(!emit(format_pe_command(image,o.command,o.json,o.command=="inspect"),o))return static_cast<int>(ErrorCode::FileAccess);
    if(image.header_status==ParseStatus::Malformed||image.header_status==ParseStatus::Unsupported)return static_cast<int>(ErrorCode::InvalidBinary);
    return 0;
}
