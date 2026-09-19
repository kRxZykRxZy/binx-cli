#include "binx/cli/output.hpp"
#include "binx/formats/detect.hpp"
#include "binx/version.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
namespace binx {
static std::string esc(const std::string& s){std::string o;for(char c:s){if(c=='"')o+="\\\"";else if(c=='\\')o+="\\\\";
else if(static_cast<unsigned char>(c)<0x20){std::ostringstream x;x<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<int(static_cast<unsigned char>(c));o+=x.str();}else o+=c;}return o;}
static std::string hex64(std::uint64_t v){std::ostringstream s;s<<"0x"<<std::hex<<std::uppercase<<v;return s.str();}
void print_help(){std::cout<<"BinX — Binary Inspector v"<<BINX_VERSION<<"\n\nUsage:\n  binx <command> <file> [options]\n\nCommands:\n  info       Show concise binary metadata\n  inspect    Inspect binary metadata\n  hash       Calculate MD5, SHA-1 and SHA-256\n  version    Show BinX version\n  help       Show this help\n\nOptions:\n  --json     Emit machine-readable JSON\n  --verbose  Enable diagnostic output (reserved in v0.1)\n  --quiet    Suppress non-error output\n  --help     Show help\n";}
void print_version(){std::cout<<"BinX Binary Inspector "<<BINX_VERSION<<"\n";}
void print_info(const BinaryFile& f,bool json){const auto&m=f.metadata();if(json){std::cout<<"{\n  \"file\": {\"name\": \""<<esc(f.path().filename().string())<<"\", \"size\": "<<m.file_size<<"},\n";std::cout<<"  \"format\": \""<<format_name(m.format)<<"\",\n  \"architecture\": \""<<architecture_name(m.architecture)<<"\",\n  \"endianness\": \""<<endianness_name(m.endianness)<<"\",\n  \"platform\": \""<<esc(m.platform)<<"\",\n";if(m.entry_point)std::cout<<"  \"entry_point\": \""<<hex64(*m.entry_point)<<"\",\n";else std::cout<<"  \"entry_point\": null,\n";if(m.image_base)std::cout<<"  \"image_base\": \""<<hex64(*m.image_base)<<"\"\n";else std::cout<<"  \"image_base\": null\n";std::cout<<"}\n";return;}std::cout<<"BinX Binary Inspector v"<<BINX_VERSION<<"\n\nFILE\n  Name:          "<<f.path().filename().string()<<"\n  Size:          "<<m.file_size<<" bytes\n\nFORMAT\n  Type:          "<<format_name(m.format)<<"\n  Architecture:  "<<architecture_name(m.architecture)<<"\n  Endianness:    "<<endianness_name(m.endianness)<<"\n  Platform:      "<<(m.platform.empty()?"unknown":m.platform)<<"\n\nIMAGE\n";std::cout<<"  Entry point:   "<<(m.entry_point?hex64(*m.entry_point):"n/a")<<"\n  Image base:    "<<(m.image_base?hex64(*m.image_base):"n/a")<<"\n";if(m.section_count)std::cout<<"  Sections:      "<<*m.section_count<<"\n";}
void print_hashes(const Hashes& h,bool json){if(json)std::cout<<"{\"md5\":\""<<h.md5<<"\",\"sha1\":\""<<h.sha1<<"\",\"sha256\":\""<<h.sha256<<"\"}\n";else std::cout<<"MD5:     "<<h.md5<<"\nSHA-1:   "<<h.sha1<<"\nSHA-256: "<<h.sha256<<"\n";}
}
