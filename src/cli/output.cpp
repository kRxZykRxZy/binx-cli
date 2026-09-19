#include "binx/cli/output.hpp"
#include "binx/formats/detect.hpp"
#include "binx/version.hpp"
#include <iomanip>
#include <sstream>
namespace binx {
namespace {
std::string esc(const std::string&s){std::string o;for(char c:s){const auto u=static_cast<unsigned char>(c);if(c=='"')o+="\\\"";else if(c=='\\')o+="\\\\";
else if(u<0x20){std::ostringstream x;x<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<static_cast<unsigned int>(u);o+=x.str();}else o+=c;}return o;}
std::string hex64(std::uint64_t v){std::ostringstream s;s<<"0x"<<std::hex<<std::uppercase<<v;return s.str();}
}
std::string format_help(){return std::string("BinX - Binary Inspector v")+BINX_VERSION+
"\n\nUsage:\n  binx <command> <file> [options]\n\n"
"Commands:\n  info       Show concise binary metadata\n  inspect    Inspect binary metadata\n  hash       Calculate MD5, SHA-1 and SHA-256\n  version    Show BinX version\n  help       Show this help\n\n"
"Options:\n  --json     Emit machine-readable JSON\n  --output   Write output to a file\n  --verbose  Enable diagnostic output\n  --quiet    Suppress normal output\n  --help     Show help\n";}
std::string format_version(){return std::string("BinX Binary Inspector ")+BINX_VERSION+"\n";}
std::string format_info(const BinaryFile&f,bool json,bool detailed){
 const auto&m=f.metadata();
 if(json){
  std::ostringstream o;
  o<<"{\n  \"file\": {\"name\": \"" << esc(f.path().filename().string()) << "\", \"size\": "<<m.file_size<<"},\n";
  o<<"  \"format\": \"" << format_name(m.format) << "\",\n";
  o<<"  \"architecture\": \"" << architecture_name(m.architecture) << "\",\n";
  o<<"  \"endianness\": \"" << endianness_name(m.endianness) << "\",\n";
  o<<"  \"platform\": \"" << esc(m.platform) << "\",\n";
  o<<"  \"valid\": "<<(m.valid?"true":"false");
  if(m.entry_point)o<<",\n  \"entry_point\": \"" << hex64(*m.entry_point) << "\"";
  if(m.entry_point_rva)o<<",\n  \"entry_point_rva\": \"" << hex64(*m.entry_point_rva) << "\"";
  if(m.image_base)o<<",\n  \"image_base\": \"" << hex64(*m.image_base) << "\"";
  if(m.raw_machine)o<<",\n  \"machine\": "<<*m.raw_machine;
  if(m.section_count)o<<",\n  \"section_count\": "<<*m.section_count;
  if(m.image_size)o<<",\n  \"image_size\": "<<*m.image_size;
  if(m.headers_size)o<<",\n  \"headers_size\": "<<*m.headers_size;
  if(m.subsystem)o<<",\n  \"subsystem\": "<<*m.subsystem;
  if(m.timestamp)o<<",\n  \"timestamp\": "<<*m.timestamp;
  if(!m.diagnostic.empty())o<<",\n  \"diagnostic\": \"" << esc(m.diagnostic) << "\"";
  o<<"\n}\n";return o.str();
 }
 std::ostringstream o;
 o<<"BinX Binary Inspector v"<<BINX_VERSION<<"\n\n";
 o<<"FILE\n  Name:          "<<f.path().filename().string()<<"\n  Size:          "<<m.file_size<<" bytes\n\n";
 o<<"FORMAT\n  Type:          "<<format_name(m.format)<<"\n  Architecture:  "<<architecture_name(m.architecture)<<"\n  Endianness:    "<<endianness_name(m.endianness)<<"\n  Platform:      "<<(m.platform.empty()?"unknown":m.platform)<<"\n\n";
 o<<"IMAGE\n  Entry point:   "<<(m.entry_point?hex64(*m.entry_point):"n/a")<<"\n";
 if(m.entry_point_rva)o<<"  Entry RVA:     "<<hex64(*m.entry_point_rva)<<"\n";
 o<<"  Image base:    "<<(m.image_base?hex64(*m.image_base):"n/a")<<"\n";
 if(m.image_size)o<<"  Image size:    "<<*m.image_size<<" bytes\n";
 if(m.headers_size)o<<"  Headers size:  "<<*m.headers_size<<" bytes\n";
 if(m.section_count)o<<"  Sections:      "<<*m.section_count<<"\n";
 if(m.raw_machine)o<<"  Machine:       "<<*m.raw_machine<<"\n";
 if(m.subsystem)o<<"  Subsystem:     "<<*m.subsystem<<"\n";
 if(m.timestamp)o<<"  Timestamp:     "<<*m.timestamp<<"\n";
 o<<"\nVALIDATION\n  Status:         "<<(m.valid?"valid/readable":"invalid")<<"\n";
 if(!m.diagnostic.empty())o<<"  Detail:         "<<m.diagnostic<<"\n";
 if(detailed)o<<"\nSAFETY\n  Input handling: read-only\n  Execution:      input files are never executed or loaded\n";
 return o.str();
}
std::string format_hashes(const Hashes&h,bool json){if(json)return std::string("{\"md5\":\"")+h.md5+"\",\"sha1\":\""+h.sha1+"\",\"sha256\":\""+h.sha256+"\"}\n";return std::string("MD5:     ")+h.md5+"\nSHA-1:   "+h.sha1+"\nSHA-256: "+h.sha256+"\n";}
}
