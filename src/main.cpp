#include "binx/cli/output.hpp"
#include "binx/analysis/byte_analysis.hpp"
#include "binx/cli/analysis_output.hpp"
#include "binx/analysis/dependencies.hpp"
#include "binx/analysis/disassembly.hpp"
#include "binx/analysis/diff.hpp"
#include "binx/analysis/crash.hpp"
#include "binx/analysis/symbols.hpp"
#include "binx/cli/dependency_output.hpp"
#include "binx/core/binary.hpp"
#include "binx/formats/detect.hpp"
#include "binx/formats/elf.hpp"
#include "binx/formats/pe.hpp"
#include "binx/hashing/hasher.hpp"
#include <charconv>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <system_error>
#include <vector>
using namespace binx;
namespace {
struct Options{std::string command;std::filesystem::path input;std::filesystem::path output;bool has_output=false;bool json=false;bool quiet=false;bool verbose=false;std::string encoding="ascii";std::string pattern;std::string text;std::filesystem::path second_input;bool has_second_input=false;std::uint64_t offset=0;std::uint64_t length=0;std::size_t width=16;std::size_t min_length=4;std::size_t max_results=0;std::size_t region_min=16;std::vector<std::filesystem::path> search_paths;std::size_t depth=8;std::size_t max_nodes=256;bool dot=false;bool recursive=false;std::size_t count=100;std::size_t max_bytes=0;bool from_entry=false;DisassemblySyntax syntax=DisassemblySyntax::Intel;};
void err(const std::string&s){std::cerr<<"binx: "<<s<<"\n";}
bool number(const std::string&s,std::uint64_t&v){if(s.empty())return false;const char*b=s.data(),*e=s.data()+s.size();int base=10;if(s.size()>2&&s[0]=='0'&&(s[1]=='x'||s[1]=='X')){base=16;b+=2;}auto [p,ec]=std::from_chars(b,e,v,base);return ec==std::errc{}&&p==e;}
bool sizeopt(const std::string&s,std::size_t&v){std::uint64_t x=0;if(!number(s,x)||x>static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))return false;v=static_cast<std::size_t>(x);return true;}
bool parse(int argc,char**argv,Options&o){
 if(argc<2)return false;o.command=argv[1];if(o.command=="--help"||o.command=="-h"){o.command="help";return true;}if(o.command=="--version"){o.command="version";return true;}
 std::vector<std::string>pos;for(int i=2;i<argc;++i){const std::string a=argv[i];
  if(a=="--json")o.json=true;else if(a=="--quiet")o.quiet=true;else if(a=="--verbose")o.verbose=true;
  else if(a=="--help"||a=="-h"){o.command="help";return true;}
  else if(a=="--output"||a=="-o"){if(i+1>=argc){err("--output requires a path");return false;}o.output=argv[++i];o.has_output=true;}
  else if(a=="--encoding"){if(i+1>=argc){err("--encoding requires a value");return false;}o.encoding=argv[++i];}
  else if(a=="--min-length"){if(i+1>=argc||!sizeopt(argv[i+1],o.min_length)){err("--min-length requires a non-negative integer");return false;}++i;}
  else if(a=="--max-results"){if(i+1>=argc||!sizeopt(argv[i+1],o.max_results)){err("--max-results requires a non-negative integer");return false;}++i;}
  else if(a=="--offset"){if(i+1>=argc||!number(argv[i+1],o.offset)){err("--offset requires a non-negative integer");return false;}++i;}
  else if(a=="--length"){if(i+1>=argc||!number(argv[i+1],o.length)){err("--length requires a non-negative integer");return false;}++i;}
  else if(a=="--width"){if(i+1>=argc||!sizeopt(argv[i+1],o.width)||o.width==0||o.width>256){err("--width must be 1..256");return false;}++i;}
  else if(a=="--pattern"||a=="--hex"){if(i+1>=argc){err(a+" requires a value");return false;}o.pattern=argv[++i];}
  else if(a=="--text"){if(i+1>=argc){err("--text requires a value");return false;}o.text=argv[++i];}
  else if(a=="--region-min"){if(i+1>=argc||!sizeopt(argv[i+1],o.region_min)||o.region_min==0){err("--region-min must be greater than zero");return false;}++i;}
  else if(a=="--search-path"){if(i+1>=argc){err("--search-path requires a directory");return false;}o.search_paths.emplace_back(argv[++i]);}
  else if(a=="--depth"){if(i+1>=argc||!sizeopt(argv[i+1],o.depth)||o.depth>64){err("--depth must be 0..64");return false;}++i;}
  else if(a=="--max-nodes"){if(i+1>=argc||!sizeopt(argv[i+1],o.max_nodes)||o.max_nodes==0||o.max_nodes>100000){err("--max-nodes must be 1..100000");return false;}++i;}
  else if(a=="--dot"){o.dot=true;}
  else if(a=="--recursive"){o.recursive=true;} else if(a=="--from-entry"){o.from_entry=true;} else if(a=="--syntax"){if(i+1>=argc){err("--syntax requires a value");return false;}std::string v=argv[++i];if(v=="intel")o.syntax=DisassemblySyntax::Intel;else if(v=="att")o.syntax=DisassemblySyntax::Att;else{err("--syntax must be intel or att");return false;}} else if(a=="--count"){if(i+1>=argc||!sizeopt(argv[i+1],o.count)||o.count==0){err("--count must be greater than zero");return false;}++i;} else if(a=="--max-bytes"){if(i+1>=argc||!sizeopt(argv[i+1],o.max_bytes)){err("--max-bytes requires a non-negative integer");return false;}++i;}
  else if(!a.empty()&&a[0]=='-'){err("unknown option '"+a+"'");return false;}else pos.push_back(a);
 }
 if(o.command=="help"||o.command=="version")return true;
 if((o.command=="diff"||o.command=="compare")){if(pos.size()!=2){err("diff requires two input files");return false;}o.input=pos[0];o.second_input=pos[1];o.has_second_input=true;}else{if(pos.size()!=1){err(pos.empty()?"missing input file":"too many input files");return false;}o.input=pos[0];}
 if(o.command=="strings"&&o.encoding!="ascii"&&o.encoding!="utf8"&&o.encoding!="utf16le"&&o.encoding!="utf16be"&&o.encoding!="all"){err("unsupported string encoding '"+o.encoding+"'");return false;}
 if(o.command=="search"&&o.pattern.empty()&&o.text.empty()){err("search requires --pattern/--hex or --text");return false;}if(o.command=="graph"&&o.dot)o.json=false;return true;
}
bool emit(const std::string&s,const Options&o){if(o.quiet)return true;if(!o.has_output){std::cout<<s;return static_cast<bool>(std::cout);}std::ofstream f(o.output,std::ios::binary|std::ios::trunc);if(!f){err("unable to open output file '"+o.output.string()+"'");return false;}f.write(s.data(),static_cast<std::streamsize>(s.size()));return static_cast<bool>(f);}
bool is_pe(BinaryFormat f){return f==BinaryFormat::PE32||f==BinaryFormat::PE64;}
bool is_elf(BinaryFormat f){return f==BinaryFormat::ELF32||f==BinaryFormat::ELF64;}
bool pe_command(const std::string&c){return c=="inspect"||c=="sections"||c=="imports"||c=="exports"||c=="resources"||c=="relocations";}
bool elf_command(const std::string&c){return c=="inspect"||c=="sections"||c=="segments"||c=="symbols"||c=="dynamic"||c=="notes"||c=="relocations";}
bool analysis_command(const std::string&c){return c=="strings"||c=="hexdump"||c=="search"||c=="regions"||c=="size";} bool diff_command(const std::string&c){return c=="diff"||c=="compare";}
bool dependency_command(const std::string&c){return c=="deps"||c=="dependencies"||c=="graph";} bool disasm_command(const std::string&c){return c=="disasm"||c=="disassemble";} bool symbols_command(const std::string&c){return c=="symbols"||c=="sym";} bool debug_command(const std::string&c){return c=="debug"||c=="debug-info";} bool crash_command(const std::string&c){return c=="crash"||c=="crash-analysis";}
}
int main(int argc,char**argv){
 Options o;if(!parse(argc,argv,o)){std::cerr<<format_help();return static_cast<int>(ErrorCode::InvalidArguments);}
 if(o.command=="help"){std::cout<<format_help();return 0;}if(o.command=="version"){std::cout<<format_version();return 0;}
 if(o.command!="info"&&o.command!="inspect"&&o.command!="hash"&&!analysis_command(o.command)&&!diff_command(o.command)&&!dependency_command(o.command)&&!disasm_command(o.command)&&!symbols_command(o.command)&&!debug_command(o.command)&&!crash_command(o.command)&&!pe_command(o.command)&&!elf_command(o.command)){err("unknown command '"+o.command+"'");return static_cast<int>(ErrorCode::InvalidArguments);}
 if(diff_command(o.command)){auto a=BinaryFile::open(o.input);auto b=BinaryFile::open(o.second_input);if(!a){err(a.error().message);return static_cast<int>(a.error().code);}if(!b){err(b.error().message);return static_cast<int>(b.error().code);}auto r=compare_binaries(a.value(),b.value());if(!r){err(r.error().message);return static_cast<int>(r.error().code);}return emit(format_binary_diff(r.value(),a.value(),b.value(),o.json),o)?0:static_cast<int>(ErrorCode::FileAccess);}
 auto file=BinaryFile::open(o.input);if(!file){err(file.error().message);return static_cast<int>(file.error().code);}
 if((o.command=="deps"||o.command=="dependencies")&&!o.recursive){auto deps=extract_dependencies(file.value());return emit(format_dependencies(deps,o.json),o)?0:static_cast<int>(ErrorCode::FileAccess);}
 if(o.command=="graph"||(o.command=="deps"&&o.recursive)||(o.command=="dependencies"&&o.recursive)){auto graph=build_dependency_graph(o.input,o.search_paths,o.depth,o.max_nodes);if(!graph){err(graph.error().message);return static_cast<int>(graph.error().code);}if(o.dot)return emit(dependency_graph_dot(graph.value()),o)?0:static_cast<int>(ErrorCode::FileAccess);return emit(format_dependency_graph(graph.value(),o.json),o)?0:static_cast<int>(ErrorCode::FileAccess);}
 if(o.command=="strings"){std::vector<ExtractedString> all;auto add=[&](StringEncoding e){auto v=extract_strings(file.value().bytes(),e,o.min_length,o.max_results);all.insert(all.end(),v.begin(),v.end());};if(o.encoding=="ascii"||o.encoding=="all")add(StringEncoding::ASCII);if(o.encoding=="utf8")add(StringEncoding::UTF8);if(o.encoding=="utf16le"||o.encoding=="all")add(StringEncoding::UTF16LE);if(o.encoding=="utf16be"||o.encoding=="all")add(StringEncoding::UTF16BE);if(o.max_results&&all.size()>o.max_results)all.resize(o.max_results);return emit(format_strings(all,o.json),o)?0:static_cast<int>(ErrorCode::FileAccess);}
 if(o.command=="hexdump"){if(o.offset>file.value().size()){err("offset is beyond end of file");return static_cast<int>(ErrorCode::InvalidArguments);}auto len=o.length?o.length:file.value().size()-o.offset;return emit(format_hexdump(make_hexdump(file.value().bytes(),o.offset,len,o.width),o.json),o)?0:static_cast<int>(ErrorCode::FileAccess);}
 if(o.command=="regions")return emit(format_regions(classify_regions(file.value().bytes(),o.region_min),o.json),o)?0:static_cast<int>(ErrorCode::FileAccess);
 if(o.command=="size"){auto r=analyze_size(file.value());if(!r){err(r.error().message);return static_cast<int>(r.error().code);}return emit(format_size_report(r.value(),file.value(),o.json),o)?0:static_cast<int>(ErrorCode::FileAccess);}
 if(o.command=="search"){std::vector<SearchMatch>matches;if(!o.pattern.empty()){std::vector<int>pat;if(!parse_hex_pattern(o.pattern,pat)){err("invalid hex pattern; use bytes such as '48 8B ?? FF'");return static_cast<int>(ErrorCode::InvalidArguments);}auto d=file.value().bytes();for(std::size_t pos=0;pos+pat.size()<=d.size()&&(o.max_results==0||matches.size()<o.max_results);++pos){bool ok=true;for(std::size_t j=0;j<pat.size();++j)if(pat[j]>=0&&std::to_integer<unsigned char>(d[pos+j])!=static_cast<unsigned char>(pat[j])){ok=false;break;}if(ok)matches.push_back({pos,pat.size()});}}else matches=search_text(file.value().bytes(),o.text,StringEncoding::UTF8,o.max_results);return emit(format_search(matches,o.json),o)?0:static_cast<int>(ErrorCode::FileAccess);}
 if(crash_command(o.command)){auto r=analyze_crash_dump(file.value());if(!r){err(r.error().message);return static_cast<int>(r.error().code);}return emit(format_crash_report(r.value(),file.value(),o.json),o)?0:static_cast<int>(ErrorCode::FileAccess);}
 if(symbols_command(o.command)){auto r=collect_symbols(file.value());if(!r){err(r.error().message);return static_cast<int>(r.error().code);}return emit(format_symbols(r.value(),o.json),o)?0:static_cast<int>(ErrorCode::FileAccess);}
 if(debug_command(o.command)){auto r=collect_debug_info(file.value());if(!r){err(r.error().message);return static_cast<int>(r.error().code);}return emit(format_debug_info(r.value(),o.json),o)?0:static_cast<int>(ErrorCode::FileAccess);}
 if(disasm_command(o.command)){DisassemblyOptions d;d.offset=o.offset;d.count=o.count;d.max_bytes=o.max_bytes;d.from_entry=o.from_entry;d.syntax=o.syntax;auto r=disassemble_file(file.value(),d);if(!r){err(r.error().message);return static_cast<int>(r.error().code);}return emit(format_disassembly(r.value(),o.json,o.syntax),o)?0:static_cast<int>(ErrorCode::FileAccess);}
 if(o.command=="hash"){auto h=hash_all(file.value().bytes());if(!h){err(h.error().message);return static_cast<int>(h.error().code);}return emit(format_hashes(h.value(),o.json),o)?0:static_cast<int>(ErrorCode::FileAccess);}
 if(!pe_command(o.command)&&!elf_command(o.command)){if(o.verbose)std::cerr<<"[binx] detected "<<format_name(file.value().metadata().format)<<"\n";return emit(format_info(file.value(),o.json,o.command=="inspect"),o)?0:static_cast<int>(ErrorCode::FileAccess);}
 if(is_elf(file.value().metadata().format)){auto elf=parse_elf_image(file.value().bytes());if(!elf){err(elf.error().message);return static_cast<int>(elf.error().code);}return emit(format_elf_command(elf.value(),o.command,o.json,o.command=="inspect"),o)?0:static_cast<int>(ErrorCode::FileAccess);}
 if(elf_command(o.command)){err("command requires an ELF image");return static_cast<int>(ErrorCode::UnsupportedFormat);}
 if(o.command=="inspect"&&!is_pe(file.value().metadata().format))return emit(format_info(file.value(),o.json,true),o)?0:static_cast<int>(ErrorCode::FileAccess);
 auto pe=parse_pe(file.value().bytes());if(!pe){err(pe.error().message);return static_cast<int>(pe.error().code);}const auto&image=pe.value();if(!emit(format_pe_command(image,o.command,o.json,o.command=="inspect"),o))return static_cast<int>(ErrorCode::FileAccess);if(image.header_status==ParseStatus::Malformed||image.header_status==ParseStatus::Unsupported)return static_cast<int>(ErrorCode::InvalidBinary);return 0;
}
