#include "binx/cli/output.hpp"
#include "binx/core/binary.hpp"
#include "binx/formats/detect.hpp"
#include "binx/hashing/hasher.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
using namespace binx;
namespace {
struct Options{std::string command;std::filesystem::path input;std::filesystem::path output;bool has_output=false;bool json=false;bool quiet=false;bool verbose=false;};
void err(const std::string&s){std::cerr<<"binx: "<<s<<"\n";}
bool parse(int argc,char**argv,Options&o){
 if(argc<2)return false;o.command=argv[1];std::vector<std::string>pos;
 for(int i=2;i<argc;++i){const std::string a=argv[i];
  if(a=="--json")o.json=true;else if(a=="--quiet")o.quiet=true;else if(a=="--verbose")o.verbose=true;
  else if(a=="--help"||a=="-h"){o.command.clear();return true;}
  else if(a=="--output"||a=="-o"){if(i+1>=argc){err("--output requires a path");return false;}o.output=argv[++i];o.has_output=true;}
  else if(!a.empty()&&a[0]=='-'){err("unknown option '"+a+"'");return false;}else pos.push_back(a);
 }
 if(o.command=="version"||o.command=="help")return true;
 if(pos.size()!=1){err(pos.empty()?"missing input file":"too many input files");return false;}o.input=pos[0];return true;
}
bool write_out(const std::string&s,const Options&o){
 if(o.quiet)return true;if(!o.has_output){std::cout<<s;return static_cast<bool>(std::cout);}
 std::ofstream f(o.output,std::ios::binary|std::ios::trunc);if(!f){err("unable to open output file '"+o.output.string()+"'");return false;}
 f.write(s.data(),static_cast<std::streamsize>(s.size()));if(!f){err("failed while writing output file '"+o.output.string()+"'");return false;}return true;
}
}
int main(int argc,char**argv){
 Options o;if(!parse(argc,argv,o)){std::cerr<<format_help();return static_cast<int>(ErrorCode::InvalidArguments);}
 if(o.command.empty()){std::cout<<format_help();return 0;}
 if(o.command=="--version"||o.command=="version"){std::cout<<format_version();return 0;}
 if(o.command=="--help"||o.command=="help"){std::cout<<format_help();return 0;}
 if(o.command!="info"&&o.command!="inspect"&&o.command!="hash"){err("unknown command '"+o.command+"'");return static_cast<int>(ErrorCode::InvalidArguments);}
 auto file=BinaryFile::open(o.input);if(!file){err(file.error().message);return static_cast<int>(file.error().code);}
 if(o.verbose){std::cerr<<"[binx] loaded "<<file.value().size()<<" bytes\n";std::cerr<<"[binx] detected "<<format_name(file.value().metadata().format)<<"\n";}
 if(o.command=="hash"){auto h=hash_all(file.value().bytes());if(!h){err(h.error().message);return static_cast<int>(h.error().code);}return write_out(format_hashes(h.value(),o.json),o)?0:static_cast<int>(ErrorCode::FileAccess);}
 return write_out(format_info(file.value(),o.json,o.command=="inspect"),o)?0:static_cast<int>(ErrorCode::FileAccess);
}
