#include "binx/core/binary.hpp"
#include "binx/cli/output.hpp"
#include "binx/hashing/hasher.hpp"
#include "binx/version.hpp"
#include <iostream>
#include <string>
#include <vector>

using namespace binx;

static bool has_arg(const std::vector<std::string>& a,const std::string& x){for(const auto&s:a)if(s==x)return true;return false;}
static void error_out(const Error&e){std::cerr<<"binx: "<<e.message<<"\n";}

int main(int argc,char**argv){
 if(argc<2){print_help();return static_cast<int>(ErrorCode::InvalidArguments);}
 std::vector<std::string>a; for(int i=1;i<argc;++i)a.emplace_back(argv[i]);
 const auto&cmd=a[0];
 if(cmd=="help"||cmd=="--help"||cmd=="-h"){print_help();return 0;}
 if(cmd=="version"||cmd=="--version"){print_version();return 0;}
 if(cmd!="info"&&cmd!="inspect"&&cmd!="hash"){std::cerr<<"binx: unknown command '"<<cmd<<"'\n";return static_cast<int>(ErrorCode::InvalidArguments);}
 if(a.size()<2){std::cerr<<"binx: missing input file\n";return static_cast<int>(ErrorCode::InvalidArguments);}
 const bool json=has_arg(a,"--json");
 auto file=BinaryFile::open(a[1]); if(!file){error_out(file.error());return static_cast<int>(file.error().code);}
 if(cmd=="hash"){
   auto h=hash_all(file.value().bytes()); if(!h){error_out(h.error());return static_cast<int>(h.error().code);}
   if(!has_arg(a,"--quiet")) print_hashes(h.value(),json);
   return 0;
 }
 if(!has_arg(a,"--quiet")) print_info(file.value(),json);
 return 0;
}
